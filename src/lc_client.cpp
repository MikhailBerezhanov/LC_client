#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <cassert>
#include <stdexcept>
#include <memory>
#include <functional>
#include <thread>
#include <chrono>

extern "C"{
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>
#include <uuid/uuid.h>
}

#define LOG_MODULE_NAME		"[ LCC ]"
#include "logger.hpp"

#include "lc.pb.h"
#include "log_result.pb.h"
#include "lc_trans.hpp"
#include "lc_client.hpp"

using namespace lc;


void LC_client::global_init()
{
	// If you did not already call curl_global_init, curl_easy_init does it automatically. 
	// This may be lethal in multi-threaded cases, since curl_global_init is not thread-safe, 
	// and it may result in resource problems because there is no corresponding cleanup.
	//
	// It is strongly advised to not allow this automatic behavior, 
	// by calling curl_global_init yourself properly at the app start.

	CURLcode ret = CURLE_OK;
	if( (ret = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK ) {
		throw LC_error(excp_method("curl_global_init() failed: " + std::to_string(ret)));
	}
}

void LC_client::global_cleanup()
{
	curl_global_cleanup();
}

void LC_client::init(settings *s)
{
	this->deinit();

	if(s){
		// Если заданы новые настройки, обновляем
		psets = s;
	} 	

	if( !psets ){
		throw std::invalid_argument(excp_method("settings ptr in null"));
	}

	logger.init(psets->lsets);

	lc::utils::make_dir_if_not_exists(pdirs->put_data_dir);
	lc::utils::make_dir_if_not_exists(pdirs->put_data_tmp_dir);
	lc::utils::make_dir_if_not_exists(pdirs->sent_data_dir);

	if( !lc::ProtoTransactions::ready() ){
		// Инициализация подмодуля транзакций если не был инициализирован ранее
		lc::ProtoTransactions::init(pdirs->put_data_dir, psets->device_id, psets->system_id, psets->device_type);
	}

	res_map.clear();

	hcurl = curl_easy_init();
	if( !hcurl ) {
		throw LC_error(excp_method("curl_easy_init() failed"));
	}

	this->curl_setup_connection();
}

void LC_client::deinit()
{
	if(hcurl){
		curl_easy_cleanup(hcurl);
		hcurl = nullptr;
	}

	if(req_header) {
		curl_slist_free_all(req_header);
		req_header = nullptr;
	}
}

// Сброс всех предыдущих настроек CURL и восстановление пресета соединения.
void LC_client::curl_setup_connection(size_t post_size) noexcept
{
	if(req_header){
		curl_slist_free_all(req_header);
		req_header = nullptr;
	} 
	curl_easy_reset(hcurl);
	memset(curl_err, 0, sizeof curl_err);

	// Signals are used for timing out name resolves (during DNS lookup) - when built 
	// without using either the c-ares or threaded resolver backends. Not thread-safe.
	curl_easy_setopt(hcurl, CURLOPT_NOSIGNAL, 1L);
	// Use whatever the TCP stack finds suitable
	curl_easy_setopt(hcurl, CURLOPT_INTERFACE, NULL);

	curl_easy_setopt(hcurl, CURLOPT_CONNECTTIMEOUT, 15L);

	if(post_size){
		req_header = curl_slist_append(req_header, "Content-Type: application/octet-stream");
		std::string content_len = "Content-Length: " + std::to_string(post_size);
		req_header = curl_slist_append(req_header, content_len.c_str());
	}
	else{
		req_header = curl_slist_append(req_header, "Content-Type: application/json");
	}
	
	curl_easy_setopt(hcurl, CURLOPT_HTTPHEADER, req_header);

	curl_version_info_data *tmp = curl_version_info(CURLVERSION_NOW);
	std::string agent_str = std::string("curl/") + tmp->version;
	curl_easy_setopt(hcurl, CURLOPT_USERAGENT, agent_str.c_str());

	// libcurl will use 'fwrite' as a callback by default.
	curl_easy_setopt(hcurl, CURLOPT_WRITEFUNCTION, NULL); 

	curl_easy_setopt(hcurl, CURLOPT_ERRORBUFFER, curl_err);

	// Disable SSL support
	if( !psets ){
		return;
	} 

	if( !(psets->ssl_check) ){
		curl_easy_setopt(hcurl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(hcurl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	if(psets->curl_verbose){
		curl_easy_setopt(hcurl, CURLOPT_VERBOSE, 1L);
	}

	curl_easy_setopt(hcurl, CURLOPT_TIMEOUT, psets->server_tmout);
}

void LC_client::curl_setup_request(const std::string &url, const std::string &post_data, void *wr_ptr, size_t post_size) noexcept
{
	// Сброс настроек предыдущего запроса
	this->curl_setup_connection(post_size);

	logger.msg(MSG_TRACE, "Sending (URL: %s) Body: %s\n\n", url, post_data);

	curl_easy_setopt(hcurl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(hcurl, CURLOPT_POSTFIELDS, post_data.c_str());

	if(post_size){
		curl_easy_setopt(hcurl, CURLOPT_POSTFIELDSIZE, static_cast<long>(post_size));
	}
	// else: use strlen() by default

	curl_easy_setopt(hcurl, CURLOPT_WRITEDATA, wr_ptr);
}

bool LC_client::curl_reset()
{
	if(hcurl){
		curl_easy_cleanup(hcurl);
		hcurl = nullptr;
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));

	hcurl = curl_easy_init();
	if( !hcurl ) {
		return false;
	}

	return true;
}


char* LC_client::curl_transceive(const std::string &uri, const std::string &body, size_t body_size, size_t *response_size)
{
	CURLcode curl_res = CURLE_OK;
	char *ms_ptr = nullptr;
	size_t ms_size = 0;
	long http_code = 0;
	bool success = false;

	auto ms_clean = [&ms_ptr, &success] (FILE *stream) {
		if( !success ){ 
			fclose(stream); 
		}
		// При закрытии потока, в ms_ptr сбрасывается динамический буфер. При экстренном
		// выходе необходимо освобождение. Если выход запланированный - ms_ptr используется дальше.
		if(ms_ptr && !success){ 
			free(ms_ptr); 
			ms_ptr = nullptr; 
		}
	};

	// open_memstream(): The locations referred to by ms_ptr pointer is updated each time
	// the stream is flushed and when the stream is closed.
	std::unique_ptr<FILE, std::function<void(FILE*)>> ms ( open_memstream(&ms_ptr, &ms_size), ms_clean );

	if( !ms ){
		throw LC_error(excp_method("open_memstream failed"));
	} 

	std::string url = psets->lc_server_url + uri;

	this->curl_setup_request(url, body, ms.get(), body_size);

	// Отправка запроса на сервер
	if((curl_res = curl_easy_perform(hcurl)) != CURLE_OK){
		// обработка критической ошибки ранних версий cURL: https://curl.se/mail/lib-2018-07/0057.html
		//
		// curl_easy_perform() failed(27): SSL: couldn't create a context: error:140A90F1:lib(20):func(169):reason(241)
		//
		// При возникновении данной ошибки нужно полностью переиницализировать cURL, 
		// что проблематично сделать в текущей реализации SUV - ошибки не выводятся наверх, контекст cURL используется несколькими потоками итд
		// поэтому при возникновении данной ошибки процесс просто отправляет SIGHUP сам себе ¯\_(ツ)_/¯
		// SIGHUP обрабатывается в main.cpp
		if (curl_res == CURLE_OUT_OF_MEMORY) {  // 27
			kill (getpid (), SIGHUP);
		}

		size_t len = strlen(curl_err);
		std::string err_text = "(" + std::to_string(curl_res) + "): " + ((len) ? curl_err : curl_easy_strerror(curl_res));
		throw LC_no_connection("curl_easy_perform() failed" + err_text);
	} 

	// Анализ хедера полученного ответа 
	curl_easy_getinfo(hcurl, CURLINFO_RESPONSE_CODE, &http_code);
	if(http_code != 200){
		throw LC_protocol_error("HTTP RESPONSE CODE not OK: " + std::to_string(http_code), http_code);
	}

	// После этого в ms_ptr хранится тело ответа сервера (ms_ptr больше не nullptr).
	fflush(ms.get());
	fclose(ms.get());
	success = true;

	if(response_size){
		*response_size = ms_size;
	}

	return ms_ptr;
}

void LC_client::try_to_make_request(std::function<void(void)> do_request, int tries)
{
	LC_error last_error;

	for(int i = 0; i < tries; ++i){
		try{
			do_request();
			return;
		}
		catch(LC_no_connection &e){
			if(i == (tries - 1)) throw e;

			logger.msg(MSG_WARNING | MSG_TO_FILE, "Connection error (%s). Trying again ..\n", e.what());
			// Попытка восстановить соединение
			if( !this->curl_reset() ) throw LC_no_connection(std::string("curl_reset() failed. ") + e.what());
		}
		// catch(LC_error &e){
		// 	logging_excp(logger, "%s\n", e.what());
		// 	if(i < tries - 1) logger.msg(MSG_DEBUG | MSG_TO_FILE, "Trying again .. \n");
		// 	last_error = e; 
		// 	continue;
		// }
	}

	throw last_error;
}

// ----------------------------------------------------------------------
// ---------- Получение файлов от сервера Локального Центра -------------
// ----------------------------------------------------------------------
#define FILE_GET_PREFIX  		_BOLD "file_get: " _RESET

void LC_client::file_get_request(const std::string &type, const std::string &ver)
{
	// Создание тела запроса формата json согласно протоколу обмена
	lc::file_get_request req{psets->device_id, psets->device_type};
	lc::file_info info{ type, ver };
	req.finfo.push_back(info);
	std::string json = req.to_json();

	// Отправка запроса и прием ответа
	std::unique_ptr<char, std::function<void(char*)>> response (this->curl_transceive(LC_GET_FILE_URI, json), [] (char *p) { free(p); } );

	// logger.msg(MSG_TRACE, FILE_GET_PREFIX "Response data: %s\n", response.get());

	// Анализ тела полученного ответа
	this->parse_file_get_response(response.get(), type, ver);
}

void LC_client::file_get_request(std::vector<lc::file_info> &info_arr)
{
	lc::file_get_request req{psets->device_id, psets->device_type, info_arr};
	std::string json = req.to_json();

	std::unique_ptr<char, std::function<void(char*)>> response (this->curl_transceive(LC_GET_FILE_URI, json), [] (char *p) { free(p); } );

	// logger.msg(MSG_TRACE, FILE_GET_PREFIX "Response data: %s\n", response.get());

	// Анализ тела полученного ответа
	this->parse_file_get_response(response.get());
}

void LC_client::parse_file_get_response(const char *response_body, const std::string &type, const std::string &ver) const
{
	if( !response_body ){
		throw LC_error(excp_method("no response_body provided"));
	} 

	file_get_response resp(response_body);

	std::string error_text;

	if(resp.res.code){
		if(resp.res.text == "Нет данных"){
			throw LC_no_data("server has no data for '" + type + "'");
		} 

		throw LC_protocol_error("server response not OK: " + resp.res.text);
	}

	if(resp.files.empty()){
		throw LC_no_data("'" + type + "' actual version already (" + ver + ")");
	}

	for(auto iter = resp.files.begin(); iter != resp.files.end(); ++iter){
		
		const uint8_t *content = reinterpret_cast<const uint8_t*>(iter->content.c_str());

		try{
			lc::utils::check_crc32( content, iter->size, iter->crc );
		}
		catch(const std::exception &e){
			error_text += "'" + iter->info.type + "' " + e.what() + ". ";
			continue;
		}
		
		if(psets->get.find(iter->info.type) == psets->get.end()){
			error_text += "response contains unknown file type (" + iter->info.type + "). ";
			continue;
			// throw LC_protocol_error("response contains unknown file type (" + iter->info.type + ")");
		}

		logger.msg(MSG_DEBUG | MSG_TO_FILE, FILE_GET_PREFIX "[+] Got '%s' (encoded size: %zu B, ver: %s)\n", iter->info.type, iter->content.length(), iter->info.version);

		// Сохранение в закодированном текстовом виде
		auto save_encoded = psets->get.at(iter->info.type).enc_save;
		if(save_encoded){
			try{
				save_encoded(iter->name, iter->content, iter->info.version);
			}
			catch(const std::exception &e){
				error_text += "'" + iter->info.type + "'.enc_save() exception: " + e.what() + ". ";
			}
		}

		// Сохранение в раскодированном бинарном виде
		auto save_decoded = psets->get.at(iter->info.type).dec_save;
		if(save_decoded){
			// Раскодировать содержимое
			size_t decoded_size = 0;
			std::unique_ptr<uint8_t[]> decoded = lc::utils::base64_decode(content, iter->content.length(), &decoded_size);

			if(decoded && decoded_size){
				try{
					save_decoded(iter->name, decoded.get(), decoded_size, iter->info.version);
				}
				catch(const std::exception &e){
					error_text += "'" + iter->info.type + "'.dec_save() exception: " + e.what() + ". ";
				}
			}
		}

	}

	if( !error_text.empty() ){
		throw LC_error(error_text);
	} 
}

void LC_client::get_file(const std::string file_type, const get_processing &file_proc)
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	}

	try{
		if( !file_proc.enabled || (!file_proc.dec_save && !file_proc.enc_save) ){
			logger.msg(MSG_VERBOSE, FILE_GET_PREFIX "loading of '%s' is disabled.\n", file_type);
			return;
		}

		logger.msg(MSG_INFO | MSG_TO_FILE, FILE_GET_PREFIX "downloading '%s' (curr_ver: '%s') ..\n", file_type, file_proc.curr_ver);

		auto do_request = [this, &file_type, &file_proc](){ this->file_get_request(file_type, file_proc.curr_ver); };
		this->try_to_make_request( do_request, psets->get_data_tries );
	}
	catch(const LC_no_connection &e){
		this->res_map["No connection"] = lc::result(-1, e.what());
		throw;
	}
	catch(const LC_no_data &e){
		logger.msg(MSG_DEBUG | MSG_TO_FILE, FILE_GET_PREFIX "%s\n", e.what());
	}
	catch(const LC_error &e){
		this->res_map["Get '" + file_type + "(" + file_proc.curr_ver + ")' error"] = lc::result(-1, e.what());
		logging_excp(logger, "%s\n", e.what());
	}
}

void LC_client::get_files()
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	} 

	for(const auto &kv : psets->get){
		this->get_file(kv.first, kv.second);
	}
}

// ----------------------------------------------------------------------
// ---------- Получение файлов от сервера Локального Центра -------------
// ----------------------------------------------------------------------
#define GET_MEDIA_PREFIX 		_BOLD "get_media_list: " _RESET

void LC_client::get_media_list_request(std::vector<lc::file_info> &info_arr)
{
	lc::get_media_list_request req{psets->device_id, psets->device_type, info_arr};
	std::string json = req.to_json();

	std::unique_ptr<char, std::function<void(char*)>> response (this->curl_transceive(LC_GET_MEDIA_LIST_URI, json), [] (char *p) { free(p); } );

	logger.msg(MSG_TRACE, GET_MEDIA_PREFIX "response data: %s\n", response.get());

	// Анализ тела полученного ответа
	this->parse_get_media_list_response(response.get());
}

void LC_client::parse_get_media_list_response(const char *response_body, const std::string &type, const std::string &ver) const
{
	if( !response_body ){
		throw LC_error(excp_method("no response_body provided"));
	} 

	get_media_list_response resp(response_body);

	if(resp.res.code){
		if(resp.res.text == "Нет данных"){
			throw LC_no_data("server has no data for '" + type + "'");
		} 

		throw LC_protocol_error("server response not OK: " + resp.res.text);
	}

	if( !on_media_list_get ){
		return;
	}

	// Проверка был ли в ответе получен лист: валидный лист может быть пустым либо 
	// содержать непустые значения
	if( resp.tmp_media_list.empty() || !resp.tmp_media_list.at(0).name.empty() ){
		on_media_list_get(resp.tmp_media_list, true);
	}
	else{
		logger.msg(MSG_DEBUG | MSG_TO_FILE, "No tmp medialist in the response\n");
	}

	if( resp.const_media_list.empty() || !resp.const_media_list.at(0).name.empty() ){
		on_media_list_get(resp.const_media_list, false);
	}
	else{
		logger.msg(MSG_DEBUG | MSG_TO_FILE, "No const medialist in the response\n");
	}
}

void LC_client::get_media_lists(const std::string &tmp_media_ver, const std::string &const_media_ver)
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	}

	if( !psets->perms.get_media_list ){
		return;
	} 

	try{
		std::vector<lc::file_info> info_arr;

		if( !tmp_media_ver.empty() ){
			info_arr.emplace_back("mediatmp", tmp_media_ver);
		}
		if( !const_media_ver.empty() ){
			info_arr.emplace_back("mediaconst", const_media_ver);
		}

		if(info_arr.empty()){
			return;
		}

		std::string msg = info_arr.at(0).type + " (curr_ver: '" + info_arr.at(0).version + "') ";
		if(info_arr.size() > 1){
			msg += info_arr.at(1).type + " (curr_ver: '" + info_arr.at(1).version + "')";
		}

		logger.msg(MSG_DEBUG | MSG_TO_FILE, GET_MEDIA_PREFIX "requesting %s\n", msg);

		auto do_request = [this, &info_arr](){ this->get_media_list_request(info_arr); };
		this->try_to_make_request( do_request, psets->get_data_tries );
	}
	catch(const LC_no_connection &e){
		this->res_map["No connection"] = lc::result(-1, e.what());
		throw;
	}
	catch(const LC_no_data &e){
		logger.msg(MSG_DEBUG | MSG_TO_FILE, GET_MEDIA_PREFIX "%s\n", e.what());
	}
	catch(const LC_error &e){
		this->res_map["Get media lists error"] = lc::result(-1, e.what());
		logging_excp(logger, "%s\n", e.what());
	}

}

// ----------------------------------------------------------------------
// -------------- Отправка данных на сервер Локального Центра -----------
// ----------------------------------------------------------------------
#define FILE_POST_PREFIX 		_BOLD "file_post: " _RESET

uint32_t LC_client::prepare_files(std::vector<std::string> &fnames, time_t *pt) const
{
	char *ms_ptr = nullptr;
	size_t ms_size = 0;

	char dt_str[50];
	time_t t = time(NULL);
	strftime(dt_str, sizeof(dt_str), "%d-%m-%Y %T", localtime(&t));
	if(pt) *pt = t;
	uint32_t trans_num = 0;

	if(fnames.empty()){
		return 0;
	} 

	auto ms_clean = [&ms_ptr] (FILE *stream) {
		if(stream) { fclose(stream);  }
			if(ms_ptr ) { free(ms_ptr); ms_ptr = nullptr; }
	};

	std::unique_ptr<FILE, std::function<void(FILE*)>> ms ( open_memstream(&ms_ptr, &ms_size), ms_clean );

	if( !ms ){
		throw LC_fs_error(excp_method(std::string("open_memstream failed: ") + strerror(errno)));
	} 

	try{
		// Очистить временную директорию после предыдущей сессии
		lc::utils::exec("rm -f " + pdirs->put_data_tmp_dir + "/*");

		// Перенести указанные файлы во временную директорию
		for(const auto fname : fnames){
			lc::utils::exec("cp " + pdirs->put_data_dir + "/" + fname + " " + pdirs->put_data_tmp_dir);
		}
	}
	catch(std::exception &e){
		throw LC_fs_error(e.what());
	}

	// Заполнить структуру метаданных отправляемых файлов 
	const auto &ms_ref = ms.get();
	fprintf(ms_ref, "%08x\n", psets->device_id);
	fprintf(ms_ref, "%s\n", dt_str);
	fprintf(ms_ref, "%s\n", psets->device_type.c_str());
	for(auto &fname : fnames){

		uint32_t crc32 = 0; 
		std::string trans_name = pdirs->put_data_tmp_dir + "/" + fname;

		try{
			crc32 = lc::utils::file_crc32(trans_name);
		}
		catch(std::invalid_argument &e){
			// Удалить пустой файл из временной, постоянной директории и текущего массива имен
			logger.msg(MSG_ERROR | MSG_TO_FILE, "%s\n", e.what());
			remove(trans_name.c_str());
			remove( (pdirs->put_data_dir + "/" + fname).c_str() );
			sync();
			fname = "";

			continue;
		}
		catch(std::exception &e){
			// Удалить файл из временной директории и текущего массива имен
			logger.msg(MSG_ERROR | MSG_TO_FILE, "%s\n", e.what());
			remove(fname.c_str());	
			sync();
			fname = "";

			continue;
		}

		fprintf(ms_ref, "%s %08x\n", fname.c_str(), crc32);
		++trans_num;
		// Сохраняем полное имя отправляемой транзакции
		//fname = trans_name;
	}

	logger.msg(MSG_INFO | MSG_TO_FILE, FILE_POST_PREFIX "created archive.info for %u transaction(s)\n", trans_num);

	fflush(ms_ref);
	fprintf(ms_ref, "%02x\n", lc::utils::crc8_tab(reinterpret_cast<uint8_t *>(ms_ptr), ms_size));
	fflush(ms_ref);

	try{
		lc::utils::write_text_file(pdirs->put_data_tmp_dir + "/archive.info", ms_ptr, ms_size);
	}
	catch(std::exception &e){
		throw LC_fs_error(e.what());
	}

	return trans_num;
}

// Упаковка подготовленных файлов в архив
std::string LC_client::pack_prepared_files(time_t t) const
{
	// Формирование имени архива
	char tar_name[128] = {0};
	char dt_str[50];
	strftime(dt_str, sizeof dt_str, "%y%m%d%H%M%S", localtime(&t));
	uuid_t uid;
		uuid_generate(uid);
		char uid_str[40] = {0};
		uuid_unparse(uid, uid_str);
		uid_str[6] = '\0'; // используются первые 6 символов

	sprintf(tar_name, "%s_tr_%010u_%s%s", dt_str, psets->device_id, uid_str, LC_FILE_EXT);

	try{
		lc::utils::exec("cd " + pdirs->put_data_tmp_dir + " && tar -cf " + tar_name + " --exclude=*.tar *");
	}
	catch(std::exception &e){
		throw LC_fs_error(e.what());
	}

	logger.msg(MSG_VERBOSE | MSG_TO_FILE, FILE_POST_PREFIX "files have been packed into: '%s'\n", tar_name);
	return std::string(tar_name);
}

std::string LC_client::create_put_file_json(const std::string &tar_name) const
{
	// base64 кодирование архива с содержимым
	uint64_t tar_size = 0;
	std::unique_ptr<uint8_t[]> tar_data = lc::utils::read_bin_file(pdirs->put_data_tmp_dir + "/" + tar_name, &tar_size);
	size_t b64_len = 0;
	std::unique_ptr<uint8_t[]> b64_data = lc::utils::base64_encode(tar_data.get(), tar_size, &b64_len);

	if( !b64_data ){
		throw LC_error("base64_encode '" + tar_name + "' of size " + std::to_string(tar_size) + "failed");
	} 

	uint32_t crc = lc::utils::crc32_wiki_inv(0xFFFFFFFF, b64_data.get(), static_cast<uint64_t>(b64_len));

	// Формирование тела запроса
	lc::file_post_request req{psets->device_id, psets->device_type};

	lc::file f{
		"device_tgz_log",
		"1",
		b64_len,
		tar_name, 
		reinterpret_cast<char*>(b64_data.get()),
		crc, 
	};

	req.files.push_back(f);

	return req.to_json();
}

void LC_client::parse_file_post_response(const char *response_body, const std::string &tar_name, const std::vector<std::string> &fnames) const
{
	if( !response_body ){
		throw LC_error(excp_method("no response_body provided"));
	} 

	logger.msg(MSG_TRACE, FILE_POST_PREFIX "response: %s\n", response_body);

	lc::file_post_response resp(response_body);

	if(resp.res.code){
		throw LC_protocol_error("server response with error: " + resp.res.text);
	}

	if( !pdirs->sent_data_dir.empty() ){
		// Сделать бэкап успешно отправленного архива с транзакциями (Папки формируются по дате)
		char dir_name[50] = {0};
		time_t t = time(nullptr);
		strftime(dir_name, sizeof(dir_name), "%y%m%d", localtime(&t));
		std::string res = lc::utils::exec_piped("cd " + pdirs->put_data_tmp_dir + " && gzip " + tar_name + 
			"&& mkdir -p " + pdirs->sent_data_dir + "/" + dir_name + " && mv " + tar_name + ".gz " + 
			pdirs->sent_data_dir + "/" + dir_name + " 2>&1 | tr -d '\n'");

		if( !res.empty() ) throw LC_error("'" + tar_name + "' backup failed: " + res);
	}

	std::string error;

	// Удалить успешно отправленные транзакции
	for(const auto &fname : fnames){
		if(fname == "") continue;

		if( remove((pdirs->put_data_dir + "/" + fname).c_str()) < 0 ){
			error += "remove '" + fname + "' failed: " + strerror(errno) + "\n";
		}
	}
	sync();

	if( !error.empty() ){
		throw LC_fs_error(error);
	} 
}

void LC_client::file_post_request()
{
	lc::utils::make_dir_if_not_exists(pdirs->put_data_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	lc::utils::make_dir_if_not_exists(pdirs->put_data_tmp_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	lc::utils::make_dir_if_not_exists(pdirs->sent_data_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	// Определить количество файлов-транзакций в директории для отправки
	uint32_t files_num = lc::utils::get_files_num_in_dir(pdirs->put_data_dir, LC_DB_TRANS_EXT);
	uint32_t sent_num = 0;
	std::string error_msg;
	std::string tar_name;
	std::vector<std::string> fnames;

	// Кол-во отправляемых файлов за одну посылку
	int files_num_to_send = psets->max_put_files_num;

	logger.msg(MSG_INFO | MSG_TO_FILE, FILE_POST_PREFIX "found %" PRIu32 " file(s) to send\n", files_num);

	// Отправка файлов пачками заданного объема
	while(sent_num < files_num){

		try{
			// Получение имен очередной пачки файлов
			fnames = lc::utils::get_file_names_in_dir(pdirs->put_data_dir, LC_DB_TRANS_EXT,
				files_num_to_send, psets->put_chunk_size, sent_num);

			// Логируем отправляемые транзакции
			logger.msg(MSG_VERBOSE | MSG_TO_FILE, FILE_POST_PREFIX "trying to send package of max %d files (max total size %" PRIu64 " B):\n", 
				files_num_to_send, psets->put_chunk_size);
			for(size_t n = 0; n < fnames.size(); ++n){
				logger.msg(MSG_VERBOSE | MSG_TO_FILE, "%d. '%s'\n", n + 1, fnames[n]);
			}

			// Подготовка файлов к отправке, получение кол-ва подготовленных файлов и их полных имен
			time_t prep_time = 0;
			uint32_t files_ready = this->prepare_files(fnames, &prep_time);	// throws only LC_fs_error
			if( !files_ready ){
				// больше нечего отправлять
				break;
			}  

			sent_num += files_ready;
			tar_name = this->pack_prepared_files(prep_time);
			std::string json = this->create_put_file_json(tar_name);

			{
				std::unique_ptr<char, std::function<void(char*)>> response (this->curl_transceive(LC_PUT_FILE_URI, json), 
					[] (char *p) { free(p); } );

				// Анализ тела полученного ответа
 				this->parse_file_post_response(response.get(), tar_name, fnames);
			}
		}
		catch(const LC_protocol_error &e){
			logging_excp(logger, "Sent package '%s' with:\n", tar_name);
			for(size_t n = 0; n < fnames.size(); ++n){
				logger.msg(MSG_ERROR | MSG_TO_FILE, "%d. '%s'\n", n + 1, fnames[n]);
			}
			logger.msg(MSG_ERROR | MSG_TO_FILE, "Got protocol_error - %s\n", e.what());
			// Фиксируем ошибку, но не выходим - попытаемся отправить другие файлы при наличии
			error_msg = e.what();
		}
	}

	if( !error_msg.empty() ){
		throw LC_protocol_error(error_msg);
	}
}


void LC_client::put_files()
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	} 

	if( !psets->perms.put_data ){
		logger.msg(MSG_INFO | MSG_TO_FILE, FILE_POST_PREFIX "Sending files is disabled.\n");
		return;
	} 

	try{
		auto do_request = [this](){ this->file_post_request(); };
		this->try_to_make_request( do_request, psets->put_data_tries );
	}
	catch(const LC_no_connection &e){
		this->res_map["No connection"] = lc::result(-1, e.what());
		throw;
	}
	catch(const LC_error &e){
		this->res_map["Put files error"] = lc::result(-1, e.what());
		// logging_excp(logger, "%s\n", e.what());
	}
}


void LC_client::rotate_sent_data()
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	} 

	if(pdirs->sent_data_dir.empty() || !psets->max_sent_data_size){
		return;
	}

	static uint32_t prev_total_num = 0;	

	std::string dir_name = lc::utils::short_name(pdirs->sent_data_dir);
	std::string prefix = "[C] '" + dir_name + "'";

	uint64_t curr_size = lc::utils::get_dir_size(pdirs->sent_data_dir);
	uint32_t total_num = lc::utils::get_entries_num_in_dir(pdirs->sent_data_dir);
	logger.msg(MSG_DEBUG | MSG_TO_FILE, "%s curr_size: %" PRIu64 ", max_size: %" PRIu64 " [B], total '%" PRIu32 "' entries\n", 
		prefix, curr_size, psets->max_sent_data_size, total_num);

	if( !total_num || (curr_size < psets->max_sent_data_size) ){
		logger.msg(MSG_INFO | MSG_TO_FILE, "%s no cleaning needed\n", prefix);
		prev_total_num = total_num;
		return;
	} 

	// Для определения запущена ли очистка в текущий момент смотрим 
	// изменилось ли кол-во файлов по сравнению с предыдущим вызовом
	if(prev_total_num && (total_num < prev_total_num)){
		logger.msg(MSG_INFO | MSG_TO_FILE, "%s cleaning is in progress, %" PRIu32 " entries were removed.\n", prefix, prev_total_num - total_num);
		prev_total_num = total_num;
		return;
	}

	// Удаляем половину старых файлов
	uint32_t num = (total_num == 1) ? 1 : total_num / 2;
	lc::utils::remove_head_files_from_dir(pdirs->sent_data_dir, num, true);
	logger.msg(MSG_INFO | MSG_TO_FILE, "%s '%" PRIu32 "' head entries cleaning in background started.\n", prefix, num);
	prev_total_num = total_num;
}


// ----------------------------------------------------------------------
// -------------- Передача информации о системе на сервер ЛЦ ------------
// ----------------------------------------------------------------------
#define INFO_POST_PREFIX  		_BOLD "info_post: " _RESET

// void LC_client::parse_info_post_response(const char *response_body)
// {
// 	if( !response_body ){
// 		throw LC_error(excp_method(": no response_body provided"));
// 	} 

// 	info_post_response resp(response_body);

// 	// Обработка предыдущего действия если есть
// 	act_handler.next_act.execute_pending();

// 	if(resp.res.code){
// 		throw LC_protocol_error("server response not OK: " + resp.res.text);
// 	}

// 	if(resp.push.action == "none"){
// 		logger.msg(MSG_INFO, "No action needed.");
// 		return;
// 	}

// 	// Поиск реакции на пришедшее действие
// 	auto it = act_handler.cb_map.find(resp.push.action);
// 	if(it == act_handler.cb_map.end()){
// 		logger.msg(MSG_INFO, "No callback for '%s' action provided. Ignoring", resp.push.action);
// 		return;
// 	}
// 	auto handle_action = it->second;

// 	// Определение типа запуска обработчика пришедшего действия
// 	switch(resp.push.mode){

// 		// как можно скорее
// 		case 0:
// 			std::thread(handle_action, resp.push.data, resp.push.data_mode, resp.push.duration).detach();
// 			break;

// 		// после отработки предыдущих действий (TODO)
// 		// case 1:
			
// 		// 	break;

// 		// после следующего info_post
// 		case 2:
// 			act_handler.next_act = LC_action::next_action(handle_action, resp.push.data, resp.push.data_mode, resp.push.duration);
// 			break;

// 		default:
// 			logger.msg(MSG_WARNING, "Unsupported push.mode (%d). Ignoring", resp.push.mode);
// 			return;
// 	}
// }

// void LC_client::info_post_request(const lc::sys_info *si)
// {
// 	// Создание тела запроса формата json согласно протоколу обмена
// 	lc::info_post_request req{psets->device_id, psets->device_type, si};
// 	std::string json = req.to_json();

// 	// Отправка запроса и прием ответа
// 	std::unique_ptr<char, std::function<void(char*)>> response (this->curl_transceive(LC_PUT_SYS_INFO_URI, json), [] (char *p) { free(p); } );

// 	logger.msg(MSG_TRACE, "Response data: %s\n", response.get());

// 	// Анализ тела полученного ответа
// 	this->parse_info_post_response(response.get());
// }



// ----------------------------------------------------------------------
// ----------- Передача протобуф пакета транзакций на сервер ЛЦ ---------
// ----------------------------------------------------------------------
#define DATA_POST_PREFIX 	_BOLD "data_post: " _RESET

// Коды ошибок, возвращаемых ЛЦ при невалидном содержании сообщения (транзакции)
#define DATA_POST_ERR_INVALID_ID   				5
#define DATA_POST_ERR_FILE_DESERIALIZATION		10
#define DATA_POST_ERR_MESSAGE_DATA_EMPTY		11
#define DATA_POST_ERR_MESSAGE_DATA_DECRYPT		12
#define DATA_POST_ERR_MESSAGE_DATA_DECODE		13
#define DATA_POST_ERR_DB_FORMAT					14
#define DATA_POST_ERR_MESSAGE_DATA_SIGNATURE	15

#define MSG_BROKEN(code) ( (code == DATA_POST_ERR_INVALID_ID) || \
		((code >= DATA_POST_ERR_FILE_DESERIALIZATION) && (code <= DATA_POST_ERR_MESSAGE_DATA_SIGNATURE))) 

std::unordered_set<std::string> LC_client::parse_data_post_response(const char *response_data, size_t response_size, std::unordered_set<std::string> &fnames)
{
	// Формат ответа сервера идентичен формату запроса. В Message.data лежит структура 
	// LogResult с описанием ошибки загрузки конкретного Message (с тем же Message.name). 
	// Если в массиве messages из ответа сервера какое-то из переданных в запросе сообщений 
	// отсутствует, считается, что сообщение было загружено без ошибки. 
	// Структуры Package.devinfo и Message.devinfo  также могут быть пустыми.

	// logger.msg(MSG_DEBUG, "Response raw data (%zu bytes): %s\n", response_size, response_data);

	pb::Package response_package;
	// Набор транзакций, которые сервер не смог принять из-за неверного формата (внутренней ошибки записи)					
	std::unordered_set<std::string> broken_messages;	

	if( !response_package.ParseFromArray(response_data, response_size) ){
		throw std::runtime_error(excp_method("Package ParseFromArray failed"));
	}

	logger.msg(MSG_TRACE, DATA_POST_PREFIX "got response :\n%s\n", proto_msg_to_json(response_package));

	// Ошибок нет - все транзакции успешно отправлены
	if( !response_package.messages_size() ){
		logger.msg(MSG_DEBUG | MSG_TO_FILE, DATA_POST_PREFIX "sending succeed\n");
		return broken_messages;
	}

	// При отправке транзакций произошла ошибка - помечаем неуспешные транзакции
	for(int i = 0; i < response_package.messages_size(); ++i){

		const auto &msg = response_package.messages(i);

		if(msg.name().empty()){
			logging_err(logger, "message[%d] has no name\n", i);
			continue;
		}

		// Удаляем файл из списка успешно отправленных 
		fnames.erase(msg.name() + LC_PROTO_TRANS_EXT);

		pb::LogResult res;
		res.ParseFromString(msg.data());

		if(MSG_BROKEN(res.errorcode())){
			broken_messages.insert(msg.name() + LC_PROTO_TRANS_EXT);
			logging_warn(logger, DATA_POST_PREFIX "message (%s) is broken: %s\n", msg.name(), proto_msg_to_json(res));
		}
		else{
			logging_warn(logger, DATA_POST_PREFIX "message (%s) failed: %s\n", msg.name(), proto_msg_to_json(res));
		}

	}

	return broken_messages;
}

// Вовзращает поток байт - сериализованный пакет для отправки 
std::string LC_client::create_package(const std::string &base_dir, const std::string &sub_dir, const std::unordered_set<std::string> &fnames)
{
	// Формируем пакет с транзакциями для отправки
	std::string out;

	pb::Package package;

	pb::DevInfo *pdev_info = package.mutable_devinfo();
	pdev_info->set_psu(psets->device_id);
	pdev_info->set_sys_id(psets->system_id);
	pdev_info->set_type(psets->device_type/*"suv"*/);
	current_time ct;
	package.set_current_time(ct.val);

	for(const auto &fname : fnames){
		
		std::string fpath = base_dir + "/" + sub_dir + "/" + fname;

		logger.msg(MSG_DEBUG | MSG_TO_FILE, DATA_POST_PREFIX "adding %s/%s message to package\n", sub_dir, fname);

		std::fstream input(fpath, std::ios::in | std::ios::binary);
		if( !input.is_open() ){
			throw std::runtime_error(excp_method(std::string("file open failed (") + fpath + ")"));
		}

		pb::Message *pmsg = package.add_messages();

		if( !pmsg->ParseFromIstream(&input) ){
			throw std::runtime_error(excp_method(std::string("ParseFromIstream failed (") + fname + ")"));
		}
	}

	logger.msg(MSG_VERBOSE, DATA_POST_PREFIX "created package:\n%s\n", proto_msg_to_json(package));

	if( !package.SerializeToString(&out) ){
		throw std::runtime_error(excp_method("Package SerializeToString failed"));
	}

	return out;
}

// Формирование и отправка пакета прото-транзакций с анализом супешности приема.
// Если какая-то транзакция не была принята сервером - ее имя удаляется из набора msgs_names
std::unordered_set<std::string> LC_client::send_package_of_messages(const std::string &msgs_dir, const std::string &msgs_subdir, std::unordered_set<std::string> &msgs_names)
{
	std::string package_bytes = this->create_package(msgs_dir, msgs_subdir, msgs_names);

	logger.msg(MSG_DEBUG | MSG_TO_FILE, DATA_POST_PREFIX "trying to send package of size %zu B\n", package_bytes.size());
	// Т.к. ответ - поток байт, необходимо отслеживать его размер
	size_t response_size = 0;
	std::unique_ptr<char, std::function<void(char*)>> response (
		this->curl_transceive(LC_DATA_POST_URI, package_bytes, package_bytes.size(), &response_size), 
		[] (char *p) { free(p); } 
	);

	// Анализ тела полученного ответа и редактирование списка файлов, отправленных успешно
	return this->parse_data_post_response(response.get(), response_size, msgs_names);
}

// Перемещение транзакций в заданную директорию
void LC_client::move_messages(
	const std::string &msgs_dir, 
	const std::string &msgs_subdir, 
	const std::unordered_set<std::string> &msgs_names,
	const std::string &dest_dir)
{
	std::string error_text;	// Строка с описанием ошибок

	for(const auto &fname : msgs_names){
		std::string trans_path = msgs_dir + "/" + msgs_subdir + "/" + fname;
		std::string cmd = "mv " + trans_path + " " + dest_dir;

		if( !lc::utils::exec(cmd, true) ){
			error_text += "move '" + trans_path + "' to " + dest_dir + " failed: " + strerror(errno) + "\n";	
		}
	}
	sync();

	if( !error_text.empty() ){
		throw LC_fs_error(error_text);
	}
}

void LC_client::data_post_request(pb::DataType data_type)
{
	// Определить количество файлов-транзакций в директории для отправки
	uint32_t total_num = ProtoTransactions::count(data_type);
	if( !total_num ){
		// Транзакций такого типа не найдено - нечего отправлять
		return;
	}
	const std::string &trans_dir = ProtoTransactions::dir(data_type);	// Директория транзакций заданного типа
	uint32_t processed_num = 0;											// Кол-во обработанных транзакций
	uint32_t sent_num = 0;												// Кол-во успешно отправленных транзакций
	uint8_t retries_num = psets->put_data_tries;						// Кол-во повторов отправки
	std::pair<std::string, std::unordered_set<std::string>> fnames;		// Имена отправляемых транзакций в ФС
	std::unordered_set<std::string> processed_subdirs;
	std::unordered_set<std::string> processed_messages;

	// Максимальный размер сообщений в одной пакете (подстраивается динамически при неудачной отправке)
	int max_messages_size = psets->put_chunk_size;

	logger.msg(MSG_INFO | MSG_TO_FILE, DATA_POST_PREFIX "found %" PRIu32 " '%s' transaction(s) to send\n", 
		total_num, ProtoTransactions::to_string(data_type));

	// Отправка файлов пачками заданного объема
	while(processed_num < total_num){

		try{
			// Получение имен очередной пачки файлов
			fnames = ProtoTransactions::get_file_names(data_type, max_messages_size, nullptr, &processed_subdirs, &processed_messages);

			if(fnames.first.empty() || fnames.second.empty()){
				break;
			}

			// Запоминаем имена обработанных транзакций
			processed_messages = fnames.second;
			processed_num += fnames.second.size();
			if(processed_num >= lc::utils::get_files_num_in_dir(trans_dir + "/" + fnames.first, LC_PROTO_TRANS_EXT)){
				// Поддиректория полностью обработана - добавляем ее в список обработанных
				processed_subdirs.insert(fnames.first);
			}

			std::unordered_set<std::string> broken_messages = this->send_package_of_messages(trans_dir, fnames.first, fnames.second);

			// Если какие-то из отправленных транзакций сервер не смог принять из-за неверного  
			// формата - изолируем их, чтобы избежать бесконечной переотправки 
			if( !broken_messages.empty() ){
				this->move_messages(trans_dir, fnames.first, broken_messages, pdirs->put_data_isolation_dir);
				logging_info(logger, "Broken messages were moved to isolation directory\n");
			}
			
			// Если ни одна транзакция не была принята - переходим к следующим транзакциям
			if(fnames.second.empty()){
				logging_warn(logger, DATA_POST_PREFIX "server declined full package\n");
				continue;	
			}

			sent_num += fnames.second.size();

			// Переместить успешно отправленные транзакции в директорию для последующего бэкапа
			// (Неуспешно отправленные транзакции при этом остаются ждать следующей попытки отравки)
			this->move_messages(trans_dir, fnames.first, fnames.second, pdirs->put_data_tmp_dir);
		}
		catch(const LC_error &e){

			if( (e.get_code() != LC_error::connection_error) && (e.get_code() != LC_error::protocol_error) ){
				// Ошибки не связанные с соединением и связью пробрасываем выше
				throw;
			}

			if( e.has_http_code() && (e.http_code() < 500) ){
				// Если ошибка не серверная - пробрасываем выше и выходим
				throw;
			}

			logging_excp(logger, "Package with messages:\n");
			size_t n = 1;
			for(const auto &name : fnames.second){
				logger.msg(MSG_ERROR | MSG_TO_FILE, "%d. '%s/%s'\n", n, fnames.first, name);
				++n;
			}
			logger.msg(MSG_ERROR | MSG_TO_FILE, "failed with protocol_error - %s\n", e.what());

			// Не выходим пока остаются попытки переотправки -
			// пытаемся уменьшить размер пакета и попробовать снова
			--retries_num;
			if( !retries_num ){
				throw;
			}

			total_num = ProtoTransactions::count(data_type);
			max_messages_size /= 2;
			processed_num = 0;

			logger.msg(MSG_DEBUG | MSG_TO_FILE, "Trying again with new max_messages_size: %d B\n", max_messages_size);
		}
	}

	// Если за сессию были попытки отправки, но сервер ничего не смог принять - генерируем ошибку
	// (вероятно на сервере какая-то ошибка)
	if( !sent_num ){
		throw LC_error(DATA_POST_PREFIX "server declined all current transactions");
	}
}

// Сделать бэкап успешно отправленных транзакций (директории формируются по дате)
void LC_client::backup_sent_messages()
{	
	if( pdirs->sent_data_dir.empty() || !psets->max_sent_data_size || 
		!lc::utils::get_files_num_in_dir(pdirs->put_data_tmp_dir, ".pb") ){
		// бэкапе не разрешен или нечего бэкапить
		return;
	}

	char dir_name[50] = {0};
	time_t t = time(nullptr);
	strftime(dir_name, sizeof(dir_name), "%y%m%d", localtime(&t));

	// Формирование имени архива
	char tar_name[128] = {0};
	char dt_str[50] = {0};
	strftime(dt_str, sizeof(dt_str), "%y%m%d%H%M%S", localtime(&t));
	uuid_t uid;
	uuid_generate(uid);
	char uid_str[40] = {0};
	uuid_unparse(uid, uid_str);
	uid_str[6] = '\0'; // используются первые 6 символов

	sprintf(tar_name, "%s_tr_%010u_%s.tar", dt_str, psets->device_id, uid_str);

	// Версия утилиты tar на устройстве не поддерживает флаг -z , поэтому сжимаем отдельно gzip-ом
	std::string res = lc::utils::exec_piped("cd " + pdirs->put_data_tmp_dir + " && tar -cf " + 
		tar_name + " ./*.pb 2>&1 && gzip " + tar_name + " 2>&1 && mkdir -p " + pdirs->sent_data_dir + "/" +  
		dir_name + " && mv " + tar_name + ".gz " + pdirs->sent_data_dir + "/" + dir_name + " 2>&1");

	if( !res.empty() ){
		logging_err(logger, "failed for '%s': %s\n", tar_name, res);
		return;
	} 

	logger.msg(MSG_DEBUG | MSG_TO_FILE, "Sent messages backuped to '%s/%s.gz'\n", dir_name, tar_name);
	lc::utils::exec("rm -f " + pdirs->put_data_tmp_dir + "/*", true);
}

// Основная функция отправки данных в формате protobuf
void LC_client::put_data()
{
	if( !psets ){
		throw LC_error(excp_method("no LC client settings provided"));
	} 

	if( !psets->perms.put_data ){
		logger.msg(MSG_INFO | MSG_TO_FILE, DATA_POST_PREFIX "Sending data is disabled.\n");
		return;
	} 

	// Подготовка директорий перед запуском запроса
	lc::utils::make_dir_if_not_exists(pdirs->put_data_dir);
	lc::utils::make_dir_if_not_exists(pdirs->put_data_tmp_dir);
	lc::utils::make_dir_if_not_exists(pdirs->put_data_isolation_dir);
	lc::utils::make_dir_if_not_exists(pdirs->sent_data_dir);

	// На случай если во временной директории что-то осталось с прошлой сессии
	this->backup_sent_messages();

	// Очистить временную директорию после предыдущих сессий
	lc::utils::exec("rm -f " + pdirs->put_data_tmp_dir + "/*", true);

	try{
		// Отправка данных осуществялется согласно приоритету выставленному в sending_order
		for(const auto data_type : psets->sending_order){
			auto do_request = [this, data_type](){ this->data_post_request(data_type); };
			this->try_to_make_request( do_request, psets->put_data_tries );
		}

		// Отправленные транзакции кладем в бэкап
		this->backup_sent_messages();
	}
	catch(const LC_error &e){

		// Вероятно, некоторые транзакции все же отправились - бэкапим
		this->backup_sent_messages();

		if(e.get_code() == LC_error::connection_error){
			this->res_map["No connection"] = lc::result(-1, e.what());
			throw;
		}
		else{
			this->res_map["Put data error"] = lc::result(-1, e.what());
		}

		// logging_excp(logger, "%s\n", e.what());

	}
}


#ifdef _LC_CLIENT_TEST

#include <fstream>
// #include "lc_client.hpp"

Logging mlog(MSG_DEBUG, "[ MAIN ]");

// Сохранение БД стоп-листа в закодированном по BASE64 виде
static void save_stoplist_b64(const std::string &file_content, const std::string &file_ver) 
{
	std::string dest_dir = ".";
	std::string name = dest_dir + "/stoplist." + file_ver + ".b64";
	lc::utils::write_text_file(name, file_content.c_str(), file_content.length());

	mlog.msg(MSG_DEBUG, "Encodded stoplist (ver.'%s') has been saved\n", file_ver);
}

// Сохранение БД Нормативно-Справочной-Информации в раскодированном бинарном виде (в виде tar архива)
static void save_nsi_bin(const uint8_t *file_content, size_t file_size, const std::string &file_ver) 
{
	std::string dest_dir = ".";
	std::string name = dest_dir + "/nsi." + file_ver + LC_FILE_EXT;
	lc::utils::write_bin_file(name, file_content, file_size);

	mlog.msg(MSG_DEBUG, "Decoded nsi (ver.'%s') of size: %zu [B] has been saved\n", file_ver, file_size);

	// Распаковка при необходимости
	std::string db_name = lc::utils::unpack_tar(name, dest_dir);
	mlog.msg(MSG_DEBUG, "'%s' has been unpacked\n", db_name);
	lc::utils::change_mod(dest_dir + "/" + db_name, 0666);
}

int main(int argc, char* argv[])
{
	// Определяем настройки клиента
	LC_client::settings sets;
	LC_client::directories dirs;
	sets.device_id = 3487366287;		// Тестовый ID
	sets.system_id = sets.device_id;
	//Назначанем колбеки для обработки принятых файлов
	sets.get["device_tgz"].dec_save = save_nsi_bin;
	sets.get["device_tgz_stoplist"].enc_save = save_stoplist_b64;
	sets.get["device_tgz_stoplist"].curr_ver = "1";

	// Добавляем новый (несуществующий на сервере) файл для скачивания
	// ПРИМ: при расширении протокола достаточно будет назначить колбек для
	// нового типа файла при помощи  sets.get[]
	sets.get["new_stoplist"].enc_save = save_stoplist_b64;

	// Создаем клиента
	LC_client lcc(&dirs, &sets);

	try{
		lcc.init();
		lcc.show_start();		// Информационное сообщение о запуске клиента

		lcc.rotate_sent_data();	// Проверка объема бэкаппа отправленных данных. Очистка при необходимости
		lcc.get_files();		// 
		lcc.put_files();		//
	}
	catch(LC_no_connection &e){
		// фиксируем что связь отсутствует. сообщение об этом появится в show_results()
	}
	catch(const std::exception &e){
		logging_excp(mlog, "%s\n", e.what());
	}
	
	lcc.show_results();			//
	lcc.deinit();
	return 0;
}

#endif