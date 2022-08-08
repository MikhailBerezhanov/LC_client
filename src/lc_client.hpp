/*============================================================================== 
Описание: 	Реализация API клиента Локального Центра.

Автор: 		berezhanov.m@gmail.com
Дата:		04.11.2021
Версия: 	1.0
==============================================================================*/

#ifndef _LC_CLIENT_HPP_ 
#define _LC_CLIENT_HPP_

#include <cstdint>
#include <cinttypes>
#include <string>
#include <map>
#include <unordered_map>
#include <functional>
#include <thread>
#include <exception>

extern "C"{
#include <curl/curl.h>
}

#include "lc_protocol.hpp"
#include "lc_utils.hpp"
#include "logger.hpp"
#include "lc.pb.h"
#include "info.pb.h"

// URI адреса функций протокола
// Обмен в формате JSON
#define LC_GET_FILE_URI				"/data/device/file_get"
#define LC_PUT_FILE_URI				"/data/device/file_post" 
#define LC_GET_UNBLOCK_URI			"/data/device/trip_info_get"
#define LC_GET_MEDIA_LIST_URI 		"/data/device/get_media_list"
// Обмен в формате Protobuf
#define LC_DATA_POST_URI			"/data/device/data_post"
#define LC_PUT_INFO_URI				"/data/device/info_post"

using lc_media_list = std::vector<lc::list_elem>;

class LC_error: public std::runtime_error{
public:

	typedef enum {
		no_error = 0,
		internal_error = -1,
		connection_error = -2,
		protocol_error = 1,
		data_error = 2,
		fs_error = 3,
	}code_t;

	LC_error(): std::runtime_error(""), code(internal_error) {}

	LC_error(const std::string &err_text, code_t err_code = internal_error): 
		std::runtime_error(err_text), code(err_code) {}

	LC_error(const char *err_text, code_t err_code = internal_error): 
		std::runtime_error(err_text), code(err_code) {}

	code_t get_code() const noexcept { return code; }

	virtual long http_code() const { return -1; };
	virtual bool has_http_code() const { return false; };

private:
	code_t code;
};

class LC_no_connection: public LC_error{
public:
	LC_no_connection(const std::string &err_text = ""): LC_error(err_text, LC_error::connection_error) {}
};

class LC_no_data: public LC_error{
public:
	LC_no_data(const std::string &err_text = ""): LC_error(err_text, LC_error::data_error) {}
};

class LC_fs_error: public LC_error{
public:
	LC_fs_error(const std::string &err_text = ""): LC_error(err_text, LC_error::fs_error) {}
};

class LC_protocol_error: public LC_error{
public:
	LC_protocol_error(const std::string &err_text = "", long hcode = -1): 
		LC_error(err_text, LC_error::protocol_error), http_code_(hcode) {}

	long http_code() const override { return http_code_; }
	bool has_http_code() const override { return http_code_ != -1; }

private:
	long http_code_ = -1;
};

// Информация об устройстве
class LC_base_device_info{

public:
	LC_base_device_info(pb::DataType dtype = pb::RAW): data_type(dtype) {}

	virtual ~LC_base_device_info() = default;

	virtual std::string serialize_to_proto() const = 0;

private:
	pb::DataType data_type = pb::RAW;
}; 

// TODO: Реакция на PUSH сообщение
class LC_action{
public:
	using callback = std::function<void(const std::string &data, int data_mode, int duration)>;

	class next_action{
	public:
		next_action() = default;

		next_action(callback cb, const std::string &d, int dm, int dur):
			func(cb), data(d), data_mode(dm), duration(dur), pending(true) {}

		void execute_pending(){
			if(pending){
				std::thread(func, data, data_mode, duration).detach();
				pending = false;
			}
		}
	private:
		callback func = nullptr;
		std::string data;
		int data_mode = -1;
		int duration = -1;
		bool pending = false;
	}next_act;

	std::map<std::string, callback> cb_map;

	std::vector<callback> active_cb;

	static void finish_execution(){
		execution_finished = true;
	}

private:
	static bool execution_finished;	// Признак окончания обработки очередного действия
};

// Класс реализующий клиента ЛЦ
class LC_client{
public:
	// Используемые директории для обмена данным
	struct directories{
		directories() = default;
		directories(const std::string &put_dir, const std::string &sent_dir):
			put_data_dir(put_dir), sent_data_dir(sent_dir) {}

		// директория с транзакциями для отправки
		std::string put_data_dir = lc::utils::get_cwd() + "/lcc_put_data";	
		std::string put_data_tmp_dir = put_data_dir + "/tmp";
		std::string put_data_isolation_dir = put_data_dir + "/broken";
		// директория для хранения успешно отправленных транзакций (бэкап)
		std::string sent_data_dir = lc::utils::get_cwd() + "/lcc_sent_data";	
	};

	// Струртура обработки скачиваемых файлов
	struct get_processing{
		// Прототип Колбек функции получения файла с сервера
		using dec_save_cb = std::function<void(const std::string &file_name, const uint8_t *file_content, size_t file_size, const std::string &file_ver)>;
		using enc_save_cb = std::function<void(const std::string &file_name, const std::string &file_content, const std::string &file_ver)>;

		std::string curr_ver = "undefined"; // текущая версия файла
		bool enabled = true;				// флаги разрешения отправки запроса на скачивание файла из ЛЦ
		dec_save_cb dec_save = nullptr;		// сохранение в раскодированном виде (банирный файл)
		enc_save_cb enc_save = nullptr;		// сохранение в закодированном base64 виде (текстовый файл) 
	};

	// Настройки соединения и обмена данными с ЛЦ
	struct settings{
		settings(): lsets(MSG_DEBUG, "[ LCC ]", lc::utils::get_cwd() + "/lcc.log", 0, MB_to_B(1)) {}

		std::string lc_server_url = "http://test.tk05.ru";	// адрес сервера ЛЦ
		std::string device_type = "usk04";	// тип устройства, с которого запущен клиент
		int max_put_files_num = 60;	// максимальное кол-во файлов для одной отправки транзакций
		uint64_t put_chunk_size = lc::utils::MB_to_B(2);	// максимальный размер файлов в одной посылке транзакций [Б]
		uint64_t max_sent_data_size = lc::utils::MB_to_B(2);
		uint32_t device_id = 0;		// идентификатор устройства
		uint32_t system_id = 0;		// идентификатор системы (может совпадать с устройством)

		Logging::settings lsets;	// настройки логирования

		int server_tmout = 180;		// таймаут ожидания ответа от сервера (с)
		int get_data_tries = 3;		// кол-во попыток для скачивания файлов
		int put_data_tries = 3;		// кол-во попыток для отправки файлов
		bool ssl_check = false;		// флаг разрешения поддержки протокола HTTPS при обмене данными
		bool curl_verbose = false;	// флаг разрешения подробного лога curl

		// Структура управления обменом данными с Локальным Центром
		struct permissions{
			bool unblock = false;	// флаг разрешения отправки запроса на разблокировку из ЛЦ
			bool put_data = true;	// флаг разрешения отправки запроса на передачу транзакций в ЛЦ
			bool get_media_list = false; // флаг разрешения отправки запроса на получение медиа листов
		}perms;

		// Тип поддерживаемого файла <-> структура обработки
		std::unordered_map<std::string, get_processing> get = {
			{ "device_tgz", get_processing() },
			{ "device_tgz_stoplist", get_processing() },
			{ "device_tgz_magiclist", get_processing() },
			{ "firmware_usk04", get_processing() },
			{ "firmware_suv", get_processing() },
		};

		// Приоритет отправки данных транзакций методом data_post
		std::vector<pb::DataType> sending_order{ {pb::SELL_LOG, pb::RIDES_LOG, pb::SYS_LOG, pb::VIEW_LOG} };

		void set_sending_order(const std::initializer_list<pb::DataType> &ilist){
			sending_order.assign(ilist);
		}

		void set_sending_order(const std::vector<std::string> &svec){
			sending_order.clear();

			for(const auto &item : svec){
				if(item == "sells"){
					sending_order.push_back(pb::SELL_LOG);
				}
				else if(item == "rides"){
					sending_order.push_back(pb::RIDES_LOG);
				}
				else if(item == "views"){
					sending_order.push_back(pb::VIEW_LOG);
				}
				else if(item == "sys"){
					sending_order.push_back(pb::SYS_LOG);
				}
			}
		}
	};

	// LC_client() = default;
	LC_client(directories *d, settings *s): pdirs(d), psets(s) {
		if( !pdirs || !psets ) throw std::invalid_argument(excp_method("invalid settings or directories pointer"));
	}

	// Глобальная инициализация CURL. Вызывается один раз при старте приложения
	static void global_init();
	static void global_cleanup();

	void init(settings *s = nullptr);
	void deinit();

	uint32_t get_dev_id() const { return psets ? psets->device_id : 0; }
	std::string get_server_url() const { return psets ? psets->lc_server_url.c_str() : ""; }
	std::string get_dev_type() const { return psets ? psets->device_type : ""; }

	// Скачивание определенного типа файла
	void get_file(const std::string file_type, const get_processing &file_proc);

	// Скачивание всех зарегистрированных в sets.get файлов
	void get_files();

	// Отправка всех накопленных в dirs.put_data_dir файлов транзакций
	void put_files();

	// Отправка всех накопленных в dirs.put_data_dir прото-транзакций (protobuf)
	void put_data();

	// Колбек на получение медиа-листов (временных tmp_list=true или постоянных tmp_list=false)
	std::function<void(lc_media_list &list, bool tmp_list)> on_media_list_get = nullptr;
	// Скачивание медаи-листов
	void get_media_lists(const std::string &tmp_media_ver, const std::string &const_media_ver);

	// Бэкап удачно отправленных транзакций в dirs.sent_data_dir
	void rotate_sent_data();

	// Логгирование начала сессии клиента
	void show_start(){
		std::string msg = Logging::padding(64, " Starting LC-Client ", '=');
		logger.msg(MSG_INFO | MSG_TO_FILE, "%s\n", msg);
		logger.msg(MSG_INFO | MSG_TO_FILE, "ID: %" PRIu32 " (%s) connecting to '%s'\n", 
			get_dev_id(), get_dev_type(), get_server_url());
	}

	// Логгирование результатов сессии связи
	bool show_results(){
		std::string msg = Logging::padding(64, " LC-Client finished ", '=');
		logger.msg(MSG_INFO | MSG_TO_FILE, "%s\n", msg);
		uint cnt = 0;
		bool connection = true;
		for(const auto &elem : this->res_map){
			if(elem.first == "No connection"){
				connection = false;
			} 

			logger.msg(MSG_INFO | MSG_TO_FILE, _RED "%s" _RESET ": %s\n", elem.first, elem.second.text);
			++cnt;
		}
		this->res_map.clear();
		msg = Logging::padding(64, " Summary: " + std::to_string(cnt) + " errors ", '=');
		logger.msg(MSG_INFO | MSG_TO_FILE, "%s\n\n", msg);
		return connection;
	}

	Logging logger;

private:
	LC_action act_handler;

	const LC_base_device_info *device_info = nullptr;
	const directories *pdirs = nullptr;
	const settings *psets = nullptr;
	mutable std::map<std::string, lc::result> res_map; 

	CURL *hcurl = nullptr;
	struct curl_slist *req_header = nullptr;
	char curl_err[CURL_ERROR_SIZE] = {0};

	bool curl_reset();
	void curl_setup_connection(size_t post_size = 0) noexcept;
	void curl_setup_request(const std::string &url, const std::string &post_data, void *wr_ptr, size_t post_size) noexcept;
	char* curl_transceive(const std::string &uri, const std::string &body, size_t body_size = 0, size_t *response_size = nullptr);

	void try_to_make_request(std::function<void(void)> do_request, int tries);

	// (метод file_get) - запрос файлов 
	void file_get_request(const std::string &type, const std::string &ver = "undefined");
	void file_get_request(std::vector<lc::file_info> &info_arr);
	void parse_file_get_response(const char *response_body, const std::string &type = "files array", const std::string &ver = "undefined") const;
	
	// (метод file_post) - передача файлов транзакций 
	uint32_t prepare_files(std::vector<std::string> &fnames, time_t *pt) const;
	std::string pack_prepared_files(time_t t) const;
	std::string create_put_file_json(const std::string &tar_name) const;
	void file_post_request();
	void parse_file_post_response(const char *response_body, const std::string &tar_name, const std::vector<std::string> &fnames) const;

	// TODO: (метод sys_info_put) - передача информации об устройстве (пинг) 
	void info_post_request(const lc::sys_info *si);
	void parse_info_post_response(const char *response_body);

	// (метод data_post) - передача протобуф пакета транзакций
	std::string create_package(const std::string &base_dir, const std::string &sub_dir, const std::unordered_set<std::string> &fnames);
	std::unordered_set<std::string> parse_data_post_response(const char *response_data, size_t response_size, std::unordered_set<std::string> &fnames);
	std::unordered_set<std::string> send_package_of_messages(const std::string &msgs_dir, const std::string &msgs_subdir, std::unordered_set<std::string> &msgs_names);
	void move_messages(const std::string &msgs_dir, const std::string &msgs_subdir, const std::unordered_set<std::string> &msgs_names, const std::string &dest_dir);
	void data_post_request(pb::DataType dtype);
	void backup_sent_messages();

	// (метод get_media_list) - получение от сервера списков медиа-файлов
	void get_media_list_request(std::vector<lc::file_info> &info_arr);
	void parse_get_media_list_response(const char *response_body, const std::string &type = "files array", const std::string &ver = "undefined") const;
};

#endif