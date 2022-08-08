
#include <algorithm>
#include <cinttypes>

#define LOG_MODULE_NAME			"[ LCT ]"
#include "logger.hpp"

#include "log.pb.h"
#include "log_result.pb.h"
#include "lc_utils.hpp"
#include "lc_trans.hpp"

namespace lc{

#ifndef _SHARED_LOG
Logging ProtoTransactions::logger{MSG_DEBUG, LOG_MODULE_NAME};
#endif

#define PROTOCOL_VERSION 		"2.0"

// Инициализация статических членов класса
std::unordered_map<int, std::string> ProtoTransactions::dirs = {
	{static_cast<int>(pb::SELL_LOG), ProtoTransactions::to_string(pb::SELL_LOG)},
	{static_cast<int>(pb::RIDES_LOG), ProtoTransactions::to_string(pb::RIDES_LOG)},
	{static_cast<int>(pb::VIEW_LOG), ProtoTransactions::to_string(pb::VIEW_LOG)},
	{static_cast<int>(pb::SYS_LOG), ProtoTransactions::to_string(pb::SYS_LOG)},
};

uint32_t ProtoTransactions::dev_id_ = 0;
uint32_t ProtoTransactions::sys_id_ = 0;	
std::string ProtoTransactions::dev_type_;
ProtoTransactions::SysEvents ProtoTransactions::sys_events;


void ProtoTransactions::init(const std::string &base_dir, uint32_t dev_id, uint32_t sys_id, const std::string &dev_type)
{
	dev_id_ = dev_id;
	sys_id_ = sys_id;
	dev_type_ = dev_type;

	// Обновляем местоположение директорий транзакций 
	for(auto &item : dirs){
		item.second = base_dir + "/" + lc::utils::short_name(item.second);
		lc::utils::make_dir_if_not_exists(item.second);
	}
}

// Вызывать в конце работы приложения - после вызова, методы работать не будут
void ProtoTransactions::deinit()
{
	// Освободить все глобальные ресурсы выделенные библиотекой libprotobuf 
	google::protobuf::ShutdownProtobufLibrary();
	dev_id_ = 0;
	sys_id_ = 0;
	dev_type_ = "";
}

std::string ProtoTransactions::save(const pb::Message &msg)
{
	std::string res;

	if(msg.name().empty()){
		std::string err_msg("message has no name");
		logging_warn(logger, "%s. skipping\n", err_msg);
		res = std::move(err_msg);
		return res;
	}

	auto it = dirs.find(msg.type());
	if(it == dirs.end()){
		std::string err_msg = "message(" + msg.name() + ") has unsupported type (" + std::to_string(msg.type()) + ")";
		logging_warn(logger, "%s. skipping\n", err_msg);
		res = std::move(err_msg);
		return res;
	}

	// Формирование имени файла с транзакцией (директории делятся по типу и по дате)
	std::string path = it->second;
	char dir_name[50] = {0};
	time_t t = time(nullptr);
	strftime(dir_name, sizeof(dir_name), "%y%m%d", localtime(&t));
	path += std::string("/") + dir_name;
	// Создаем директорию по дате
	lc::utils::make_dir_if_not_exists(path);
	// Для записи используем имя временного файла, чтобы он в момент записи не попал в 
	// список для отправки на сервер во время очередной передачи 
	path += "/" + msg.name() + LC_PROTO_TRANS_EXT;
	std::string tmp_path = path + ".tmp";
	// Запись в файл сериализованного сообщения 
	std::fstream output(tmp_path, std::ios::out | std::ios::trunc | std::ios::binary);
	if( !output.is_open() ){
		throw std::runtime_error(excp_method(std::string("file open failed (") + tmp_path + ")"));
	}

	if( !msg.SerializeToOstream(&output) ){
		throw std::runtime_error(excp_method("msg.SerializeToOstream failed"));
	}

	output.flush();
	output.close();

	// Помечаем файл, как готовый к отправке 
	if( rename(tmp_path.c_str(), path.c_str()) ){
		throw std::runtime_error(excp_method("rename from .tmp failed"));
	}

	return res;
}

// Заполнение информации о неуспешно обработанном сообщении
static void fill_failed_message(pb::Message *pmsg, const std::string &msg_name, const std::string &err_text)
{
	pmsg->set_name(msg_name);
	pmsg->set_encrypted(pb::NONE);
	pmsg->set_type(pb::LOG_RESULT);

	pb::LogResult log_res;

	log_res.set_errorcode(1);
	log_res.set_errortext(err_text);

	std::string data;

	if( !log_res.SerializeToString(&data) ){
		throw std::runtime_error(excp_func("log_res SerializeToString failed"));
	}

	pmsg->set_data(data);
}

// Возвращает сериализованный пакет с результатами обработки транзакций 
std::string ProtoTransactions::save(const std::string &bytes_stream)
{
	using namespace pb;

	// Ответ идентичен формату запроса. В массив messages помещаются неуспешно обратанные 
	// транзакции: в Message.data при этом кладется стуктура класса LogResult с описанием ошибки
	std::string response;
	Package response_package;
	response_package.set_protocol_ver(PROTOCOL_VERSION);
	response_package.mutable_devinfo()->set_psu(dev_id_);
	response_package.mutable_devinfo()->set_sys_id(sys_id_);
	response_package.mutable_devinfo()->set_type(dev_type_);
	response_package.set_current_time(lc::utils::get_local_datetime_fmt("%Y-%m-%d %H:%M:%S.", true));

	// Обработка входного потока байт - пакета с транзакциями
	Package package;
	if( !package.ParseFromString(bytes_stream) ){
		throw std::runtime_error(excp_method("ParseFromString failed"));
	}

	logging_msg(logger, MSG_TRACE, "Got transaction package: %s\n", proto_msg_to_json(package));

	for(int i = 0; i < package.messages_size(); ++i){

		const auto &msg = package.messages(i);

		std::string res = ProtoTransactions::save(msg);
		if( !res.empty() ){
			// Добавляем в массив сообщений информацию о неуспешно обработанном
			Message *pmsg = response_package.add_messages();
			fill_failed_message(pmsg, msg.name(), res);			
		}

		logging_msg(logger, MSG_DEBUG | MSG_TO_FILE, "Saved transaction: " _GREEN "%s" _RESET "\n", msg.name());
		// logging_msg(logger, MSG_TRACE, "%s\n", proto_msg_to_json(msg));
	}

	if( !response_package.SerializeToString(&response) ){
		throw std::runtime_error(excp_method("response_package SerializeToString failed"));
	}

	return response;
}

void ProtoTransactions::check_and_clean()
{
	for(const auto &item : dirs){
		// Проверяем есть ли пустые директории по датам и удаляем их
		std::string cmd = "for dir in $(ls " + item.second + "); do rmdir " + item.second + "/$dir 2>/dev/null; done";
		lc::utils::exec_piped(cmd);
	}
}

uint32_t ProtoTransactions::count(pb::DataType type)
{
	uint32_t cnt = 0;

	if(type == pb::RAW){
		// Проходимся по всем директориям транзакций и считаем их кол-во во вложенных директориях дат
		for(const auto &item : dirs){
			cnt += lc::utils::get_files_num_in_dir(item.second, LC_PROTO_TRANS_EXT, true);
		}
	}
	else{
		cnt = lc::utils::get_files_num_in_dir(dirs.at(static_cast<int>(type)), LC_PROTO_TRANS_EXT, true);
	}

	return cnt;
}

// Возвращает имена файлов из одной поддиректории для заданного типа транзакции.
// Поддиректории хранятся по датам - на каждый новый день создается отдельная директория
// По умолчанию набор имен файлов возвращается из самой древней найденной поддиректории
// Передав набор prev_subdirs можно указать какие поддиректории стоит проигнорировать 
std::pair<std::string, std::unordered_set<std::string>> ProtoTransactions::get_file_names(
	pb::DataType type,
	uint64_t max_size,
	uint64_t *total_size,
	const std::unordered_set<std::string> *prev_subdirs,
	const std::unordered_set<std::string> *prev_names)
{
	// Получаем имена поддиректорий по датам 
	const std::string &trans_dir = dirs.at(static_cast<int>(type));

	std::unordered_set<std::string> file_names;
	std::string subdir;
	std::vector<std::string> subdir_names = lc::utils::get_subdirs_names_in_dir(trans_dir);

	// Сортируем в порядке возрастания даты 
	std::sort(subdir_names.begin(), subdir_names.end());

	for(const auto &dir_name : subdir_names){

		if( prev_subdirs && (prev_subdirs->find(dir_name) != prev_subdirs->end()) ){
			// Пропускаем уже просмотренные ранее поддиректории
			continue;
		}

		std::string dir = trans_dir + "/" + dir_name;

		if( lc::utils::get_files_num_in_dir(dir) ){
			file_names = lc::utils::get_file_names_in_dir(dir, LC_PROTO_TRANS_EXT, max_size, total_size, prev_names);
			subdir = dir_name;
			break;
		}
	}

	return {subdir, file_names};
}

pb::Message ProtoTransactions::create_message(
	const std::string &name, 
	pb::DataType data_type,
	const std::string &data,
	pb::EncryptionType enc_type,
	pb::SignatureType sig_type
	)
{
	pb::Message pb_msg;

	pb_msg.set_name(name);
	
	pb_msg.mutable_devinfo()->set_psu(ProtoTransactions::dev_id_);
	pb_msg.mutable_devinfo()->set_sys_id(ProtoTransactions::sys_id_);
	pb_msg.mutable_devinfo()->set_type(ProtoTransactions::dev_type_);

	pb_msg.set_type(data_type);

	// Шифруем данные 
	std::string encrypted_data;
	pb_msg.set_encrypted(enc_type);
	switch(enc_type){
		case pb::NONE: 
			pb_msg.set_data(data);
			break;

		case pb::AES:
			lc::utils::aes128_encrypt(data.c_str(), data.size(), ProtoTransactions::sys_id_, encrypted_data);
			pb_msg.set_data(encrypted_data);
			break;

		default:
			logging_warn(logger, "Unsupported encryption type: %d\n", enc_type);
	}

	// Подписываем данные
	pb_msg.set_signature_type(sig_type);
	switch(sig_type){
		case pb::SHA1:
			pb_msg.set_signature(lc::utils::SHA1_hash(data.c_str(), data.size()));
			break;

		// TODO:
		case pb::SHA256:
		case pb::HMAC_SHA1:
		case pb::HMAC_SHA256:

		default:
			logging_warn(logger, "Unsupported signature type: %d\n", enc_type);
	}

	return pb_msg;
}

// Создание прото-файла системного события 
void ProtoTransactions::SysEvents::create(uint32_t psutrans, const sys_event &sev, const std::string &sev_data) const
{
	// Проверка уровня события
	if(this->get_level() < sev.info.level){
		return;
	}

	pb::SysEventsLog pb_sev_log;

	char arr[3] = {0};
	strncpy(arr, sev.info.code.c_str(), 2);

	pb_sev_log.set_psutrans(psutrans);
	pb_sev_log.set_psu(ProtoTransactions::dev_id_);
	pb_sev_log.set_actcode(arr);

	time_t t = time(nullptr);
	struct tm *curr_tm = localtime(&t);
	if(curr_tm){
		pb_sev_log.set_actday(curr_tm->tm_mday);
		pb_sev_log.set_actmonth(curr_tm->tm_mon + 1);
		pb_sev_log.set_actyear(curr_tm->tm_year + 1900);
		pb_sev_log.set_acthour(curr_tm->tm_hour);
		pb_sev_log.set_actmin(curr_tm->tm_min);
		pb_sev_log.set_actsec(curr_tm->tm_sec);
	}

	uint32_t tmp = 0; 
	sscanf(sev.gps_latitude.c_str(), "%" PRIu32 "", &tmp);
	pb_sev_log.set_gpswide(tmp);
	sscanf(sev.gps_longitude.c_str(), "%" PRIu32 "", &tmp);
	pb_sev_log.set_gpslong(tmp);

	strncpy(arr, sev.info.devcode.c_str(), 2);
	pb_sev_log.set_devcode(arr);
	pb_sev_log.set_gps_latitude(sev.gps_latitude);
	pb_sev_log.set_gps_longitude(sev.gps_longitude);
	pb_sev_log.set_gps_valid(sev.gps_valid);

	// Генерация контрольной суммы по дампу данных события 
	uint32_t crc32 = sys_event_record::dump_crc(curr_tm, ProtoTransactions::dev_id_, psutrans, sev);
	pb_sev_log.set_crcrec(crc32);

	// Добавляем дополнительную информацию события
	pb_sev_log.set_datasys(sev_data);

	std::string serialized_sev_log;
	if( !pb_sev_log.SerializeToString(&serialized_sev_log) ){
		throw std::runtime_error(excp_method("pb_sev_log.SerializeToString() failed"));
	}

	// Пример формата имени: 3626321533_71254_sys_220308233821.pb
	std::string name = std::to_string(ProtoTransactions::dev_id_) + "_" + std::to_string(psutrans) + "_sys_" +
		ProtoTransactions::dev_type_ + "_" + lc::utils::get_local_datetime_fmt("%Y%m%d%H%M%S", false, &t);

	// Упаковываем лог события в формат сообщения и сохраняем на диск
	pb::Message pb_msg = ProtoTransactions::create_message(name, pb::SYS_LOG, serialized_sev_log, pb::AES, pb::SHA1);

	ProtoTransactions::save(pb_msg);
}






// InfoPush


} // namespace

#ifdef _LC_TRANS_TEST

int main(int argc, char* argv[])
{

	try{

	}
	
	catch(const std::exception &e){

	}

	return 0;
}

#endif