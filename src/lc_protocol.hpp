/*============================================================================== 
Описание: 	Реализация протокола обмена данными в формате JSON с Локальныи Центром.

Автор: 		berezhanov.m@gmail.com
Дата:		04.11.2021
Версия: 	1.0
==============================================================================*/

#ifndef _LC_PROTOCOL_HPP_ 
#define _LC_PROTOCOL_HPP_

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <ctime>

#include "nlohmann/json.hpp"


namespace lc {

#define LC_PROTOCOL_VERSION 	"1.30"


#define LC_DB_TRANS_EXT			".db"	// Расширение файла транзакции в формате БД
#define LC_FILE_EXT				".tar"	// Расширение для архивации файлов


////////////////////// Общие структуры данных протокола 
struct result{
	result(): code(-1), text("undefined") {}
	result(int c, std::string t): code(c), text(t) {}
	int code;					// Код возврата
	std::string text;			// Текст ошибки (необязательное поле)
};

struct header{
	std::string protocol_ver = LC_PROTOCOL_VERSION;	// Версия протокола
};

struct dev_info{
	dev_info() = default;
	dev_info(uint32_t p, const std::string &t): psu(p), type(t) {}
	dev_info(uint32_t p, std::string &&t): psu(p), type(std::move(t)) {}
	uint32_t psu = 0;			// Идентификатор устройства (номер ПСУ)
	std::string type;			// Тип устройства
};

struct file_info{
	file_info() = default;
	file_info(const std::string &t, const std::string &v): type(t), version(v) {}
	file_info(std::string &&t, std::string &&v): type(std::move(t)), version(std::move(v)) {}
	std::string type;			// Тип файла 
	std::string version;		// Версия данных файла

	friend std::ostream& operator<< (std::ostream &, const file_info &);
};

struct file{
	file() = default;
	file(const std::string &t, 
		 const std::string &v, 
		 uint64_t s, 
		 const std::string &n, 
		 const std::string &c, 
		 uint32_t cr):
			info(t, v), size(s), name(n), content(c), crc(cr) {}
			
	file_info info;
	uint64_t size = 0;			// Размер файла (длина Base64-строки content)
	std::string name;			// Имя файла
	std::string content;		// Содержимое файла (закодированное Base64)
	uint32_t crc = 0;			// CRC32 по Base64-строке content

	friend std::ostream& operator<< (std::ostream &, const file &);
};

struct list_elem{
	list_elem() = default;
	list_elem(const std::string &name_, const std::string &md5_): name(name_), md5(md5_){}

	std::string name;	// Имя файла
	std::string md5;	// MD5 файла
};

struct signature{
	// TODO
	std::string val = "signature";
};

struct current_time{
	current_time() {
		struct tm timeinfo;
		struct timespec spec;
	 
		clock_gettime(CLOCK_REALTIME, &spec);

		if( !localtime_r(&spec.tv_sec, &timeinfo) ){
			return;
		}

		char time_str[32] = {0};
		char buf[64] = {0};
		strftime(time_str, sizeof time_str, "%d.%m.%Y %T", &timeinfo);
		snprintf(buf, sizeof buf, "%s.%03lu", time_str, spec.tv_nsec / 1000000L); 

	 	val = buf;
	}

	current_time(const char *fmt_time): val(fmt_time) {}
	current_time(std::string& fmt_time): val(fmt_time) {}

	std::string val;
};

////////////////////// Запрос файла(-ов) из ЛЦ
struct file_get_request{
	file_get_request() = default;
	explicit file_get_request(uint32_t psu, const std::string &dev_type): devinfo(psu, dev_type) {}
	explicit file_get_request(uint32_t psu, const std::string &dev_type, std::vector<file_info> &fi):
		devinfo(psu, dev_type), finfo(fi) {}

	explicit file_get_request(uint32_t psu, std::string &&dev_type, std::vector<file_info> &&fi):
		devinfo(psu, std::move(dev_type)), finfo(std::move(fi)) {}

	header hdr;
	dev_info devinfo;
	std::vector<file_info> finfo;	// Коллекция версий запрашиваемых файлов
	current_time ctime;
	signature sig;

	std::string to_json() const;
};

struct file_get_response{
	file_get_response(): ctime("") {}
	file_get_response(const char *json_str) { this->from_json(json_str); }

	header hdr;
	result res;
	std::vector<file> files;		// Коллекция полученных файлов
	current_time ctime;
	signature sig;

	void from_json(const char *json_str);
	friend std::ostream& operator<< (std::ostream &, const file_get_response &);
};

////////////////////// Передача файла(-ов) в ЛЦ
struct file_post_request{
	file_post_request() = default;
	explicit file_post_request(uint32_t psu, const std::string &dev_type): devinfo(psu, dev_type) {}
	explicit file_post_request(uint32_t psu, const char *dev_type): devinfo(psu, dev_type) {}
	header hdr;
	dev_info devinfo;
	std::vector<file> files; 		// Коллекция отправляемых файлов
	current_time ctime;
	signature sig;

	std::string to_json() const;
};

struct file_post_response{
	file_post_response(): ctime("") {}
	file_post_response(const char *json_str) { this->from_json(json_str); }

	header hdr;
	result res;
	current_time ctime;
	signature sig;

	void from_json(const char *json_str);
	friend std::ostream& operator<< (std::ostream &, const file_post_response &);
};

////////////////////// Запрос медиа-листов из ЛЦ
struct get_media_list_request : public file_get_request{
	get_media_list_request(): file_get_request() {}
	explicit get_media_list_request(uint32_t psu, const std::string &dev_type): file_get_request(psu, dev_type) {}
	explicit get_media_list_request(uint32_t psu, const std::string &dev_type, std::vector<file_info> &fi):
		file_get_request(psu, dev_type, fi) {}
};

struct get_media_list_response{
	get_media_list_response(): ctime("") {}
	get_media_list_response(const char *json_str) { this->from_json(json_str); }

	header hdr;
	result res;
	// При отсутствии необходимости обновления медиафайлов лист не включается в ответ
	// Также Лист может быть пустым. Это означает, что все текущие медиафайлы можно удалять
	std::vector<list_elem> tmp_media_list{{"", ""}};	// признак отсутствия листа в ответе
	std::vector<list_elem> const_media_list{{"", ""}};
	current_time ctime;
	signature sig;

	void from_json(const char *json_str);
};

////////////////////// Передача информации о системе на сервер ЛЦ
// ПРИМ: В зависимости от типа устройства содержание sys_info_* может меняться

struct sys_info{
	virtual ~sys_info() = default;

	virtual void add_json_part(nlohmann::json &j) const;

	std::string state = "undefined";
	std::string app_version;
	std::string nsi_version;
};

struct sys_info_avi: public sys_info{

	sys_info_avi(): sys_info() {}

	uint32_t vehicle_number = 0; 
	uint64_t sd_free_space = 0;

	void add_json_part(nlohmann::json &j) const;
};

struct info_post_request{
	info_post_request() = default;
	info_post_request(uint32_t psu, const std::string &dev_type, const sys_info *i = nullptr): 
		devinfo(psu, dev_type), info(i) {}

	header hdr;
	dev_info devinfo;
	const sys_info *info = nullptr; 	// указатель на данные определенного устройства
	current_time ctime;
	signature sig;

	std::string to_json() const;
};

struct push_data{
	push_data() = default;

	std::string action;		// Событие требуемое к вызову от терминала («none», если событие не требуется)
	std::string data;		// Флаг вызова (0-как можно скорее, 1-после отработки предыдущих событий, 2-после следующего info_post)
	int mode = -1;			// Данные для события
	int data_mode = -1;		// Флаг для данных (0 – без повторения, 1 – проигрывание duration секунд, >1 – проигрывание datamode раз)
	int duration = -1;		// Длительность проигрывания
};

struct info_post_response{
	info_post_response(): ctime("") {}
	info_post_response(const char *json_str) { this-> from_json(json_str); }

	header hdr;
	result res;
	push_data push;
	current_time ctime;
	signature sig;

	void from_json(const char *json_str);
};



/*
////////////////////// Запрос номера наряда из ЛЦ
typedef struct {
	header_t hdr;
	devinfo_t devinfo;
	char signature[32];
}lc_unblock_req_t;

typedef struct {
	header_t hdr;
	result_t res;
	unblock_data_t ubd;
	char signature[32];
}lc_unblock_resp_t;

char* lc_unblock_req_to_json(lc_unblock_req_t *req);
jerr_t json_to_lc_unblock_resp(const char *json, lc_unblock_resp_t *resp);
*/

} // namespace ls
#endif
