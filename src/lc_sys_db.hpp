/*============================================================================== 
Описание: 	Модуль хранения системных событий в БД.

Автор: 		berezhanov.m@gmail.com
Дата:		07.04.2022
Версия: 	1.0
==============================================================================*/

#ifndef _LC_SYS_DB_HPP_
#define _LC_SYS_DB_HPP_

#include <cstdint>
#include <string>
#include <mutex>

extern "C"{
#include <sqlite3.h>
}

#include "lc_sys_ev.hpp"
#include "logger.hpp"

namespace lc {

// Реализация системных событий на sqlite3 базе данных
class Sys_events_storage
{
public:

	// Инициализация БД и конфигурация
	void init(
		const std::string &path, 		// Полный путь к БД
		const std::string &trans_dir, 	// Полный путь к директории для отправки транзакций в ЛЦ
		const std::string &db_type,		// Тип БД согласно протоколу
		const std::string &dev_type,	// Тип устройства согласно протоколу 
		uint32_t psu, 					// Идентификатор устройства (системы)
		Logging *plog = nullptr);		// Указатель на логер

	// Запись очередного системного события в базу
	// ПРИМ: sev_data - Данные события (необязательное поле) Формат БД допускает максимум 40 байт
	// Параметр psutrans отвечает за выбор стратегии нумерования системных событий:
	// 	если параметр не задан (0) - используется встроенная нумерация с использованием 
	//								 внутреннеuj счетчика SysEvents таблицы Counters;
	//	если же параметр задан 	   - используется его значение и встроенный счетчик 
	// 								 таблицы Counters не используется.
	void put_event(const sys_event &sev, const std::string &sev_data = "", uint32_t psutrans = 0);

	// Формирование из текущей БД транзакции для отправки в ЛЦ
	void slice();		

	void set_events_level(int lvl){
		std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
		this->events_level = lvl;
	}

	int get_events_level(){
		std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
		return events_level;
	}

	void set_slice_chunk(uint32_t num){
		std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
		this->slice_chunk = num;
	}

	void set_event_psutrans(uint32_t value);

	uint32_t get_event_psutrans();

	// Обертка для управления открытием и закрытием базы в cтиле RAII
	struct open_close
	{
		open_close(sqlite3 **sq, const std::string &path): fd(sq)
		{
			if(*sq) return;		// Если уже открыта 
			if(sqlite3_open_v2(path.c_str(), sq, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_CREATE, nullptr)){
				throw std::runtime_error(excp_method((std::string)"sqlite3_open_v2() failed: " + sqlite3_errmsg(*sq)));
			}
			opened = true;
		}

		~open_close(){
			if( !fd || !opened ) return;	// Уже закрыта или не была открыта текущим объектом

			sqlite3_close(*fd);
			*fd = nullptr;
			fd = nullptr;
		}

	private:
		sqlite3 **fd = nullptr;
		bool opened = false; 	// Флаг, чтобы закрывать то, что было открыто этим объектом, а не другим
	};

private:
	// Колбек на SQL запрос
	using sq3_cb = int (*)(void*, int, char**, char**);

	mutable std::recursive_mutex access_mtx;
	const int open_mode = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_CREATE;
	sqlite3 *fd = nullptr;				// Дестриптор БД
	uint32_t device_id = 0;				// Идентификатор устройства
	uint32_t system_id = 0;				// Идентификатор системы
	std::string path;					// Абсолютный путь к БД
	std::string dir;					// Директория, в которой находится БД
	std::string dest_dir;				// Директория для сохранения транзакций системных событий
	int events_level = EV_LVL_MEDIUM;	// Уровень разрешенной подробности системных событий
	uint32_t slice_chunk = 10;			// Максимальное кол-во записей в БД перед формированием транзакции

	Logging *lgr = nullptr;

	void send_sql(const std::string &sql, sq3_cb cb, void *cb_param, const std::string &caller = "");

	void update_db_info(const std::string &db_type = "", const std::string &dev_type = "", uint32_t psu = 0);
	uint32_t get_db_version();
	uint32_t get_events_num();
	void clear();

	void open(){
		if(sqlite3_open_v2(this->path.c_str(), &this->fd, this->open_mode, nullptr)){
			throw std::runtime_error(excp_method((std::string)"sqlite3_open_v2() failed: " + sqlite3_errmsg(fd)));
		}
	}

	void close(){
		sqlite3_close(this->fd);
		this->fd = nullptr;
	}

	// Создание записи системного события в базе
	void put_record(const sys_event_record &rec, const std::string &ev_data);
};

}	// namespace

#endif
