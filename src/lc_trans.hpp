/*============================================================================== 
Описание:   Модуль работы с ЛЦ транзакциями в формате protobuf

Автор:    	berezhanov.m@gmail.com
Дата:   	28.02.2022
Версия:   	1.0
==============================================================================*/

#ifndef _LC_TRANS_HPP_ 
#define _LC_TRANS_HPP_

#include <string>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <list>

#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

#include "lc.pb.h"
#include "lc_sys_ev.hpp"
#include "logger.hpp"

namespace lc{

// Расширение файлов прото-сообщений 
#define LC_PROTO_TRANS_EXT 		".pb"


inline std::string proto_msg_to_json(const google::protobuf::Message &msg)
{
	std::string res;
	google::protobuf::util::MessageToJsonString(msg, &res);
	return res;
}

// Транзакции в формате google::protobuf
class ProtoTransactions
{
	// Подкласс системных событий
	class SysEvents;

public:

	static void init(const std::string &base_dir, uint32_t dev_id = 0, uint32_t sys_id = 0, const std::string &dev_type = "");
	static void deinit();
	static bool ready() { return dev_id_ && sys_id_ && !dev_type_.empty(); }

	// Получение директории для типа транзакции
	static const std::string& dir(pb::DataType type) { return dirs.at(static_cast<int>(type)); }

	// Преобразование типов транзакций в имена директорий
	static std::string to_string(pb::DataType type)
	{
		switch(type){
			case pb::SELL_LOG: return "sells";
			case pb::RIDES_LOG: return "rides";
			case pb::VIEW_LOG: return "views";
			case pb::SYS_LOG: return "sys";
			default: return "unknown_type";
		}
	}

	// Проверка и очистка пустых директорий по датам
	static void check_and_clean();

	static pb::Message create_message(
		const std::string &name, 
		pb::DataType data_type,
		const std::string &serialized_data,
		pb::EncryptionType enc_type,
		pb::SignatureType sig_type);

	// Сохранение сообщения на диск
	static std::string save(const pb::Message &msg);

	// Парсинг и сохранение очередной транзакции из потока байт представляюшего пакет pb::Package
	static std::string save(const std::string &bytes_stream);

	// Получение текущего кол-ва сохраненных транзакций 
	static uint32_t count(pb::DataType type = pb::RAW);

	// Возвращает имена файлов из одной поддиректории для заданного типа транзакции.
	// Поддиректории хранятся по датам - на каждый новый день создается отдельная директория
	// По умолчанию набор имен файлов возвращается из самой древней найденной поддиректории
	// Передав набор prev_subdirs можно указать какие поддиректории стоит проигнорировать
	static std::pair<std::string, std::unordered_set<std::string>> get_file_names(
		pb::DataType type,
		uint64_t max_size = 0,
		uint64_t *total_size = nullptr,
		const std::unordered_set<std::string> *prev_subdirs = nullptr,
		const std::unordered_set<std::string> *prev_names = nullptr);

	// Поддержка системных событий в формате прото
	static SysEvents sys_events;

	// Добавляем внутренний логгер если не используется внешний
#ifndef _SHARED_LOG
	static Logging logger;
#endif

private:
	// Соответствие типов транзакций и директорий для их хранения 
	static std::unordered_map<int, std::string> dirs;

	static uint32_t dev_id_;			// Идентификатор устройства
	static uint32_t sys_id_;			// Идентификатор системы
	static std::string dev_type_;		// Тип устройства - "usk04|usk04xx|vm18|suv"

	// Реализация системных событий на protobuf сообщениях
	class SysEvents
	{
	public:
		SysEvents(int level = EV_LVL_MEDIUM): level_(level) {}

		void init(int level = EV_LVL_MEDIUM) { this->level_ = level; }

		// Получение текущего уровя подробности событий
		int get_level() const { return this->level_; }

		// Создание прото-файла системного события
		void create(uint32_t psutrans, const lc::sys_event &sev, const std::string &sev_data = "") const;

	private:
		int level_ = EV_LVL_MEDIUM;		// Уровень разрешенной подробности системных событий
	};
};

//
// class InfoPush
// {
// public:

// 	// 
// 	pb::Message create_info_message(pb::DataType type);

// private:

	
// };


} // namespace

#endif
