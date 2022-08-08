#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cinttypes>
#include <stdexcept>
#include <memory>
#include <fstream>

extern "C"{
#include <libgen.h>		// dirname
#include <uuid/uuid.h>
}

#define LOG_MODULE_NAME		"[ SEV ]"
#include "logger.hpp"

#include "lc_utils.hpp"
#include "lc_protocol.hpp"
#include "lc_sys_db.hpp"

#define to_s(x) 	std::to_string(x)

#ifdef _SHARED_LOG
#define logmsg(flag, str...) log_msg(flag, str) 
#else
#define logmsg(flag, str...)	do{				\
	if(this->lgr) this->lgr->msg(flag, str); 	\
}while(0)
#endif

namespace lc {

void Sys_events_storage::send_sql(const std::string &sql, sq3_cb cb, void *cb_param, const std::string &caller) 
{
	if( !this->fd ) throw std::runtime_error(caller + "No db handle provided");
	if(sql.empty()) throw std::runtime_error(caller + "No SQL provided");

	char *err = nullptr;

	if(sqlite3_exec(fd, sql.c_str(), cb, cb_param, &err) != SQLITE_OK){
		std::string msg = "'" + sql + "' failed: " + err;
		sqlite3_free(err);
		throw std::runtime_error(caller + msg);
	}
}

// Функция формирования структуры Базы
static std::string prepare_db_struct(uint32_t *ver = nullptr)
{
	uint32_t version = 40006;

	std::string sql = "\
CREATE TABLE IF NOT EXISTS kInfo (infParam TEXT UNIQUE, paramMeaning TEXT); \
INSERT OR IGNORE INTO kInfo VALUES('dbType', ''); \
INSERT OR IGNORE INTO kInfo VALUES('devType', ''); \
INSERT OR IGNORE INTO kInfo VALUES('dbStructVersion', '00040006'); \
INSERT OR IGNORE INTO kInfo VALUES('PSU', '0'); \
CREATE TABLE IF NOT EXISTS kRides (idrow INTEGER NOT NULL PRIMARY KEY, id TEXT, crc TEXT, route INTEGER, routec TEXT, vihod INTEGER, smena INTEGER, riderest INTEGER, region INTEGER, emissid INTEGER, emissidfull TEXT, cardtype TEXT, town INTEGER, psu INTEGER, lgota TEXT, tabno INTEGER, inday INTEGER, inmonth INTEGER, inyear INTEGER, inhour INTEGER, inmin INTEGER, insec INTEGER, instop INTEGER, outday INTEGER, outmonth INTEGER, outyear INTEGER, outhour INTEGER, outmin INTEGER, outsec INTEGER, outstop INTEGER, inflag INTEGER, pricerub INTEGER, pricekop INTEGER, allrub INTEGER, allkop INTEGER, cardtrans INTEGER, zoneflag INTEGER, psutrans INTEGER, rideall INTEGER, psusell INTEGER, psulast INTEGER, transtype INTEGER, skmocount1 TEXT, skmocount2 TEXT, skmocount3 TEXT, skmocount4 TEXT, crcrec INTEGER, readflag INTEGER, outdataday INTEGER, outdatamonth INTEGER, outdatayear INTEGER, outdatahour INTEGER, outdatamin INTEGER, outdatasec INTEGER, sent INTEGER, confirmed INTEGER, q_order INTEGER, ext TEXT); \
CREATE TABLE IF NOT EXISTS kSellJournal (id TEXT, crc TEXT, emissid INTEGER, emissidfull TEXT, cardtype TEXT, lgota TEXT, inday INTEGER, inmonth INTEGER, inyear INTEGER, inhour INTEGER, inmin INTEGER, insec INTEGER, action TEXT, actstop INTEGER, instop INTEGER, outstop INTEGER, pricerub INTEGER, pricekop INTEGER, psu INTEGER, tabno INTEGER, route INTEGER, routec TEXT, vihod INTEGER, smena INTEGER, psutrans INTEGER, transtype INTEGER, rideall INTEGER, tariff INTEGER, begday INTEGER, begmonth INTEGER, begyear INTEGER, endday INTEGER, endmonth INTEGER, endyear INTEGER, idsell INTEGER, ctrans INTEGER, paymentrub INTEGER, paymentkop INTEGER, ext TEXT, storno INTEGER, idrow INTEGER NOT NULL PRIMARY KEY, readflag INTEGER, outdataday INTEGER, outdatamonth INTEGER, outdatayear INTEGER, outdatahour INTEGER, outdatamin INTEGER, outdatasec INTEGER, crcrec INTEGER, saleinfo TEXT, sent INTEGER, confirmed INTEGER, q_order INTEGER, ofd_fn TEXT, ofd_fd TEXT, ofd_fp TEXT); \
CREATE TABLE IF NOT EXISTS kSysEvents (idrow INTEGER NOT NULL PRIMARY KEY, psutrans INTEGER, psu INTEGER, actcode TEXT, actday INTEGER, actmonth INTEGER, actyear INTEGER, acthour INTEGER, actmin INTEGER, actsec INTEGER, cardid TEXT, crc TEXT, emissid INTEGER, emissidfull TEXT, tabnumber INTEGER, gpswide INTEGER, gpslong INTEGER, transtype INTEGER, devcode TEXT, gps_latitude TEXT, gps_longitude TEXT, gps_valid INTEGER, crcrec INTEGER, readflag INTEGER, outdataday INTEGER, outdatamonth INTEGER, outdatayear INTEGER, outdatahour INTEGER, outdatamin INTEGER, outdatasec INTEGER, datasys TEXT, sent INTEGER, confirmed INTEGER, q_order INTEGER); \
CREATE TABLE IF NOT EXISTS kView (idrow INTEGER NOT NULL PRIMARY KEY, id TEXT, crc TEXT, region INTEGER, town INTEGER, lgota TEXT, emissid INTEGER, emissidfull TEXT, cardtype TEXT, actcode TEXT, actday INTEGER, actmonth INTEGER, actyear INTEGER, acthour INTEGER, actmin INTEGER, actsec INTEGER, actstop INTEGER, tariffrub1 INTEGER, tariffkop1 INTEGER, tariffrub2 INTEGER, tariffkop2 INTEGER, psu INTEGER, tabno INTEGER, route INTEGER, routec TEXT, vihod INTEGER, smena INTEGER, psulast INTEGER, psusell INTEGER, rideall INTEGER, begday INTEGER, begmonth INTEGER, begyear INTEGER, endday INTEGER, endmonth INTEGER, endyear INTEGER, begday2 INTEGER, begmonth2 INTEGER, begyear2 INTEGER, endday2 INTEGER, endmonth2 INTEGER, endyear2 INTEGER, riderest1 INTEGER, riderest2 INTEGER, skmocount1 TEXT, skmocount2 TEXT, skmocount3 TEXT, skmocount4 TEXT, inday INTEGER, inmonth INTEGER, inyear INTEGER, inhour INTEGER, inmin INTEGER, insec INTEGER, outday INTEGER, outmonth INTEGER, outyear INTEGER, outhour INTEGER, outmin INTEGER, outsec INTEGER, psutrans INTEGER, ext TEXT, crcrec INTEGER, readflag INTEGER, outdataday INTEGER, outdatamonth INTEGER, outdatayear INTEGER, outdatahour INTEGER, outdatamin INTEGER, outdatasec INTEGER, sent INTEGER, confirmed INTEGER, q_order INTEGER);"
;

	if(ver) *ver = version;
	return sql;
}

void Sys_events_storage::update_db_info(const std::string &db_type, const std::string &dev_type, uint32_t dev_id)
{
	std::string sql;

	if( !db_type.empty() ){
		sql = "UPDATE kInfo SET paramMeaning='" + db_type + "' WHERE infParam=\"dbType\";";
		send_sql(sql, nullptr, nullptr, excp_method(""));
	}
	if( !dev_type.empty() ){
		sql = "UPDATE kInfo SET paramMeaning='" + dev_type + "' WHERE infParam=\"devType\";";
		send_sql(sql, nullptr, nullptr, excp_method(""));
	}
	if(dev_id){
		sql = "UPDATE kInfo SET paramMeaning='" + to_s(dev_id) + "' WHERE infParam=\"PSU\";";
		send_sql(sql, nullptr, nullptr, excp_method(""));
	}
}

void Sys_events_storage::init(
	const std::string &path, 
	const std::string &trans_dir, 
	const std::string &db_type,
	const std::string &dev_type,
	uint32_t dev_id, 
	Logging *plog)
{
	std::lock_guard<std::recursive_mutex> lck(this->access_mtx);

	if(this->fd) return;	// Уже проинициализирована

	this->path = path;
	this->dest_dir = trans_dir;
	this->device_id = dev_id;
	// Определение директории БД
	std::unique_ptr<char[]> cpath (new char[path.length() + 1]);	// must use delete[]
	std::strcpy(cpath.get(), this->path.c_str());
	this->dir = dirname(cpath.get());

	if(plog) this->lgr = plog;
	lc::utils::make_dir_if_not_exists(this->dest_dir);

	if(sqlite3_open_v2(this->path.c_str(), &this->fd, this->open_mode, nullptr)){
		throw std::runtime_error(excp_method((std::string)"sqlite3_open_v2() failed: " + sqlite3_errmsg(fd)));
	}

	uint32_t curr_ver = 0;	// Текущая версия структруы базы
	uint32_t target_ver = 0;
	std::string db_create_sql = prepare_db_struct(&target_ver);
	std::string sql;

	// Таблица может еще не существовать
	try{
		curr_ver = this->get_db_version();
	}	
	catch(const std::runtime_error &e){
		// нет такой таблицы => база еще не была создана. создаем
		logmsg(MSG_DEBUG | MSG_TO_FILE, "+ Creating database structure v.%" PRIu32 "\n", target_ver);
		sql = "BEGIN TRANSACTION; " + db_create_sql + " COMMIT;" ;
		send_sql(sql, nullptr, nullptr, excp_method(""));
		goto exit;
	}

	// Если структура базы старая
	if(curr_ver < target_ver){
		logmsg(MSG_DEBUG | MSG_TO_FILE, "-> Current db version is '%" PRIu32 "'. Updating structure to v.%" PRIu32 "\n", 
			curr_ver, target_ver);

		this->slice();

		sql = "BEGIN TRANSACTION; \
DROP TABLE kInfo; \
DROP TABLE kRides; \
DROP TABLE kSellJournal; \
DROP TABLE kSysEvents; \
DROP TABLE kView; \
" + db_create_sql + " \
COMMIT;";

		send_sql(sql, nullptr, nullptr, excp_method(""));
		
	}

exit:
	// Обновить индивидуальные параметры БД
	this->update_db_info(db_type, dev_type, dev_id);

	// Добавляем новую таблицу для хранения счетчика системных событий
	sql = "CREATE TABLE IF NOT EXISTS Counters ( \
type TEXT UNIQUE, \
psutrans INTEGER); \
INSERT OR IGNORE INTO Counters VALUES ('SysEvents', 1);" ;
	send_sql(sql, nullptr, nullptr, excp_method(""));
	
	// Каждая операция с БД оставляет файл закрытым 
	this->close();
}

// void Sys_events_storage::deinit()
// {
// 	std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
// 	if( !this->fd ) return;

// 	sqlite3_close(this->fd);
// 	this->fd = nullptr;
// 	this->path.clear();
// 	this->dir.clear();
// }

void Sys_events_storage::set_event_psutrans(uint32_t value)
{
	std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
 
	open_close oc(&this->fd, this->path);

	std::string sql = "UPDATE Counters SET psutrans=" + to_s(value) + " WHERE type='SysEvents';" ; 
	send_sql(sql, nullptr, nullptr, excp_method(""));
}

uint32_t Sys_events_storage::get_event_psutrans()
{
	uint32_t res = 0;
	std::lock_guard<std::recursive_mutex> lck(this->access_mtx);

	open_close oc(&this->fd, this->path);

	auto callback = [](void *param, int argc, char **argv, char **col_name) -> int { 
		uint32_t *tmp = static_cast<uint32_t*>(param);
		if(argc) sscanf(argv[0], "%" PRIu32 "", tmp);
		else *tmp = 0;

		return 0;
	};

	std::string sql = "SELECT psutrans FROM Counters WHERE type='SysEvents';";
	send_sql(sql, callback, &res, excp_method(""));

	return res;
}

uint32_t Sys_events_storage::get_db_version()
{
	uint32_t res = 0;

	auto callback = [](void *param, int argc, char **argv, char **col_name) -> int { 
		uint32_t *tmp = static_cast<uint32_t*>(param);
		if(argc) sscanf(argv[0], "%" PRIu32 "", tmp);
		else *tmp = 0;

		return 0;
	};

	std::string sql = "SELECT paramMeaning FROM kInfo WHERE infParam='dbStructVersion';";
	send_sql(sql, callback, &res, excp_method(""));

	return res;
}


void Sys_events_storage::clear()
{
	send_sql("DELETE FROM kSysEvents;", nullptr, nullptr, excp_method(""));	
	send_sql("VACUUM;", nullptr, nullptr, excp_method(""));
}

uint32_t Sys_events_storage::get_events_num()
{
	uint32_t res = 0;

	auto callback = [](void *param, int argc, char **argv, char **col_name) -> int { 
		uint32_t *tmp = static_cast<uint32_t*>(param);
		if(argc) sscanf(argv[0], "%" PRIu32 "", tmp);
		else *tmp = 0;

		return 0;
	};

	std::string sql = "SELECT idrow FROM kSysEvents ORDER BY idrow DESC LIMIT 1;";
	send_sql(sql, callback, &res, excp_method(""));

	return res;
}


void Sys_events_storage::slice()
{
	char dt_str[50] = {0};
	char uid_str[40] = {0};

	time_t t = time(nullptr);
	strftime(dt_str, sizeof(dt_str), "%y%m%d%H%M%S", localtime(&t));

	uuid_t uid;
	uuid_generate(uid);
	uuid_unparse(uid, uid_str);
	uid_str[8] = '\0'; // используется 8 первых символов

	std::string name = std::to_string(this->device_id) + "_sys_ev_" + uid_str + "_" + dt_str;
	std::string dest_path = this->dest_dir + "/" + name + LC_DB_TRANS_EXT;

	try{
		// На время копирования текущего состояния блокируем доступ
		std::lock_guard<std::recursive_mutex> lck(this->access_mtx);
		open_close oc(&this->fd, this->path);

		// Нет записей - нет необходимости делать срез
		uint32_t num = this->get_events_num();
		if( !num ) {
			return;
		} 	

		logmsg(MSG_DEBUG, "Slicing database with %" PRIu32 " sys event(s)\n", num);
		// Делаем срез текущего состояния БД и шифруем ее как транзакцию
		lc::utils::file_aes128(this->path, dest_path, this->system_id);
		// Удаляем срезанные системные события
		this->clear();	
	}
	catch(...){
		remove(dest_path.c_str());
		throw;
	}
}

// Параметр psutrans отвечает за выбор стратегии нумерования системных событий:
// 	если параметр не задан (0) - используется встроенная нумерация с использованием 
//								 внутренней таблицы Counters (поле SysEvents)
//	если же параметр задан 	   - используется его значение и встроенный механизм 
// 								 таблицы Counters не используется
void Sys_events_storage::put_event(const sys_event &sev, const std::string &sev_data, uint32_t psutrans)
{
	std::unique_lock<std::recursive_mutex> ulck(this->access_mtx);

	// Проверка необходимости сохранения события
	if(this->events_level < sev.info.level) return;

	sys_event_record rec;

	// Заполняем новую запись события
	rec.psu = this->device_id;
	ulck.unlock();

	memcpy(rec.actcode, sev.info.code.c_str(), 2);

	time_t t = time(nullptr);
	struct tm *curr_tm = localtime(&t);
	if(curr_tm){
		rec.actday = curr_tm->tm_mday;
		rec.actmonth = curr_tm->tm_mon + 1;
		rec.actyear = curr_tm->tm_year + 1900;
		rec.acthour = curr_tm->tm_hour;
		rec.actmin = curr_tm->tm_min;
		rec.actsec = curr_tm->tm_sec;
	}
	sscanf(sev.gps_latitude.c_str(), "%" PRIu32 "", &rec.gpswide);
	sscanf(sev.gps_longitude.c_str(), "%" PRIu32 "", &rec.gpslong);
	memcpy(rec.devcode, sev.info.devcode.c_str(), 2);
	strncpy(rec.gps_latitude, sev.gps_latitude.c_str(), sizeof(rec.gps_latitude) - 1);
	strncpy(rec.gps_longitude, sev.gps_longitude.c_str(), sizeof(rec.gps_longitude) - 1);
	rec.gps_valid = sev.gps_valid;

	ulck.lock();
	open_close oc(&this->fd, this->path);
	// Задаем номер записи исходя из переданного параметра psutrans
	rec.psutrans = psutrans ? psutrans : this->get_event_psutrans();
	rec.calc_crc();
	// rec.crcrec = lc::utils::crc32_wiki_inv(0, reinterpret_cast<uint8_t *>(&rec), (sizeof(rec) - sizeof(rec.crcrec)));
	this->put_record(rec, sev_data);

	// Обновление встроенного счетчика если он использовался в качестве номера записи
	if( !psutrans ){
		++rec.psutrans;
		// Проверка переполнения
		if(rec.psutrans == UINT32_MAX) {
			rec.psutrans = 1;
			memcpy(rec.actcode, EV_PSUTRANS_OVFL, 2);
			memcpy(rec.devcode, sev.info.devcode.c_str(), 2);
			rec.crcrec = lc::utils::crc32_wiki_inv(0, reinterpret_cast<uint8_t *>(&rec), (sizeof(rec) - sizeof(rec.crcrec)));
			this->put_record(rec, "");
		}
		this->set_event_psutrans(rec.psutrans);
	}

	uint32_t records_num = this->get_events_num();
	// Проверяем допустимый размер после очередного добавления
	if(this->slice_chunk && (records_num >= this->slice_chunk)){
		this->slice();	
	} 
}
		
void Sys_events_storage::put_record(const sys_event_record &rec, const std::string &ev_data)
{
	std::array<char, 1024> sql{};

	sprintf(sql.data(), "INSERT INTO kSysEvents (psutrans, psu, actcode, actday, actmonth, \
actyear, acthour, actmin, actsec, cardid, crc, emissid, emissidfull, tabnumber, gpswide, gpslong, \
transtype, devcode, gps_latitude, gps_longitude, gps_valid, crcrec, \
readflag, outdataday, outdatamonth, outdatayear, outdatahour, \
outdatamin, outdatasec, datasys, sent, confirmed, q_order) VALUES \
(%" PRIu32 ", %" PRIu32 ", \"%.2s\", %" PRIu32 ", %" PRIu32 ", \
%" PRIu32 ", %" PRIu32 ", %" PRIu32 ", %" PRIu32 ", \"%.16s\", \"%.2s\", %" PRIu32 ", \"%.32s\", %" PRIu32 ", %" PRIu32 ", %" PRIu32 ", \
%" PRIu32 ", \"%.2s\", \"%.32s\",\"%.32s\", %" PRIu32 ", %" PRIu32 ", \
0, 0, 0, 0, 0, 0, 0, \"%.40s\", 0, 0, 0);", rec.psutrans, rec.psu, rec.actcode, rec.actday, rec.actmonth, 
rec.actyear, rec.acthour, rec.actmin, rec.actsec, rec.cardid, rec.crc, rec.emissid, rec.emissidfull, rec.tabnumber, rec.gpswide, rec.gpslong, 
rec.transtype, rec.devcode, rec.gps_latitude, rec.gps_longitude, rec.gps_valid, rec.crcrec, ev_data.c_str());

	send_sql(sql.data(), nullptr, nullptr, excp_method(""));
}

} // namespace


#ifdef _LC_SYS_EV_TEST

int main(int argc, char* argv[])
{
	lc::Sys_events_storage ev_db;
	Logging lgr(MSG_TRACE, "[ SYS_EV ]");

	try{
		std::string cwd = lc::utils::get_cwd();
		ev_db.init(cwd + "/suv_logs.db", cwd + "/lcc_put_data", "suv_logs", "bk_ttm", 3487366287, &lgr);

		ev_db.put_event(lc::sys_event(  lc::sys_event::meta(1, "01", "40")) );
		ev_db.put_event(lc::sys_event(  lc::sys_event::meta(1, "0A", "00")) );
		ev_db.put_event(lc::sys_event(  lc::sys_event::meta(1, "0B", "01")) );
		ev_db.put_event(lc::sys_event(  lc::sys_event::meta(1, "0C", "02")) );
		ev_db.put_event(lc::sys_event(  lc::sys_event::meta(1, "0D", "03")) );
	}
	
	catch(const std::exception &e){
		logging_excp(lgr, "%s\n", e.what());
	}

	return 0;
}

#endif
