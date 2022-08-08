/*============================================================================== 
Описание: 	Модуль формирования системных событий для отправки в Локальный Центр.

Автор: 		berezhanov.m@gmail.com
Дата:		09.12.2021
Версия: 	1.0
==============================================================================*/

#ifndef _LC_SYS_EV_HPP_
#define _LC_SYS_EV_HPP_

#include <cstdint>
#include <string>

#include "lc_utils.hpp"
#include "logger.hpp"

// Уровни подробности системных событий
#define EV_LVL_BRIEF			0 		// Краткий
#define EV_LVL_MEDIUM			1 		// Средний
#define EV_LVL_VERBOSE			2 		// Подробный

// Коды устройств - источников событий 
#define EV_DEV_SUV				"00"	// Код СУВ (Сервера управления валидаторами)
#define EV_DEV_VALIDATOR		"01"	// Код Валидатора
#define EV_DEV_PASS_CNT			"02"	// Код Счетчика пассажиров
#define EV_DEV_AVI 				"03" 	// Код Автоинформатора

// Внутренне событие
#define EV_PSUTRANS_OVFL		"2A"	// Переполнение счётчика системных событий

namespace lc {

inline std::string event_level_as_str(int level)
{
	switch(level){
		case EV_LVL_BRIEF: return "brief";
		case EV_LVL_MEDIUM: return "medium";
		case EV_LVL_VERBOSE: return "verbose";
	}

	return "unsupported";
}

// Обобщенное представление системного события
struct sys_event
{
	struct meta{
		meta() = default;
		meta(int lvl, const std::string &c, const std::string &d): level(lvl), code(c), devcode(d) {}

		int level = 0;					// Уровень события
		std::string code;				// Код события (hex - 2 байта)
		std::string devcode;			// Код устройства (hex - 2 байта)
	}info;

	sys_event() = default;
	sys_event(const sys_event::meta &m): info(m) {}
	sys_event(int lvl, const std::string &c, const std::string &d): info(lvl, c, d) {}
				
	std::string gps_latitude;			// GPS-координаты события (широта) (для варианта с навигацией)
	std::string gps_longitude;			// GPS-координаты события (долгота) (для варианта с навигацией)
	uint32_t gps_valid = 0;				// Признак валидности GPS-координат
};

// Структура записи системного события
struct sys_event_record
{
	uint32_t psutrans = 0;			// Порядковый номер события
	uint32_t psu = 0;				// ПСУ устройства
	char actcode[2] = {0};			// Код события (hex)
	uint32_t actday = 0;			// День события
	uint32_t actmonth = 0;			// Месяц события
	uint32_t actyear = 0;			// Год события
	uint32_t acthour = 0;			// Час события
	uint32_t actmin = 0;			// Минута события
	uint32_t actsec = 0;			// Секунда события
	char cardid[16] = {0};			// Не используется
	char crc[2] = {0};				// Не используется
	uint32_t emissid = 0;			// Не используется
	char emissidfull[32] = {0};		// Не используется
	uint32_t tabnumber = 0;			// Не используется
	uint32_t gpswide = 0;			// Координата (широта) события
	uint32_t gpslong = 0;			// Координата (долгота) события
	uint32_t transtype = 0;			// Не используется
	char devcode[2] = {0};			// Код устройства (hex)
	char gps_latitude[32] = {0};	// GPS-координаты события (широта) (для варианта с навигацией)
	char gps_longitude[32] = {0};	// GPS-координаты события (долгота) (для варианта с навигацией)
	uint32_t gps_valid = 0;			// Признак валидности GPS-координат
	uint32_t crcrec = 0;			// CRC32 по всем вышеперечисленным полям

	static uint32_t dump_crc(struct tm *tm, uint32_t psu, uint32_t psutrans, const sys_event &sev);

	void calc_crc(){
		this->crcrec = lc::utils::crc32_wiki_inv(0, reinterpret_cast<uint8_t *>(this), (sizeof(*this) - sizeof(this->crcrec)));
	}

}__attribute__((__packed__));

} // namespace

#endif
