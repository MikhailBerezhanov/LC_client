#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cinttypes>
#include <stdexcept>

#include "lc_utils.hpp"
#include "lc_sys_ev.hpp"

namespace lc {

uint32_t sys_event_record::dump_crc(struct tm *tm, uint32_t psu, uint32_t psutrans, const sys_event &sev)
{
	sys_event_record rec;

	// Заполняем дамп записи события
	rec.psutrans = psutrans;
	rec.psu = psu;

	memcpy(rec.actcode, sev.info.code.c_str(), 2);

	if(tm){
		rec.actday = tm->tm_mday;
		rec.actmonth = tm->tm_mon + 1;
		rec.actyear = tm->tm_year + 1900;
		rec.acthour = tm->tm_hour;
		rec.actmin = tm->tm_min;
		rec.actsec = tm->tm_sec;
	}
	sscanf(sev.gps_latitude.c_str(), "%" PRIu32 "", &rec.gpswide);
	sscanf(sev.gps_longitude.c_str(), "%" PRIu32 "", &rec.gpslong);
	memcpy(rec.devcode, sev.info.devcode.c_str(), 2);
	strncpy(rec.gps_latitude, sev.gps_latitude.c_str(), sizeof(rec.gps_latitude) - 1);
	strncpy(rec.gps_longitude, sev.gps_longitude.c_str(), sizeof(rec.gps_longitude) - 1);
	rec.gps_valid = sev.gps_valid;

	return lc::utils::crc32_wiki_inv(0, reinterpret_cast<uint8_t *>(&rec), (sizeof(rec) - sizeof(rec.crcrec)));
}

} // namespace

