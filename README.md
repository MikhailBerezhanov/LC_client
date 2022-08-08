# C++ Библиотека обмена данным с сервером локального центра
### Реализация клиентской части для Linux-устройств
Протокол реализован поверх HTTP и представляет собой REST API.
Используемые методы:

* `/data/device/file_get` - получение из ЛЦ файлов НСИ, стоп-листов, обновлений ПО.
* `/data/device/file_post` - передача в ЛЦ файлов первичных данных (транзакций) в формате sqlite __(deprecated)__
* `/data/device/data_post` - передача в ЛЦ первичных данных (транзакций) в формате protobuf.
* `/data/device/trip_info_get` - запрос данных разблокировки из ЛЦ.
* `/data/device/info_post` - передача в ЛЦ информации об устройстве с возможностью получения PUSH-сообщения (_in the pipeline_)

Данные передаются в форматах JSON и Protobuf.

## Зависимости
Основные модули библиотеки имеют зависимости от `pthread`, `libcrypto`, `libuuid`, `libcurl` и `libprotobuf`  
Для компиляции прото-файлов потребуется компилятор `protoc` версии не ниже 3.0 (как и библиотека libprotobuf).  
Опционально (для хранения и\или передачи транзакций в формате .db) - `libsqlite3`. 

Кроме этого библиотека использует внешний модуль логирования `logger`:

```sh
# Инициализация модуля логирования
git submodule init
git submodule update
```

## Сборка
Модуль поставляется в качестве исходного кода поэтому предполагается, что собираться будет вместе с разрабатываемым приложением. Пример правил для сборки можно посмотреть в Makefile.  

Процесс сборки разделен на две части:

1. компиляция прото-файлов
2. компиляция и сборка приложения

Используемые прото-файлы расположены в директории `./proto/`. Скомпилированные из них .cpp файлы попадут в директория `./src/proto/`.

```sh
# 1. Компиляция прото-файлов. По умолчанию будет использован системный protoc - если нужно указать путь указываем PROTOC=..
make proto-src PROTOC=/path/to/protoc
# 2. Сборка приложения - в данном случае демонстрационной тестовой утилиты-клиента lcc.out
make
```

При вызове `make` будет собираться тестовая демонстрационная утилита `output/lcc.out`. 

Модуль поддерживает кросс-компиляцию и испольует переменную окружения CXX для вызова c++ компилятора. По умолчанию испольуется системный компилятор (хост-машины), как правило g++. 

## Использование
Библиотека разделена на функциональные модули:

* `./src/lc_client.hpp` - непосредственно клиент, осуществляющий обмен данным (скачивание, отправку)
* `./src/lc_trans.hpp` - модуль формирования транзаций в формате protobuf
* `./src/lc_sys_ev.hpp` - определения для формирования системных событий
* `./src/lc_sys_db.hpp` - модуль формирования системных событий в формате sqlite __(deprecated)__
* `./src/logger/cpp_src` - модуль логирования

Пример использования клиента:
```C
#include <fstream>
// Подключение модуля клиента
#include "lc_client.hpp"

Logging mlog(MSG_DEBUG, "[ MAIN ]");

// Файлы с сервера скачиваются в закодированном по BASE64 виде. Приложению может не требоваться
// их раскодировать, поэтому для каждого скачиваемого файла поддерживается два колбека:
// * enc_save() - сохранение в закодированном виде 
// * dec_save() - сохранение с дальнейшим раскодированием
// Приложение должно их определить при необходимости. Ниже приведен пример использования:

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
	LC_client::directories dirs;		// Будем использовать директории по умолчанию
	sets.device_id = 3487366287;		// Идентификатор устройства - Тестовый ID
	sets.system_id = sets.device_id;	// Идентификатор системы, в которой находится утройства (может совпадать) 

	// Будет использован адрес тестового сервера ЛЦ. Адрес настраивается аналогично через sets.lc_server_url

	// Назначанем колбеки для обработки принятых файлов
	// Файлы, для которых колбеки не назначены скачиваться не будут
	// Кроме этого необходимо выставить текущую версию .curr_ver файла на устройстве, чтобы
	// сервер мог понять нужно ли отсылать обновление. По умолчанию версии файлов "undefined"
	sets.get["device_tgz"].dec_save = save_nsi_bin;
	sets.get["device_tgz_stoplist"].enc_save = save_stoplist_b64;
	sets.get["device_tgz_stoplist"].curr_ver = "1";

	// Добавляем новый (несуществующий на сервере) файл для скачивания
	// ПРИМ: при расширении протокола достаточно будет назначить колбек для
	// нового типа файла при помощи  sets.get[]
	sets.get["new_stoplist"].enc_save = save_stoplist_b64;

	// Создаем объект клиента с заданным настройками
	// ПРИМ: lcc хранит указатели на dirs и sets поэтому они должны быть валидными
	// на протяжение всех операций с lcc. Таким образом, до вызова очередных методов lcc 
	// настройки могут быть изменены из-вне - например, прочитаны из конфигурационного файла
	// или динамически изменены разрешения на запросы новых файлов.
	LC_client lcc(&dirs, &sets);

	try{
		lcc.init();				// Инициализация клиентской части
		lcc.show_start();		// Информационное сообщение о запуске клиента

		lcc.rotate_sent_data();	// Проверка объема бэкаппа отправленных данных. Очистка при необходимости
		lcc.get_files();		// Запрос файлов, для которых выставлены колбеки, с сервера 
		lcc.put_files();		// Отправки накопленных файлов транзакций (sqlite)
		lcc.put_data(); 		// Отправки накопленных транзакций (protobuf)
	}
	catch(LC_no_connection &e){
		// фиксируем что связь отсутствует. сообщение об этом появится в show_results()
	}
	catch(const std::exception &e){
		logging_excp(mlog, "%s\n", e.what());
	}
	
	// Возникшие ошибки в процессе работы клиента фиксируются и могут быть выведны методом show_results()
	lcc.show_results();			// Вывод результатов прошедшей сессии связи
	lcc.deinit(); 				// При завершении работы - деинициализация клиента 
	return 0;
}
```

По умолчанию клиент пишет лог в файл __lcc.log__ и в __stdout__, но поведение логгера может быть настроено по-другому используя `LC_client::settings::lsets`.

Пример использования модуля сохранения и формирования транзакций:

```C
#include "lc_trans.hpp"		// Модуль формирования транзакций
#include "lc_sys_ev.hpp" 	// Вспомогательные определения для формирования системных событий

/* Пример приема транзакции из-вне и сохранения на усйтрове для дальнейшей отправки клиентом lc_client на сервер */
void save_tranasction()
{
	// Принять пакет прото-транзакций в бинарном виде	
	std::string transaction_bytes = get_transaction_from_anywhere(); 
	// Сохраняем полученные транзакцией и генерируем ответ с результатом
	std::string serialized_response = lc::ProtoTransactions::save(transaction_bytes);
	// Отправить результаты обработки 
	response_with_bytes_stream(serialized_response);
}

/* Пример формирования системного события */
// Создаем хеш-таблицу с данными о событиях (уровень, HEX-код, код устройства)
static const std::unordered_map<std::string, lc::sys_event::meta> sys_ev_map = {
	{"POWER_ON", {EV_LVL_BRIEF, "0B", EV_DEV_SUV} },	// Включение системы
	{"POWER_OFF", {EV_LVL_BRIEF, "0C", EV_DEV_SUV} },	// Выключение системы
};

// ev_name - имя события
// ev_data - дополнительные данные события
void create_sys_event(const std::string &ev_name, const std::string &ev_data = "")
{
	if(sys_ev_map.find(ev_name) == sys_ev_map.end()){
		// Неверно указано имя события
		return;
	}

	// Получаем мета-данные о генерируемом событии 
	lc::sys_event::meta event_info = sys_ev_map.at(ev_name);

	// Проверяем уровень события (необходимость формирования) 
	if(lc::ProtoTransactions::sys_events.get_level() < event_info.level){
		return;
	}

	lc::sys_event sev(event_info);

	// Заполняем координаты события			
	sev.gps_latitude = 1;			
	sev.gps_longitude = 2;			
	sev.gps_valid = 1;

	// Получаем счетчик системных событий (реализация зависит от приложения)
	uint32_t psutrans = get_psutrans();

	// Сохраняем системное событие как прото-транзакцию
	lc::ProtoTransactions::sys_events.create(psutrans, sev, ev_data);

	// Обновляем счетчик системных событий
	++psutrans;
	update_psutrans(psutrans);
}

int main(int argc, char* argv[])
{
	lc::ProtoTransactions::init(dirs.transactions_dir, sys_id.get(), sys_id.get(), "suv");
	lc::ProtoTransactions::check_and_clean();
	lc::ProtoTransactions::sys_events.init(EV_LVL_BRIEF);

	create_sys_event("POWER_ON");

	save_tranasction();

	lc::ProtoTransactions::deinit();

	return 0;
}

```







