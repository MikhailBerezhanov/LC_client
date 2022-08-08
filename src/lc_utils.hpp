/*============================================================================== 
Описание:   Модуль вспомогательных утилит для работы клиента.

Автор:    	berezhanov.m@gmail.com
Дата:   	04.11.2021
Версия:   	1.0
==============================================================================*/

#ifndef _LC_UTILS_HPP_ 
#define _LC_UTILS_HPP_

#include <cstdint>
#include <memory>
#include <vector>
#include <list>
#include <unordered_set>

extern "C"{
#include <sys/stat.h>
}

namespace lc{
namespace utils{

// ГБайты -> Байты
constexpr uint64_t GB_to_B(uint64_t x) { return ((x) * 1073741824); };
// МБайты -> Байты
constexpr uint64_t MB_to_B(uint64_t x) { return ((x) * 1048576); };
// КБайты -> Байты
constexpr uint64_t KB_to_B(uint64_t x) { return ((x) * 1024); };


/**
  * @описание   Расчет CRC8 по массиву данных
  * @параметры
  *     Входные:
  *         block - указатель на массив данных
  *         size  - длина массива данных
  * @возвращает Контрольную сумму
 */
uint8_t crc8_tab (const uint8_t *block, size_t size);

/**
  * @описание   Расчет CRC32 с инвертирование в конце по массиву данных
  * @параметры
  *     Входные:
  *         initial - стартовое значение
  *         block - указатель на массив данных
  *         size  - длина массива данных
  * @возвращает Контрольную сумму
 */
uint32_t crc32_wiki_inv (uint32_t initial, const uint8_t *block, uint64_t size);

/**
  * @описание   Расчет CRC32 по файлу
  * @параметры
  *     Входные:
  *         path - полный путь к файлу
  * @возвращает Контрольную сумму
 */
uint32_t file_crc32(const std::string &path);

/**
  * @описание   Проверка CRC32 по данным на соответсвие с предполагаемым значением
  * @примечание Высбрасывает исключение в случае несоответствия
  * @параметры
  *     Входные:
  *         data - указатель на массив данных
  *         size  - длина массива данных
  *         crc - предполагаемое значение
 */
void check_crc32(const void *data, uint64_t size, uint32_t crc);

/**
  * @описание   Кодирование файла по AES128
  * @параметры
  *     Входные:
  *         src - указатель на данные
  *         src_len - размер данных в байтах
  *         cipher_key - ключ шифрования
  *     Выходные:
  *         dest - поток байт с закодированным содержимым
 */
void aes128_encrypt(const void *src, size_t src_len, uint32_t cipher_key, std::string &dest);

/**
  * @описание   Кодирование файла по AES128
  * @параметры
  *     Входные:
  *         src - полный путь к файлу
  *         dest - путь к файлу с закодированным содержимым
  *         cipher_key - ключ шифрования
 */
void file_aes128(const std::string &src, const std::string &dest, uint32_t cipher_key);

/**
  * @описание   Кодирование \ Декодирование в формает BASE64
  * @параметры
  *     Входные:
  *         src - указатель на массив данных
  *         len - длина массива данных
  *     Выходные:
  *         out_len - размер получившегося содержимого
  * @возвращает закодированное \ раскодированное содержимое
 */
std::unique_ptr<uint8_t[]> base64_decode (const uint8_t *src, size_t len, size_t *out_len);
std::unique_ptr<uint8_t[]> base64_encode (const uint8_t *src, size_t len, size_t *out_len);

/**
  * @описание   Вычисление хэша по данным
  * @параметры
  *     Входные:
  *         data - указатель на массив данных
  *         len - размер массива данных
  * @возвращает Строку с хэшем в HEX формате
 */
std::string SHA1_hash(const void *data, unsigned long len);
std::string SHA256_hash(const void *data, unsigned long len);

/**
  * @описание   Получение текущего локального времени в заданном формате (по умолчанию 19.03.2021 20:30:31)
  * @параметры
  *     Входные:
  *         fmt - формат представления времени
  *         with_ms - формат с милисекундами 
  *         sec - если не задано, для формирования используется текущее время, иначе заданное
  * @возвращает Строку с временем в заданном формате
 */
std::string get_local_datetime_fmt(const char *fmt = "%d.%m.%Y %T", bool with_ms = false, const time_t *sec = nullptr);

/**
  * @описание   Выполнить команду в оболочке и считать вывод через пайп в строку.
  * @параметры
  *     Входные:
  *         cmd - строка, содержащая команду оболочки среды
  * @возвращает Строку с результатом выполнения команды
 */
std::string exec_piped(const std::string &cmd);

/**
  * @описание   Выполнить команду в оболочке.
  * @параметры
  *     Входные:
  *         cmd - строка, содержащая команду оболочки среды
  *         no_throw - флаг разрешения генерации исключения (false - разрешено)
  * @возвращает true при успехе - иначе false
 */
bool exec(const std::string &cmd, bool no_throw = false);

/**
  * @описание   Получение текущего абсолютного пути рабочей директории 
  * @прим      (где расположен исполняемый файл)
  * @параметры
  *     Выходные:
  *         s - строка содержащая полный путь, не включая имени исполняемого файла
 */
std::string get_cwd(void);

/**
  * @описание   Изменение прав доступа к файлу 
  * @параметры
  *     Входные:
  *         path - строка содержащая полный к файлу
  *         mode - новые флаги доступа
 */
void change_mod(const std::string& path, mode_t mode);

/**
  * @описание   Создание новой директории если таковой еще не существует
  * @параметры
  *     Входные:
  *         path - строка содержащая полный путь создаваемой директории
  *         mode - флаги прав доступа к новой директории
 */
void make_dir_if_not_exists(const std::string &path, mode_t mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

/**
  * @описание   Получение имени файла из полного пути
  * @параметры
  *     Входные:
  *         path - строка содержащая полный путь к файлу
  * @возвращает имя файла
 */
std::string short_name(const std::string &path);

/**
  * @описание   Получение расширения файла из полного пути
  * @параметры
  *     Входные:
  *         path - строка содержащая полный путь к файлу
  * @возвращает расширение файла ".ext"
 */
std::string file_extension(const std::string &path);

/**
  * @описание   Определение размера директории и поддиректорий.
  * @параметры
  *     Входные:
  *         dir_name - имя директории
  *			nesting - разрешение обхода поддиректорий
  *     Выходные:
  *         dir_size - размер директории в байтах
  * @возвращает true в случае успеха, иначе false.
 */
uint64_t get_dir_size(const std::string &dir_name, bool nesting = true);

/**
  * @описание   Получение кол-ва файлов (или файлов и поддиректорий) в директории
  * @параметры
  *     Входные:
  *         dir_name - строка с именем директории
  *         ext      - расширение файлов
  *         nesting  - разрешение рекурсивного обхода поддиректорий
  * @возвращает Количество файлов в директории
 */
uint32_t get_files_num_in_dir(const std::string &dir_name, const std::string &ext = "", bool nesting = false);
uint32_t get_entries_num_in_dir(const std::string &dir_name);

/**
  * @описание   Удаляет из директории заданное количество верхних файлов.
  * @параметры
  *     Входные:
  *         dir_name - имя директории (С-строка)
  *         files_num - количество удаляемых файлов
  *         async - разрешение фонового режима выполнения
 */
void remove_head_files_from_dir(const std::string &dir_name, uint32_t files_num, bool async = false);

/**
  * @описание   Получение имен файлов в директории
  * @параметры
  *     Входные:
  *         dir_name - строка с именем директории
  *         file_ext - расширение файлов для поиска ("" для любого расширения)
  *         max_file_num - максимальное кол-во найденных файлов
  *         max_total_size - максимальный суммарный размер найденных файлов
  * @возвращает Вектор строк с именами файлов
 */
std::vector<std::string> get_file_names_in_dir(
	const std::string &dir_name, 
	const char *file_ext = nullptr,
	uint32_t max_file_num = 0, 
	uint64_t max_total_size = 0,
	uint32_t skip_files_num = 0);

std::unordered_set<std::string> get_file_names_in_dir(
  const std::string &dir_name, 
  const std::string &ext = "",
  uint64_t max_size = 0,
  uint64_t *total_size = nullptr,
  const std::unordered_set<std::string> *exclude_names = nullptr,
  uint32_t max_num = 0);

// std::vector<std::string> get_file_names_in_dir_v2(
// 	const std::string &dir_name,
// 	const char *file_ext = nullptr,
// 	uint32_t max_file_num = 0, 
// 	uint64_t max_total_size = 0,
// 	uint32_t skip_files_num = 0);

/**
  * @описание   Получение имен поддиректорий директории
  * @параметры
  *     Входные:
  *         dir_name - строка с именем директории
  * @возвращает Массив с именами поддиректорий
 */
std::vector<std::string> get_subdirs_names_in_dir(const std::string &dir_name);

/**
  * @описание   Получение размера файла
  * @параметры
  *     Входные:
  *         fname - строка с именем файла
  * @возвращает Размер файла в байтах
 */
uint64_t get_file_size(const std::string &fname);

/**
  * @описание   Чтение бинарного файла
  * @параметры
  *     Входные:
  *         fname - строка с именем файла
  *     Выходные
  *         buf_len - размер прочитанного массива байт
  * @возвращает Умный указатель на прочитанный массив байт
 */
std::unique_ptr<uint8_t[]> read_bin_file(const std::string &fname, uint64_t *buf_len);

/**
  * @описание   Запись в юинарный файл потока байт
  * @параметры
  *     Входные:
  *         fname - строка с именем файла
  *         buf - указатель на массив для записи
  *         buf_len - размер массива для записи
 */
void write_bin_file(const std::string& fname, const uint8_t *buf, size_t buf_len);

/**
  * @описание   Запись в текстовый файл потока символов
  * @параметры
  *     Входные:
  *         fname - строка с именем файла
  *         buf - указатель на массив символов для записи
  *         buf_len - размер массива символов для записи
 */
void write_text_file(const std::string &fname, const char *buf, size_t buf_len);

/**
  * @описание   Распаковка tar архива формата передачи БД ЛЦ
  * @параметры
  *     Входные:
  *         tar_name - строка с именем файла
  *         dest_dir - указатель на массив для записи
  *         no_info_error - размер массива для записи
  * @возвращает Строку с именем содержимого
 */
std::string unpack_tar(const std::string &tar_name, const std::string &dest_dir, bool no_info_error = true);

} // namespace
}

#endif
