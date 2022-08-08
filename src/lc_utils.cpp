
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <sstream>

extern "C"{
#include <sys/mman.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
}

#include "logger.hpp"
#include "lc_utils.hpp"

namespace lc{
namespace utils{

uint32_t crc32_wiki_inv(uint32_t initial, const uint8_t *block, uint64_t size) 
{
	const uint32_t table[] = {
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
		0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
		0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
		0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
		0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
		0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
		0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
		0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
		0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
		0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
		0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
		0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
		0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
		0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
		0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
		0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
		0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
		0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
		0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
		0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
		0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
		0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
		0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
		0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
		0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
		0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
		0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
		0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
		0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
		0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
		0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
		0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
		0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
		0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
		0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
		0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
		0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
		0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
		0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
		0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
		0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
		0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
		0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
		0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
		0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
		0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
		0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
		0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
		0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
		0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
		0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
		0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
		0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
		0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
		0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
		0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
		0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
		0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
		0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
		0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
		0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
	};

	uint32_t crc = initial;

	while (size--) {
		crc = (crc >> 8) ^ table[(crc ^ *block++) & 0xFF];
	}

	return ~crc;
}

uint8_t crc8_tab(const uint8_t *block, size_t size) 
{
	const uint8_t table[] = {
		0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
		157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
		35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
		190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
		70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
		219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
		101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
		248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
		140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
		17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
		175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
		50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
		202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
		87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
		233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
		116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
	};

	uint8_t crc = 0;

	while (size--) {
		crc = table[crc ^ *block++];
	}

	return crc;
}

uint32_t file_crc32(const std::string &path) 
{
	uint64_t size = get_file_size(path);
	if( !size ) throw std::invalid_argument(excp_func("File '" + path + "' size is 0"));

	int fd = open(path.c_str(), O_RDONLY);
	if(fd < 0) {
		throw std::runtime_error("File '" + path + "' open failed");
	}

	void *addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(addr == MAP_FAILED) {
		close (fd);
		throw std::runtime_error(excp_func("File '" + path + "' mmap failed"));
	}

	uint32_t crc = crc32_wiki_inv(0xFFFFFFFF, reinterpret_cast<uint8_t *>(addr), size);

	munmap(addr, size);
	close(fd);

	return crc;
}

void check_crc32(const void *data, uint64_t size, uint32_t crc)
{
	uint32_t calc_crc = crc32_wiki_inv(0xFFFFFFFF, reinterpret_cast<const uint8_t*>(data), size);

	if(calc_crc != crc){
		throw std::runtime_error(excp_func("Invalid CRC. calc_crc: " + std::to_string(calc_crc) + ", crc: " + std::to_string(crc)));
	} 
}

void aes128_encrypt(const void *src, size_t src_len, uint32_t cipher_key, std::string &dest)
{
	uint8_t key[16] = { 0 };
	uint8_t iv[16] = { 0 };
	memcpy(key + 12, &cipher_key, 4);

	std::unique_ptr<EVP_CIPHER_CTX, decltype(EVP_CIPHER_CTX_free)*> ctx ( EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free );

	EVP_CIPHER_CTX_init(ctx.get());
	EVP_EncryptInit(ctx.get(), EVP_aes_128_cbc(), key, iv);

	int outlen = 0;
	const size_t chunk_size = 1024;
	std::array<uint8_t, chunk_size> outbuf{};
	size_t encrypted_len = 0;

	while(encrypted_len < src_len) {

		int inlen = std::min(src_len - encrypted_len, chunk_size);
		const uint8_t *inptr = static_cast<const uint8_t*>(src);

		if( !EVP_EncryptUpdate(ctx.get(), outbuf.data(), &outlen, &inptr[encrypted_len], inlen) ){
			throw std::runtime_error(excp_func(std::string("EVP_EncryptUpdate() failed (inlen: ") + std::to_string(inlen) + ")"));
		}

		dest += std::string(outbuf.begin(), outbuf.begin() + outlen);
		encrypted_len += inlen;
	}

	EVP_EncryptFinal(ctx.get(), outbuf.data(), &outlen);

	dest += std::string(outbuf.begin(), outbuf.begin() + outlen);

	EVP_CIPHER_CTX_cleanup(ctx.get());
}

void file_aes128(const std::string &src, const std::string &dest, uint32_t cipher_key)
{
	uint64_t size = get_file_size(src);
	if( !size ){
		throw std::runtime_error(excp_func("File '" + src + "' is empty"));
	} 

	std::ifstream in_file(src, std::ifstream::binary);
	if( !in_file.is_open() ){
		throw std::runtime_error(excp_func("File '" + src + "' open for reading failed"));
	} 

	std::ofstream out_file(dest);
	if( !out_file.is_open() ){
		throw std::runtime_error(excp_func("File '" + dest + "' open for writing failed"));
	} 
	change_mod(dest, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);


	uint8_t key[16] = { 0x29, 0x9A, 0xF1, 0x2F, 0x4A, 0x43, 0xA5, 0x9B, 0xD5, 0xFB, 0x7A, 0x1E };
	uint8_t iv[16] = { 0 };

	uint8_t inbuf[1024];
	uint8_t outbuf[1024];

	memcpy(key + 12, &cipher_key, 4);

	std::unique_ptr<EVP_CIPHER_CTX, decltype(EVP_CIPHER_CTX_free)*> ctx ( EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free );

	EVP_CIPHER_CTX_init(ctx.get());
	EVP_EncryptInit(ctx.get(), EVP_aes_128_cbc(), key, iv);

	int outlen = 0;

	for(uint64_t i = 0; i < size; ) {

		if( !in_file.read(reinterpret_cast<char*>(inbuf), sizeof inbuf) ){
			throw std::runtime_error(excp_func("File '" + src + "' read failed"));
		} 
		int inlen = in_file.gcount();

		EVP_EncryptUpdate(ctx.get(), outbuf, &outlen, inbuf, inlen);
		if(inlen == outlen) {
			
			if( !out_file.write(reinterpret_cast<char*>(outbuf), outlen) ){
				throw std::runtime_error(excp_func("File '" + dest + "' write failed"));
			} 

		}

		i += inlen;
	}

	EVP_EncryptFinal(ctx.get(), outbuf, &outlen);
	if( !out_file.write(reinterpret_cast<char*>(outbuf), outlen) ){
		throw std::runtime_error(excp_func("File '" + dest + "' final write failed"));
	} 

	EVP_CIPHER_CTX_cleanup(ctx.get());

	in_file.close();
	out_file.flush();
	out_file.close();
}



static const uint8_t base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::unique_ptr<uint8_t[]> base64_encode(const uint8_t *src, size_t len, size_t *out_len) 
{
	uint8_t *pos;
	const uint8_t *end, *in;
	size_t olen;

	if(len >= SIZE_MAX / 4) throw std::overflow_error(excp_func("len overflow"));

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen++; /* nul termination */
	if(olen < len) throw std::overflow_error(std::string(excp_func("integer overflow")));

	std::unique_ptr<uint8_t[]> out ( new uint8_t[olen] );

	if( !out ) return nullptr;

	end = src + len;
	in = src;
	pos = out.get();
	while(end - in >= 3) {
		*pos++ = base64_table[(in[0] >> 2) & 0x3f];
		*pos++ = base64_table[(((in[0] & 0x03) << 4) | (in[1] >> 4)) & 0x3f];
		*pos++ = base64_table[(((in[1] & 0x0f) << 2) | (in[2] >> 6)) & 0x3f];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if(end - in) {
		*pos++ = base64_table[(in[0] >> 2) & 0x3f];
		if(end - in == 1) {
			*pos++ = base64_table[((in[0] & 0x03) << 4) & 0x3f];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[(((in[0] & 0x03) << 4) | (in[1] >> 4)) & 0x3f];
			*pos++ = base64_table[((in[1] & 0x0f) << 2) & 0x3f];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	if(out_len) *out_len = pos - out.get();

	return out;
}

std::unique_ptr<uint8_t[]> base64_decode(const uint8_t *src, size_t len, size_t *out_len) 
{
	uint8_t dbase64_table[256], *pos, block[4], tmp;
	size_t i, count, olen;        
	int pad = 0;
	size_t extra_pad;             

	memset(dbase64_table, 0x80, 256);
	for(i = 0; i < sizeof(base64_table) - 1; i++){
		dbase64_table[base64_table[i]] = (unsigned char) i;
	}
	dbase64_table['='] = 0;

	count = 0;
	for(i = 0; i < len; i++) {
		if (dbase64_table[src[i]] != 0x80) count++;
	}

	if(count == 0) return nullptr;

	extra_pad = (4 - count % 4) % 4;

	olen = (count + extra_pad) / 4 * 3;

	std::unique_ptr<uint8_t[]> out ( new uint8_t[olen] );
	if( !out ) return nullptr;

	pos = out.get();
	count = 0;
	for(i = 0; i < len + extra_pad; i++) {
		unsigned char val;

		if (i >= len)
			val = '=';
		else
			val = src[i];
		tmp = dbase64_table[val];
		if (tmp == 0x80) continue;

		if (val == '=')
		    pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
				    /* Invalid padding */
					out.reset();
					return nullptr;
				}
				break;
			}
		}
	}

	*out_len = pos - out.get();
	return out;
}

//
std::string SHA1_hash(const void *data, unsigned long len)
{
	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA_CTX ctx;
	if( !SHA1_Init(&ctx) ) {
		throw std::runtime_error(excp_method("SHA1_Init() failed"));
	}

	SHA1_Update(&ctx, data, len);
	if( !SHA1_Final(hash, &ctx) ){
		throw std::runtime_error(excp_method("SHA1_Final() failed"));
	}

	// Добабить хеш в строку в формате HEX
	std::string hash_str;
	for(size_t i = 0; i < sizeof(hash); ++i){
		char tmp[3] = {0};
		sprintf(tmp, "%02x", hash[i]);
		hash_str += tmp;
	}

	return hash_str;
}

std::string SHA256_hash(const void *data, unsigned long len)
{
	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA256_CTX ctx;
	if( !SHA256_Init(&ctx) ) {
		throw std::runtime_error(excp_method("SHA256_Init() failed"));
	}

	SHA256_Update(&ctx, data, len);
	if( !SHA256_Final(hash, &ctx) ){
		throw std::runtime_error(excp_method("SHA256_Final() failed"));
	}

	// Добабить хеш в строку в формате HEX
	std::string hash_str;
	for(size_t i = 0; i < sizeof(hash); ++i){
		char tmp[3] = {0};
		sprintf(tmp, "%02x", hash[i]);
		hash_str += tmp;
	}

	return hash_str;
}


// Получить текущее локальное время системы в виде строки в заданном формате
std::string get_local_datetime_fmt(const char *fmt, bool with_ms, const time_t *sec)
{
	char str[64] = {0};
	time_t seconds = sec ? *sec : time(nullptr);
	struct tm timeinfo;
	struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);

	if( !localtime_r(&seconds, &timeinfo) ){
		return "";
	} 

	char buf[32] = {0};
	strftime(buf, sizeof buf, fmt, &timeinfo);
	if( !with_ms ){
		return std::string(buf);
	} 

	snprintf(str, sizeof str, "%s%03lu", buf, spec.tv_nsec / 1000000L);
	return std::string(str);
}

// Выполнить команду в оболочке и считать вывод через пайп в строку.
std::string exec_piped(const std::string &cmd)
{
	std::array<char, 128> buf{};
	std::string result;
	std::unique_ptr<FILE, decltype(pclose)*> pipe(popen(cmd.c_str(), "r"), pclose);

	if( !pipe ){
		throw std::runtime_error(excp_func((std::string)"popen() failed: " + strerror(errno)));
	} 

	while(fgets(buf.data(), buf.size(), pipe.get()) != nullptr){
	    result += buf.data();
	    std::fill(begin(buf), end(buf), 0);
	}

	return result;
}

// Выполнить команду в оболочке
bool exec(const std::string &cmd, bool no_throw)
{
	int res = system(cmd.c_str());

	if(res){
		if( !no_throw ){
			throw std::runtime_error("cmd '" + cmd + "' failed (" + std::to_string(WEXITSTATUS(res)) + ")");
		}
		return false;
	} 

	return true;
}

// Получение текущего абсолютного пути рабочей директории 
std::string get_cwd(void)
{
	int cnt = 0;
	char buf[256] = {0};

	cnt = readlink("/proc/self/exe", buf, sizeof buf);

	if(cnt <= 0){
		throw std::runtime_error((std::string)"readlink '/proc/self/exe' failed: " + strerror(errno));
	} 

	char* sc = strrchr(buf, '/');
	if(sc){
		*sc = '\0'; // исключить собственное имя бинарника
	} 

	return std::string(buf);
}

// Изменение прав доступа к файлу
void change_mod(const std::string &path, mode_t mode)
{
	if(chmod(path.c_str(), mode)){
		throw std::runtime_error("failed to change mod '" + path + "': " + strerror(errno));
	} 
}

// Создание новой директории если таковой еще не существует
void make_dir_if_not_exists(const std::string& path, mode_t mode)
{
	if(path.empty()){
		return;
	}

	std::string cmd_ret = exec_piped("mkdir -p " + path + " 2>&1 | tr -d '\n'");

	if(!cmd_ret.empty()){
		throw std::runtime_error(" failed: " + cmd_ret);
	} 

	change_mod(path, mode);
}

std::string short_name(const std::string &path)
{
	std::string res{path};
	size_t pos = path.find_last_of('/');
	if( (pos != std::string::npos) && ((pos + 1) < path.length()) ){
		res = path.substr(pos + 1);
	} 

	return res;
}

std::string file_extension(const std::string &path)
{
	std::string extension;
	size_t pos = path.find_last_of('.');

	if( pos != std::string::npos ){
		extension = path.substr(pos);
	}

	return extension;
}

// Определение размера директории
uint64_t get_dir_size(const std::string &dir_name, bool nesting)
{
	uint64_t total = 0;
	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir);
	struct dirent *entry = nullptr;

	if( !dirp ){
		throw std::runtime_error(excp_func("opendir '" + dir_name + "' failed: " + strerror(errno)));
	} 

	while( (entry = readdir(dirp.get())) != nullptr ){

		std::string entry_name = dir_name + "/" + entry->d_name;

		// Если разрешена вложенность, считаем размер поддиректорий
		if( nesting && (entry->d_type == DT_DIR) && strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") ){
			total += get_dir_size(entry_name, nesting);;
		}
		// Считаем размер файлов
		else if(entry->d_type == DT_REG){
			total += get_file_size(entry_name);
		}
	}

	return total;
}

uint32_t get_files_num_in_dir(const std::string &dir_name, const std::string &ext, bool nesting)
{
	uint32_t file_count = 0;
	struct dirent *entry = nullptr;
	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir); 

	if( !dirp ){
		throw std::runtime_error(excp_func("opendir '" + dir_name + "' failed: " + strerror(errno)));
	} 

	while( (entry = readdir(dirp.get())) != nullptr ) {

		if( nesting && (entry->d_type == DT_DIR) && strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") ){
			std::string entry_name = dir_name + "/" + entry->d_name;
			file_count += get_files_num_in_dir(entry_name, ext, nesting);
		}
		else if(entry->d_type == DT_REG){
			// Поиск любых файлов
	        if( ext.empty() ){
	            ++file_count;
	        }
	        // Поиск файлов с заданным расширением
	        else{
	            std::string fn{entry->d_name};
	            size_t pos = fn.find_last_of('.');
	            if( (pos != std::string::npos) && (fn.substr(pos) == ext) ){
	                ++file_count;
	            }
	        }
		}
	}

	return file_count;
}


// Определение количества файлов и поддиректорий в директории
uint32_t get_entries_num_in_dir(const std::string &dir_name)
{
	uint32_t count = 0;
	struct dirent *entry = nullptr;
	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir); 

	if(!dirp) throw std::runtime_error(excp_func("opendir '" + dir_name + "' failed: " + strerror(errno)));

	while( (entry = readdir(dirp.get())) != nullptr ) {
		if( (entry->d_type == DT_REG) || ((entry->d_type == DT_DIR) && strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ){
			++count;
		}
	}

	return count;
}



std::vector<std::string> get_file_names_in_dir(
	const std::string &dir_name,
	const char *file_ext,
	uint32_t max_file_num, 
	uint64_t max_total_size,
	uint32_t skip_files_num)
{
	uint64_t curr_size = 0;

	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir);
	struct dirent* entry = nullptr;
	std::vector<std::string> vec;

	if( !dirp ){
		throw std::runtime_error(excp_func("opendir '" + dir_name + "' failed: " + strerror(errno)));
	} 

	while( (entry = readdir(dirp.get())) != nullptr )
	{
		bool to_add = false;

		// Проверка достижения максимального числа обрабатываемых файлов
		if(max_file_num && (vec.size() >= max_file_num)) break;

		// Проверка достижения максимального размера обрабатываемых файлов [Б]
		if(max_total_size && (curr_size > max_total_size)) break;

		// Исключить из поиска относительные переходы
		if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

		// Игнорировать все кроме файлов
		if( entry->d_type != DT_REG ) continue;

		// Поиск любых файлов
		if( !file_ext ){
			to_add = true;
		}
		// Поиск файлов с заданным расширением
		else{
			std::string fn{entry->d_name};
			size_t pos = fn.find_last_of('.');
			if( (pos != std::string::npos) && (fn.substr(pos) == file_ext) ){
				to_add = true;
			}
		}

		if(to_add){
			// Если требуется пропустить некоторое количество имен файлов - пропускаем
			if(skip_files_num){
				--skip_files_num;
				continue;
			} 

			uint64_t fsize = get_file_size(dir_name + "/" + entry->d_name);
			if( max_total_size && (fsize > (max_total_size - curr_size)) ){
				// Файл не влезает в оставшийся допустимый общий размер - попробуем найти другой
				continue;
			} 
			vec.push_back(entry->d_name);
			curr_size += fsize;
		}
	}

	return vec;
}

std::unordered_set<std::string> get_file_names_in_dir(
	const std::string &dir_name, 
	const std::string &ext,
	uint64_t max_size,
	uint64_t *total_size,
	const std::unordered_set<std::string> *exclude_names,
	uint32_t max_num
	)
{
	uint64_t curr_size = 0;

	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir);
	struct dirent *entry = nullptr;
	std::unordered_set<std::string> set;

	if( !dirp ){
		throw std::runtime_error("opendir '" + dir_name + "' failed: " + strerror(errno));
	}

	while( (entry = readdir(dirp.get())) != nullptr )
	{
		bool to_add = false;

		// Проверка достижения максимального числа обрабатываемых файлов
		if(max_num && (set.size() >= max_num)) break;

		// Проверка достижения максимального размера обрабатываемых файлов [Б]
		if(max_size && (curr_size > max_size)) break;

		// Исключить из поиска относительные переходы
		if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

		// Игнорировать все кроме файлов
		if( entry->d_type != DT_REG ) continue;

		// Если задан список игнорируемых имен - проверяем 
		if(exclude_names && (exclude_names->find(entry->d_name) != exclude_names->end() )){	
			continue;
		}

	    // Поиск любых файлов
		if( ext.empty() ){
			to_add = true;
		}
	    // Поиск файлов с заданным расширением
	    else if(file_extension(entry->d_name) == ext){
	    	to_add = true;
	    }

		if(to_add){
			uint64_t fsize = get_file_size(dir_name + "/" + entry->d_name);
			if( max_size && (fsize > (max_size - curr_size)) ){
				// попробуем найти файл поменьше
				continue;
			} 

			set.insert(entry->d_name);
			curr_size += fsize;
		}
	}

	if(total_size){
		*total_size = curr_size;
	}

	return set;
}

std::vector<std::string> get_subdirs_names_in_dir(const std::string &dir_name)
{
	std::unique_ptr<DIR, int(*)(__dirstream*)> dirp (opendir(dir_name.c_str()), closedir);
	struct dirent *entry = nullptr;
	std::vector<std::string> vec;

	if( !dirp ){
		throw std::runtime_error(excp_func("opendir '" + dir_name + "' failed: " + strerror(errno)));
	} 

	while( (entry = readdir(dirp.get())) != nullptr )
	{
		// Исключить из поиска относительные переходы
		if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

		// Регистрируем имена директорий
		if(entry->d_type == DT_DIR){
			vec.push_back(entry->d_name);
		}
	}

	return vec;
}


// Сортирует вывод в алфавитном порядке
std::vector<std::string> get_file_names_in_dir_v2(
	const std::string &dir_name,
	const char *file_ext,
	uint32_t max_file_num, 
	uint64_t max_total_size,
	uint32_t skip_files_num)
{
	uint64_t ts = 0; 

	struct dirent **namelist = nullptr;
	std::vector<std::string> vec;

	int n = scandir(dir_name.c_str(), &namelist, nullptr, alphasort);

	if(n == -1){
		throw std::runtime_error(excp_func("scandir '" + dir_name + "' failed: " + strerror(errno)));
	} 

	while( n-- )
	{
		bool to_add = false;
		struct dirent *entry = namelist[n];	// TODO: free

		// Проверка достижения максимального числа обрабатываемых файлов
		if(max_file_num && (vec.size() >= max_file_num)) break;

		// Проверка достижения максимального размера обрабатываемых файлов [Б]
		if(max_total_size && (ts > max_total_size)) break;

		// Исключить из поиска относительные переходы
		if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

		// Игнорировать все кроме файлов
		if( entry->d_type != DT_REG ) continue;

		// Поиск любых файлов
		if( !file_ext ){
			to_add = true;
		}
		// Поиск файлов с заданным расширением
		else{
			std::string fn{entry->d_name};
			size_t pos = fn.find_last_of('.');
			if( (pos != std::string::npos) && (fn.substr(pos) == file_ext) ){
				to_add = true;
			}
		}

		if(to_add){
			// Если требуется пропустить некоторое количество имен файлов - пропускаем
			if(skip_files_num){
				--skip_files_num;
				continue;
			} 

			uint64_t fsize = get_file_size(dir_name + "/" + entry->d_name);
			if( max_total_size && (fsize > (max_total_size - ts)) ) continue;
			vec.push_back(entry->d_name);
			ts += fsize;
		}

		free(namelist[n]);
	}

	free(namelist);
	return vec;
}


//
void remove_head_files_from_dir(const std::string &dir_name, uint32_t files_num, bool async)
{
	std::string cmd = "for i in $(ls " + dir_name + " | head -" + std::to_string(files_num) + " ); do rm -rf " + dir_name + "/$i; done";
	if(async) cmd += " &";

	exec(cmd); 
}


uint64_t get_file_size (const std::string &fname)
{
	struct stat st;
	if(stat(fname.c_str(), &st)) throw std::runtime_error(excp_func("File '" + fname + "' : " + strerror(errno)));

	return static_cast<uint64_t>(st.st_size);
}


std::unique_ptr<uint8_t[]> read_bin_file(const std::string &fname, uint64_t *buf_len)
{
	std::ifstream file(fname, std::ifstream::binary);
	if( !file.is_open() ) throw std::runtime_error(excp_func("File '" + fname + "' open for reading failed"));

	uint64_t size = get_file_size(fname);
	std::unique_ptr<uint8_t[]> buf_ptr(new (std::nothrow) uint8_t[size]); 
	if( !buf_ptr ) throw std::runtime_error(excp_func("Memory allocation for '" + fname + "' buf failed"));

	if( !file.read(reinterpret_cast<char*>(buf_ptr.get()), size) ) throw std::runtime_error(excp_func("File '" + fname + "' read failed"));
	file.close();
	if(buf_len) *buf_len = size;
	return buf_ptr;
}

void write_bin_file(const std::string& fname, const uint8_t *buf, size_t buf_len)
{
	std::ofstream file(fname, std::ofstream::binary);

	if( !file.is_open()) throw std::runtime_error("File '" + fname + "' open for writing failed");

	if( !file.write(reinterpret_cast<const char*>(buf), buf_len) ) throw std::runtime_error("File '" + fname + "'writing failed");
	file.flush();
	file.close();
}

void write_text_file(const std::string& fname, const char *buf, size_t buf_len)
{
	std::ofstream file(fname);

	if( !file.is_open() ) throw std::runtime_error("File '" + fname + "' open for writing failed");

	if( !file.write(buf, buf_len) ) throw std::runtime_error("File '" + fname + "' writting failed");
	file.flush();
	file.close();
}

std::string unpack_tar(const std::string &tar_name, const std::string &dest_dir, bool no_info_error)
{
	std::string cmd = "tar -xf " + tar_name + " -C " + dest_dir + "/";
	
	// Распаковать архив
	exec(cmd);

	// Прочитать из 2 строки fileinfo файла название БД
	std::ifstream file(dest_dir + "/fileinfo");

	if( !file.is_open() ){
		if(no_info_error) throw std::runtime_error("No fileinfo from '" + short_name(tar_name) + "' found");

		return "";
	} 

	std::string content_name;
	std::string content_type;
	getline(file, content_type); 	// Пропустить первую строку
	getline(file, content_name);

	return content_name;
}


} // namespace
}
