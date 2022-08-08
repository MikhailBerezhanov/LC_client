#include <stdexcept>

#define JSON_DIAGNOSTICS 1
#include "nlohmann/json.hpp"

#include "lc_protocol.hpp"

using json = nlohmann::json;

namespace lc {

std::string file_get_request::to_json() const
{
	std::string ret;

	try{
		json j;

		j["header"]["protocol_ver"] = hdr.protocol_ver;
		j["devinfo"]["psu"] = devinfo.psu;
		j["devinfo"]["type"] = devinfo.type;

		j["versions"] = json::array();
		for(size_t i = 0; i < finfo.size(); ++i){
			json j_elem;
			j_elem["type"] = finfo[i].type;
			j_elem["version"] = finfo[i].version;
			j["versions"].push_back(j_elem);
		}

		j["current_time"] = ctime.val;
		j["signature"] = sig.val;

		ret = j.dump();
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_get_request.to_json(): ") + e.what());
	}

	return ret;
}

void file_get_response::from_json(const char *json_str)
{
	try{
		auto j = json::parse(json_str);

		hdr.protocol_ver = j["header"]["protocol_ver"];
		res.code = j["result"]["code"];
		if( !j["result"]["text"].is_null() ) res.text = j["result"]["text"];

		if( !j["files"].is_array() ){
			throw std::runtime_error("/files isn't an array");
		} 

		for(size_t i = 0; i < j["files"].size(); ++i){

			file f_elem(
				j["files"][i]["type"], 
				j["files"][i]["version"], 
				j["files"][i]["size"],
				j["files"][i]["name"],
				j["files"][i]["content"],
				j["files"][i]["cs"]);

			files.push_back(f_elem);
		}

		ctime.val = j["current_time"];
		sig.val = j["signature"];
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_get_response.from_json(): ") + e.what());
	}
	catch(const std::exception& e){
		throw std::runtime_error(std::string("file_get_response.from_json(): ") + e.what());
	}
}

std::ostream& operator<< (std::ostream &os, const file_info &fi)
{
	os << "\ttype:\t\t" << fi.type << "\n" << "\tversion:\t" << fi.version;

	return os;
}

std::ostream& operator<< (std::ostream &os, const file &f)
{
	os << f.info << "\n" << "\tsize:\t\t" << f.size << "\n" <<
	"\tname:\t\t" << f.name << "\n" << "\tcs:\t\t" << f.crc << "\n";
	if( !f.content.empty() ){
		size_t len = f.content.length();
		if(len > 16) os << "\tcontent:\t[ " << f.content.substr(0, 16) << " ] (" << len << ")";
		else os << "\tcontent:\t" << f.content.substr(0, len);
	}

	return os;
}

std::ostream& operator<< (std::ostream &os, const file_get_response &r)
{
	os << "--- LCC file_get_response ---\n" <<
	"header.protocol_ver:\t" << r.hdr.protocol_ver << "\n" <<
	"result.code:\t" << r.res.code << "\n" <<
	"result.text:\t" << r.res.text << "\n" <<
	"files:";
	for(size_t i = 0; i < r.files.size(); ++i){
		os << "\n[" << i << "]:\n" << r.files[i];
	}
	os << "\ncurrent_time:\t" << r.ctime.val << "\n" <<
	"signature:\t" << r.sig.val;

	return os;
}

void get_media_list_response::from_json(const char *json_str)
{
	try{
		auto j = json::parse(json_str);

		hdr.protocol_ver = j["header"]["protocol_ver"];
		res.code = j["result"]["code"];
		// Текст - необязательное поле
		if( !j["result"]["text"].is_null() ){
			res.text = j["result"]["text"];
		} 

		auto fill_list = [&j](std::vector<list_elem> &out, const char *list_name){
			// Лист не включается в ответ при отсутствии необходимости обновления медиафайлов 
			if( j[list_name].is_null() ){
				return;
			}

			if( !j[list_name].is_array() ){
				throw std::runtime_error(std::string("/") + list_name + " isn't an array");
			} 

			out.clear();

			for(size_t i = 0; i < j[list_name].size(); ++i){
				out.emplace_back(j[list_name][i]["name"], j[list_name][i]["md5"]);
			}
		};

		fill_list(tmp_media_list, "tmpmedialist");
		fill_list(const_media_list, "constmedialist");

		ctime.val = j["current_time"];
		sig.val = j["signature"];
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("get_media_list_response.from_json(): ") + e.what());
	}
	catch(const std::exception& e){
		throw std::runtime_error(std::string("get_media_list_response.from_json(): ") + e.what());
	}
}

std::string file_post_request::to_json() const
{
	std::string ret;

	try{
		json j;

		j["header"]["protocol_ver"] = hdr.protocol_ver;
		j["devinfo"]["psu"] = devinfo.psu;
		j["devinfo"]["type"] = devinfo.type;

		j["files"] = json::array();
		for(size_t i = 0; i < files.size(); ++i){
			json j_elem;
			j_elem["type"] = files[i].info.type;
			j_elem["version"] = files[i].info.version;
			j_elem["size"] = files[i].size;
			j_elem["name"] = files[i].name;
			j_elem["content"] = files[i].content;
			j_elem["cs"] = files[i].crc;
			j["files"].push_back(j_elem);
		}

		j["current_time"] = ctime.val;
		j["signature"] = sig.val;

		ret = j.dump();
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_post_request.to_json(): ") + e.what());
	}

	return ret;
}

void file_post_response::from_json(const char *json_str)
{
	try{
		auto j = json::parse(json_str);

		hdr.protocol_ver = j["header"]["protocol_ver"];
		res.code = j["result"]["code"];
		if( !j["result"]["text"].is_null() ) res.text = j["result"]["text"];

		ctime.val = j["current_time"];
		sig.val = j["signature"];
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_get_response.from_json(): ") + e.what());
	}
}

std::ostream& operator<< (std::ostream &os, const file_post_response &r)
{
	os << "--- LCC file_post_response ---\n" <<
	"header.protocol_ver:\t" << r.hdr.protocol_ver << "\n" <<
	"result.code:\t" << r.res.code << "\n" <<
	"result.text:\t" << r.res.text << "\n" <<
	"current_time:\t" << r.ctime.val << "\n" <<
	"signature:\t" << r.sig.val;

	return os;
}



void sys_info::add_json_part(nlohmann::json &j) const
{
	j["state"] = state;
	j["app_version"] = app_version;
	j["nsi_version"] = nsi_version;
}

void sys_info_avi::add_json_part(nlohmann::json &j) const
{
	sys_info::add_json_part(j);

	j["vehicle_number"] = vehicle_number;
	j["sd_free_space"] = sd_free_space;
}


std::string info_post_request::to_json() const
{
	std::string ret;

	try{
		json j;

		j["header"]["protocol_ver"] = hdr.protocol_ver;
		j["devinfo"]["psu"] = devinfo.psu;
		j["devinfo"]["type"] = devinfo.type;

		// Добавить содержимое в зависимости от динамического типа указателя
		if(info) info->add_json_part( j["sys_info"] );	

		j["current_time"] = ctime.val;
		j["signature"] = sig.val;

		ret = j.dump();
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_post_request.to_json(): ") + e.what());
	}

	return ret;
}

void info_post_response::from_json(const char *json_str)
{
	try{
		auto j = json::parse(json_str);

		hdr.protocol_ver = j["header"]["protocol_ver"];
		res.code = j["result"]["code"];
		if( !j["result"]["text"].is_null() ) res.text = j["result"]["text"];

		push.action = j["push"][""];
		push.data = j["push"]["data"];
		push.mode = j["push"]["mode"];
		push.data_mode = j["push"]["datamode"];
		push.duration = j["push"]["duration"];

		ctime.val = j["current_time"];
		sig.val = j["signature"];
	}
	catch(json::exception& e){
		throw std::runtime_error(std::string("file_get_response.from_json(): ") + e.what());
	}
}


} // namespace




#ifdef _LC_PROTOCOL_TEST

int main(int argc, char* argv[])
{
	using namespace std;
	using namespace lc;

	cout << "1. ___ Testing GET_FILES Method ___" << endl;

	file_get_request get_req(UINT32_MAX, "usk03");
	//file_get_request get_req2(-1, "usk03");
	// file_get_request get_req3{-10, "usk-10"};

	file_get_response get_resp;

	file_info f1("nsi", "1.123");
	file_info f2;
	get_req.finfo.push_back(f1);
	get_req.finfo.push_back(f2);
	try{
		cout << get_req.to_json() << '\n' << endl;

		get_resp.from_json("{ \
\"header\": {\"protocol_ver\":\"1.30\"}, \
\"result\": {\"code\":0}, \
\"files\": [ \
{\"type\":\"test\", \"version\": \"0123\", \"size\": 3, \"name\":\"TEST1\", \"content\":\"abc\", \"cs\":0}, \
{\"type\":\"test\", \"version\": \"0123\", \"size\": 10, \"name\":\"TEST2\", \"content\":\"ACD\", \"cs\":0} \
], \
\"current_time\": \"current_time\", \
\"signature\": \"signature\"}");

		cout << get_resp << endl;
	}
	catch(exception& e){
		cerr << e.what() << endl;
	}
	
	

	get_req.finfo.clear();
	get_resp.files.clear();

	cout << endl;
	cout << "2. ___ Testing PUT_FILES Method ___" << endl;

	file_post_request put_req;
	put_req.devinfo.psu = -10;

	file_post_response put_resp;

	try{
		cout << put_req.to_json() << '\n' << endl;

		put_resp.from_json("{ \
\"header\": {\"protocol_ver\":\"1.30\"}, \
\"result\": {\"code\":0}, \
\"current_time\": \"current_time\", \
\"signature\": \"signature\"}");

		cout << put_resp << endl;
	}
	catch(exception& e){
		cerr << e.what() << endl;
	}


	cout << "3. ___ Testing SYS_INFO Method ___" << endl;

	sys_info si;
	sys_info_avi si_avi;

	info_post_request si_req1(123, "test", &si);
	info_post_request si_req2(45678, "avi", &si_avi);

	try{
		cout << si_req1.to_json() << '\n' << endl;
		cout << si_req2.to_json() << '\n' << endl;
	}
	catch(exception& e){
		cerr << e.what() << endl;
	}

	return 0;
}

#endif