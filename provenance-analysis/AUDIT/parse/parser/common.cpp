#include "common.h"

std::ostringstream& operator<<(std::ostringstream& dest, __uint128_t value)
{
    std::ostringstream::sentry s(dest);
    if (s) {
        __uint128_t tmp = value;
        char buffer[128];
        char* d = std::end(buffer);
        do {
            -- d;
            *d = "0123456789"[tmp % 10];
            tmp /= 10;
        } while (tmp != 0);
        int len = std::end(buffer) - d;
        if (dest.rdbuf()->sputn(d, len) != len) {
            dest.setstate(std::ios_base::badbit);
        }
    }
    return dest;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
   std::vector<std::string> tokens;
   std::string token;
   std::istringstream tokenStream(s);
   while (std::getline(tokenStream, token, delimiter)) {
      tokens.push_back(token);
   }
   return tokens;
}

std::string NodeEnum2String(NodeType_t type) {
	switch(type){
		case NodeType_t::Proc:
			return "proc";
		case NodeType_t::File:
			return "file";
		case NodeType_t::Socket:
			return "socket";
		case NodeType_t::Attr:
			return "attr";
		case NodeType_t::NotDefined:
			std::cerr << "undefined node " << __FILE__ << " "<<  __LINE__ << std::endl;
			return "notdefined";
	}
	return "";
}

int NodeEnum2Int(NodeType_t type) {
	switch(type){
		case NodeType_t::Proc:
			return 1;
		case NodeType_t::File:
			return 2;
		case NodeType_t::Socket:
			return 3;
		case NodeType_t::Attr:
			return 4;
		case NodeType_t::NotDefined:
			std::cerr << "undefined node " << __FILE__ << " "<<  __LINE__ << std::endl;
			return 0;
	}
	return 0;
}

std::string EdgeEnum2String(EdgeType_t type) {
	switch(type){
		case EdgeType_t::Vfork:
			return "vfork";
		case EdgeType_t::Clone:
			return "clone";
		case EdgeType_t::Execve:
			return "execve";
		case EdgeType_t::Kill:
			return "kill";
		case EdgeType_t::Create:
			return "create";
		case EdgeType_t::Pipe:
			return "pipe";
		case EdgeType_t::Delete:
			return "delete";
		case EdgeType_t::Recv:
			return "recv";
		case EdgeType_t::Send:
			return "send";
		case EdgeType_t::Mkdir:
			return "mkdir";
		case EdgeType_t::Rmdir:
			return "rmdir";
		case EdgeType_t::Open:
			return "open";
		case EdgeType_t::Load:
			return "load";
		case EdgeType_t::Read:
			return "read";
		case EdgeType_t::Pread:
			return "pread";
		case EdgeType_t::Write:
			return "write";
		case EdgeType_t::Writev:
			return "writev";
		case EdgeType_t::Connect:
			return "connect";
		case EdgeType_t::Getpeername:
			return "getpeername";
		case EdgeType_t::Accept4:
			return "accept4";
		case EdgeType_t::NotDefined:
			std::cerr << "undefined relation " << __FILE__ << " "<<  __LINE__ << std::endl;
			return "notdefined";
	}
	return "";
}

int EdgeEnum2Int(EdgeType_t type) {
	switch(type){
		case EdgeType_t::Vfork:
			return 1;
		case EdgeType_t::Clone:
			return 2;
		case EdgeType_t::Execve:
			return 3;
		case EdgeType_t::Kill:
			return 4;
		case EdgeType_t::Pipe:
			return 5;
		case EdgeType_t::Delete:
			return 6;
		case EdgeType_t::Create:
			return 7;
		case EdgeType_t::Recv:
			return 8;
		case EdgeType_t::Send:
			return 9;
		case EdgeType_t::Mkdir:
			return 10;
		case EdgeType_t::Rmdir:
			return 11;
		case EdgeType_t::Open:
			return 12;
		case EdgeType_t::Load:
			return 13;
		case EdgeType_t::Read:
			return 14;
		case EdgeType_t::Pread:
			return 15;
		case EdgeType_t::Write:
			return 16;
		case EdgeType_t::Writev:
			return 17;
		case EdgeType_t::Connect:
			return 18;
		case EdgeType_t::Getpeername:
			return 19;
		case EdgeType_t::Accept4:
			return 20;
		case EdgeType_t::NotDefined:
			std::cerr << "undefined relation " << __FILE__ << " "<<  __LINE__ << std::endl;
			return 0;
	}
	return 0;
}

std::string EdgeInt2String(int id) {
	switch(id){
		case 1:
			return "vfork";
		case 2:
			return "clone";
		case 3:
			return "execve";
		case 4:
			return "kill";
		case 5:
			return "create";
		case 6:
			return "pipe";
		case 7:
			return "delete";
		case 8:
			return "recv";
		case 9:
			return "send";
		case 10:
			return "mkdir";
		case 11:
			return "rmdir";
		case 12:
			return "open";
		case 13:
			return "load";
		case 14:
			return "read";
		case 15:
			return "pread";
		case 16:
			return "write";
		case 17:
			return "writev";
		case 18:
			return "connect";
		case 19:
			return "getpeername";
		case 20:
			return "accept4";
		case 0:
			std::cerr << "undefined relation " << __FILE__ << " "<<  __LINE__ << std::endl;
			return "";
	}
	return "";
}
