#ifndef _REDIS_REDIS_H_
#define _REDIS_REDIS_H_

#include <iostream>
#include <vector>
#include <cstring>

extern "C" {
    #include "hiredis/hiredis.h"
}

class Redis {
    public:
        std::string prog_name;
        redisContext *conn = NULL;
        redisReply *key_reply = NULL;
        redisReply *type_reply = NULL;
        redisReply *value_reply = NULL;

        Redis(const char *ip, int port, std::string prog_name);
        ~Redis();

        const char* getStringValue(const char *key);
        std::vector<std::string> getListValue(const char* key);

        const char* getType(const char *key);
        void getAllKey();
        void getAllValue();
};

#endif