#include "redis.h"

Redis::Redis(const char *ip, int port, std::string _prog_name) {
    prog_name = _prog_name;
    conn = redisConnect(ip, port);
    
    if (conn == NULL or conn->err) {
        if (conn)
            std::cerr << conn->err << std::endl;
        else
            std::cerr << "Connection error: can't allocate redis context" << std::endl;
        exit(-1);
    }
    else {
        std::cout << "Successfully Connect to Redis db" << std::endl;
    }
}

Redis::~Redis() {
    if (key_reply)
        freeReplyObject(key_reply);
    // if (type_reply)
    //     freeReplyObject(type_reply);
    // if (value_reply)
    //     freeReplyObject(value_reply);
    if (conn) {
        redisFree(conn);
    }
}

const char* Redis::getStringValue(const char *key) {
    value_reply = (redisReply *) redisCommand(conn, "GET %s", key);
    if (value_reply->type == REDIS_REPLY_ERROR) {
        std::cerr << "Redis Command Error " << value_reply->str << std::endl;
        exit(-1);
    }
    auto value = value_reply->str;
    return value;
}

std::vector<std::string> Redis::getListValue(const char* key) {
    value_reply = (redisReply *) redisCommand(conn, "LRANGE %s 0 -1", key);
    if (value_reply->type == REDIS_REPLY_ERROR) {
        std::cerr << "Redis Command Error " << value_reply->str << std::endl;
        exit(-1);
    }
    else if (value_reply->type != REDIS_REPLY_ARRAY) {
        std::cerr << "Unexpected: Keys should be an array " << std::endl;
        exit(-1);
    }

    std::vector<std::string> value_list;
    for (size_t j = 0; j < value_reply->elements; j++) {
        std::string value = value_reply->element[j]->str;
        value_list.push_back(value);
    }
    return value_list;
}

const char* Redis::getType(const char *key) {
    type_reply = (redisReply *) redisCommand(conn, "TYPE %s", key);
    auto type = type_reply->str;
    return type;
}

void Redis::getAllKey() {
    std::string key_command = "KEYS " + prog_name + ":*";
    key_reply = (redisReply *) redisCommand(conn, key_command.c_str());
    if (key_reply->type == REDIS_REPLY_ERROR) {
        std::cerr << "Redis Command Error " << key_reply->str << std::endl;
        exit(-1);
    }
    else if (key_reply->type != REDIS_REPLY_ARRAY) {
        std::cerr << "Unexpected: Keys should be an array " << std::endl;
        exit(-1);
    }
}
 
void Redis::getAllValue() {
    for (size_t i = 0; i < key_reply->elements; i++) {
        auto key = key_reply->element[i]->str;
        auto type = getType(key);

        if (strcmp(type, "string") == 0) {
            std::cout << "Key: " << key << "\tType: " << type;
            const char* value = getStringValue(key);
            std::cout << "\t Value: " << value << std::endl;
        }
        else if (strcmp(type, "list") == 0) {
            std::vector<std::string> value = getListValue(key);
            // std::cout << "\t Value: ";
            for (auto it: value) {
                // std::cout << it << "\t";
            }
            // std::cout << std::endl;
        }
        else {
            std::cout << "Unkown Redis Data Type: " << type << std::endl;
            exit(-1);
        }

        freeReplyObject(type_reply);
        freeReplyObject(value_reply);
    }
}
