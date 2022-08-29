#include "redis.h"

int main(int argc, char **argv) {
    const char *ip = "127.0.0.1";
    int port = 6379;

    if (argc == 2) {
        ip = argv[1];
        port = std::stoi(argv[2]);
    }

    Redis redis(ip, port, "");

    redis.getAllKey();
    redis.getAllValue();

    return 0;
}