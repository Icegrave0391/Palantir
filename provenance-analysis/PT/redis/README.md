# Redis
Redis is an in-memory key-value store known for its flexibility, performance, and wide language support.

### Install Redis 
-------------------
``` bath
$ sudo apt update
$ sudo apt install redis-server

# install redis-dump
$ sudo apt install ruby ruby-dev gcc
$ sudo gem install redis-dump
```

### Test Redis 
-------------------
``` bath
$ service redis status
$ redis-cli
127.0.0.1:6379> set test "working"
127.0.0.1:6379> get test
127.0.0.1:6379> exit
```
Redis is ready to use if you see "working" after "get test"

### Dump and Load Redis DB
-------------------
``` bath
$ (dump) redis-dump –u 127.0.0.1:6379 > test.json
$ (load) < test.json redis-load -u 127.0.0.1:6379

$ (cleanup) redis-cli
$ (cleanup) FLUSHDB
```

### Python and C++ for Redis
-------------------
#### Python on [redis-py](https://github.com/WoLpH/redis-py)
Better create a virtual environment to install redis
``` bath
$ workon pt
$ pip3 install redis
```

#### C++ on [HIREDIS](https://github.com/redis/hiredis)
Better create a virtual environment to install redis
``` bath
$ wget https://github.com/redis/hiredis/archive/refs/tags/v1.0.2.tar.gz
$ tar xzvf v1.0.2.tar.gz
$ cd hiredis-1.0.2
$ mv hiredis-1.0.2 hiredis
$ make
$ sudo make install
```