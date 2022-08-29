import os
import redis
import argparse

from setting import init_setting, log

def connect(args:argparse.Namespace) -> redis.StrictRedis:
    log.info("Connecting to redis server")
    try:
        redis.StrictRedis(host=args.host, port=args.port).ping()
    except redis.ConnectionError:
        log.error("Fail to connect to redis %s:%d", args.host, args.port)
    return redis.StrictRedis(host=args.host, 
                             port=args.port,
                             db=args.db)

def load_json(args:argparse.Namespace) -> None:
    file_path = args.json_file
    if os.path.isabs(file_path):
        dir =os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(dir, file_path)

        if os.path.isfile(args.json_file):
            log.error("Cannot find json file %s", args.json_file)
            exit(-1)
    log.info("Loading json file from %s" % file_path)

    # load json file to redis 
    log.info("< {} redis-load -u {}:{}".format(file_path, args.host, args.port))
    os.system("< {} redis-load -u {}:{}".format(file_path, args.host, args.port))

def clean_db(redis_client:redis.StrictRedis) -> None:
    for k in redis_client.keys():
        redis_client.delete(k)

def print_db(redis_client:redis.StrictRedis) -> None:
    keys = redis_client.keys('*')
    log.debug('key:\tvalue:')
    for key in keys:
        type = redis_client.type(key)
        if type == b'string':
            val = redis_client.get(key).decode('ascii')
        # if type == b'hash':
        #     vals = redis_client.hgetall(key)
        # if type == b'zset':
        #     vals = redis_client.zrange(key, 0, -1)
        elif type == b'list':
            vals = redis_client.lrange(key, 0, -1)
            val = [v.decode('ascii') for v in vals]
        # if type == b'set':
        #     vals = redis_client.smembers(key)
        else:
            log.error('Unknown redis type ', type)
            exit(-1)

        log.debug(key.decode('ascii') + '\t' + ' '.join(map(str, val)))

def main():
    args = init_setting()

    # connect to redis server
    redis_client = connect(args)

    # cleanup redis db and load data from json
    clean_db(redis_client)
    load_json(args)

    # print keys in db
    print_db(redis_client)

if __name__ == "__main__":
    main()
