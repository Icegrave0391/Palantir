import argparse
import logging
from colorlog import ColoredFormatter

log = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
    prog="redis",
    description="operations to redis")

    parser.add_argument('-l', '--logging', type=int, default=10,    
                        help='Log level [10-50] (default: 10 - Debug)')

    parser.add_argument('--host', type=str, default='127.0.0.1',
                        help='ip address for redis server')
    parser.add_argument('--port', type=int, default=6379,
                        help='ip port for redis server')
    parser.add_argument('--password', type=str, default='',
                        help='password for db auth')
    parser.add_argument('--db', type=str, default='',
                        help='database to connect')

    parser.add_argument('--json_file', type=str, default='test.json',
                        help='database to connect')

    args = parser.parse_args()
    return args
    
def init_logging(level:int) -> None:
    formatter = ColoredFormatter(
        "%(white)s%(asctime)10s | %(log_color)s%(levelname)6s | %(log_color)s%(message)6s",
        reset=True,
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'yellow',
            'WARNING':  'green',
            'ERROR':    'red',
            'CRITICAL': 'red,bg_white',
        },
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(level)

def init_setting() -> argparse.Namespace:
    args = parse_args()
    init_logging(args.logging)
    return args