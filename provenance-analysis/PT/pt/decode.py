import os
import argparse
import subprocess
import re

def parse_args():
    """"Parse sys.argv"""
    parser = argparse.ArgumentParser(
        prog="decode",
        description="decode trace using griffin's tool (/tool/pt)")
    
    parser.add_argument('-p', '--pt_path', type=str, default='../pt/pt',
                        help='file path for tool/pt/pt (parse pt)')
    parser.add_argument('-t', '--trace_dir', type=str, 
                        default='../../trace/ls/trace-output',
                        help='dir path for pt trace')
    parser.add_argument('-d', '--disasm', type=str, default='1',
                        help='disasm for pt trace -> 0: xed; 1: distorm')
    args = parser.parse_args()
    return args

# syscall translation
system_calls = {
    0: 'read',
    1: 'write',
    2: 'open',
    3: 'close',
    4: 'stat',
    5: 'fstat',
    6: 'lstat',
    7: 'poll',
    8: 'lseek',
    9: 'mmap',
    10: 'mprotect',
    11: 'munmap',
    12: 'brk',
    13: 'rt_sigaction',
    14: 'rt_sigprocmask',
    15: 'rt_sigreturn',
    16: 'ioctl',
    17: 'pread',
    18: 'pwrite',
    19: 'readv',
    20: 'writev',
    21: 'access',
    22: 'pipe',
    23: 'select',
    24: 'sched_yield',
    25: 'mremap',
    26: 'msync',
    27: 'mincore',
    28: 'madvise',
    29: 'shmget',
    30: 'shmat',
    31: 'shmctl',
    32: 'dup',
    33: 'dup2',
    34: 'pause',
    35: 'nanosleep',
    36: 'getitimer',
    37: 'alarm',
    38: 'setitimer',
    39: 'getpid',
    40: 'sendfile',
    41: 'socket',
    42: 'connect',
    43: 'accept',
    44: 'sendto',
    45: 'recvfrom',
    46: 'sendmsg',
    47: 'recvmsg',
    48: 'shutdown',
    49: 'bind',
    50: 'listen',
    51: 'getsockname',
    52: 'getpeername',
    53: 'socketpair',
    54: 'setsockopt',
    55: 'getsockopt',
    56: 'clone',
    57: 'fork',
    58: 'vfork',
    59: 'execve',
    60: 'exit',
    61: 'wait4',
    62: 'kill',
    63: 'uname',
    64: 'semget',
    65: 'semop',
    66: 'semctl',
    67: 'shmdt',
    68: 'msgget',
    69: 'msgsnd',
    70: 'msgrcv',
    71: 'msgctl',
    72: 'fcntl',
    73: 'flock',
    74: 'fsync',
    75: 'fdatasync',
    76: 'truncate',
    77: 'ftruncate',
    78: 'getdents',
    79: 'getcwd',
    80: 'chdir',
    81: 'fchdir',
    82: 'rename',
    83: 'mkdir',
    84: 'rmdir',
    85: 'creat',
    86: 'link',
    87: 'unlink',
    88: 'symlink',
    89: 'readlink',
    90: 'chmod',
    91: 'fchmod',
    92: 'chown',
    93: 'fchown',
    94: 'lchown',
    95: 'umask',
    96: 'gettimeofday',
    97: 'getrlimit',
    98: 'getrusage',
    99: 'sysinfo',
    100: 'times',
    101: 'ptrace',
    102: 'getuid',
    103: 'syslog',
    104: 'getgid',
    105: 'setuid',
    106: 'setgid',
    107: 'geteuid',
    108: 'getegid',
    109: 'setpgid',
    110: 'getppid',
    111: 'getpgrp',
    112: 'setsid',
    113: 'setreuid',
    114: 'setregid',
    115: 'getgroups',
    116: 'setgroups',
    117: 'setresuid',
    118: 'getresuid',
    119: 'setresgid',
    120: 'getresgid',
    121: 'getpgid',
    122: 'setfsuid',
    123: 'setfsgid',
    124: 'getsid',
    125: 'capget',
    126: 'capset',
    127: 'rt_sigpending',
    128: 'rt_sigtimedwait',
    129: 'rt_sigqueueinfo',
    130: 'rt_sigsuspend',
    131: 'sigaltstack',
    132: 'utime',
    133: 'mknod',
    134: 'uselib',
    135: 'personality',
    136: 'ustat',
    137: 'statfs',
    138: 'fstatfs',
    139: 'sysfs',
    140: 'getpriority',
    141: 'setpriority',
    142: 'sched_setparam',
    143: 'sched_getparam',
    144: 'sched_setscheduler',
    145: 'sched_getscheduler',
    146: 'sched_get_priority_max',
    147: 'sched_get_priority_min',
    148: 'sched_rr_get_interval',
    149: 'mlock',
    150: 'munlock',
    151: 'mlockall',
    152: 'munlockall',
    153: 'vhangup',
    154: 'modify_ldt',
    155: 'pivot_root',
    156: '_sysctl',
    157: 'prctl',
    158: 'arch_prctl',
    159: 'adjtimex',
    160: 'setrlimit',
    161: 'chroot',
    162: 'sync',
    163: 'acct',
    164: 'settimeofday',
    165: 'mount',
    166: 'umount2',
    167: 'swapon',
    168: 'swapoff',
    169: 'reboot',
    170: 'sethostname',
    171: 'setdomainname',
    172: 'iopl',
    173: 'ioperm',
    174: 'create_module',
    175: 'init_module',
    176: 'delete_module',
    177: 'get_kernel_syms',
    178: 'query_module',
    179: 'quotactl',
    180: 'nfsservctl',
    181: 'getpmsg',
    182: 'putpmsg',
    183: 'afs_syscall',
    184: 'tuxcall',
    185: 'security',
    186: 'gettid',
    187: 'readahead',
    188: 'setxattr',
    189: 'lsetxattr',
    190: 'fsetxattr',
    191: 'getxattr',
    192: 'lgetxattr',
    193: 'fgetxattr',
    194: 'listxattr',
    195: 'llistxattr',
    196: 'flistxattr',
    197: 'removexattr',
    198: 'lremovexattr',
    199: 'fremovexattr',
    200: 'tkill',
    201: 'time',
    202: 'futex',
    203: 'sched_setaffinity',
    204: 'sched_getaffinity',
    205: 'set_thread_area',
    206: 'io_setup',
    207: 'io_destroy',
    208: 'io_getevents',
    209: 'io_submit',
    210: 'io_cancel',
    211: 'get_thread_area',
    212: 'lookup_dcookie',
    213: 'epoll_create',
    214: 'epoll_ctl_old',
    215: 'epoll_wait_old',
    216: 'remap_file_pages',
    217: 'getdents64',
    218: 'set_tid_address',
    219: 'restart_syscall',
    220: 'semtimedop',
    221: 'fadvise64',
    222: 'timer_create',
    223: 'timer_settime',
    224: 'timer_gettime',
    225: 'timer_getoverrun',
    226: 'timer_delete',
    227: 'clock_settime',
    228: 'clock_gettime',
    229: 'clock_getres',
    230: 'clock_nanosleep',
    231: 'exit_group',
    232: 'epoll_wait',
    233: 'epoll_ctl',
    234: 'tgkill',
    235: 'utimes',
    236: 'vserver',
    237: 'mbind',
    238: 'set_mempolicy',
    239: 'get_mempolicy',
    240: 'mq_open',
    241: 'mq_unlink',
    242: 'mq_timedsend',
    243: 'mq_timedreceive',
    244: 'mq_notify',
    245: 'mq_getsetattr',
    246: 'kexec_load',
    247: 'waitid',
    248: 'add_key',
    249: 'request_key',
    250: 'keyctl',
    251: 'ioprio_set',
    252: 'ioprio_get',
    253: 'inotify_init',
    254: 'inotify_add_watch',
    255: 'inotify_rm_watch',
    256: 'migrate_pages',
    257: 'openat',
    258: 'mkdirat',
    259: 'mknodat',
    260: 'fchownat',
    261: 'futimesat',
    262: 'newfstatat',
    263: 'unlinkat',
    264: 'renameat',
    265: 'linkat',
    266: 'symlinkat',
    267: 'readlinkat',
    268: 'fchmodat',
    269: 'faccessat',
    270: 'pselect6',
    271: 'ppoll',
    272: 'unshare',
    273: 'set_robust_list',
    274: 'get_robust_list',
    275: 'splice',
    276: 'tee',
    277: 'sync_file_range',
    278: 'vmsplice',
    279: 'move_pages',
    280: 'utimensat',
    281: 'epoll_pwait',
    282: 'signalfd',
    283: 'timerfd',
    284: 'eventfd',
    285: 'fallocate',
    286: 'timerfd_settime',
    287: 'timerfd_gettime',
    288: 'accept4',
    289: 'signalfd4',
    290: 'eventfd2',
    291: 'epoll_create1',
    292: 'dup3',
    293: 'pipe2',
    294: 'inotify_init1',
    295: 'preadv',
    296: 'pwritev',
    297: 'rt_tgsigqueueinfo',
    298: 'perf_event_open',
    299: 'recvmmsg',
    300: 'fanotify_init',
    301: 'fanotify_mark',
    302: 'prlimit64',
    303: 'name_to_handle_at',
    304: 'open_by_handle_at',
    305: 'clock_adjtime',
    306: 'syncfs',
    307: 'sendmmsg',
    308: 'setns',
    309: 'getcpu',
    310: 'process_vm_readv',
    311: 'process_vm_writev',
    312: 'kcmp',
    313: 'finit_module',
    314: 'sched_setattr',
    315: 'sched_getattr',
    316: 'renameat2',
    317: 'seccomp',
    318: 'getrandom',
    319: 'memfd_create',
    320: 'kexec_file_load',
    321: 'bpf',
    322: 'execveat',
    323: 'userfaultfd',
    324: 'membarrier',
    325: 'mlock2',
    326: 'copy_file_range',
    327: 'preadv2',
    328: 'pwritev2',
    329: 'pkey_mprotect',
    330: 'pkey_alloc',
    331: 'pkey_free',
    332: 'statx',
    333: 'io_pgetevents',
    334: 'rseq'
}

# Each event has a RE for extracting data and a lambda for encoding it (from ARCUS)
disasm_events = {
    'buffer':  (re.compile('^buffer: pid=([0-9]+), size=([0-9a-f]+)'),
                lambda x: (int(x[0], 10), int(x[1], 16))),
    'block':   (re.compile('^  block: ([0-9a-f]+)'),
                lambda x: int(x[0], 16)),
    'process': (re.compile('^process: tgid=([0-9]+), cmd=(.*)'),
                lambda x: (int(x[0], 10), x[1])),
    'thread':  (re.compile('^thread: tgid=([0-9]+), pid=([0-9]+)'),
                lambda x: (int(x[0], 10), int(x[1], 10))),
    'syscall': (re.compile('^  syscall: ([0-9a-f]+)'),
                lambda x: int(x[0], 16)),
    'audit':   (re.compile('^audit: sid=([0-9]+), timestamp=(.*), pid=([0-9]+)'),
                lambda x: (system_calls[int(x[0])], x[1], int(x[2], 10))),
    'image':   (re.compile('^image: tgid=([0-9]+), base=([0-9a-f]+), size=([0-9a-f]+), name=(.*)'),
                lambda x: (int(x[0], 10), int(x[1], 16), int(x[2], 16), x[3])),
    'xpage':   (re.compile('^xpage: tgid=([0-9]+), base=([0-9a-f]+), size=([0-9a-f]+)'),
                lambda x: (int(x[0], 10), int(x[1], 16), int(x[2], 16))),
}

def traverse_bin(trace_dir:str):
    """traverse /bin in trace dir
    
    Attributes:
        trace_dir -- trace dir

    Returns:
        bin_addr -- a list of binary [address, name] sorted by addresses
    """
    bin_dir = os.path.join(trace_dir, 'bin')
    if not os.path.isdir(bin_dir):
        raise Exception("Cannot find bins", bin_dir)

    bin_addr = []
    for _, _, files in os.walk(bin_dir):
        for file in files:
            tokens = file.split('-')
            bin_addr.append([int(tokens[0], 16), tokens[1]])

    bin_addr.sort(key = lambda bin_addr: bin_addr[0], reverse=True)

    return bin_addr

def decode(pt_path:str, trace_dir:str, disasm:str):
    """Decode trace using xed's pt
    
    tool/pt/pt is designed by Griffin to parses pt trace: extract buffer, syscall...

    Attributes:
        pt_path -- file path for tool/pt/pt
        event -- pt log items
        trace_dir -- file path for pt trace
        disasm -- xed (0) or distorm (1) for disassmble PT trace

    Returns:
        A list of parsed pt events:
            ['block', 0x7f781302de90],
            ['process', (2157, 'a.out')],
            ['syscall': 0x7f781302c497]
    """
    if not os.path.isfile(pt_path):
        raise Exception("Cannot find pt", pt_path)

    if not os.path.isdir(trace_dir):
        raise Exception("Cannot find trace", trace_dir)

    trace_path = os.path.join(trace_dir, 'trace.file')
    if not os.path.isfile(trace_path) or os.path.getsize(trace_path) == 0:
        trace_path = os.path.join(trace_dir, 'trace.memory')
        if not os.path.isfile(trace_path):
            raise Exception("Cannot find trace", trace_path)
        elif os.path.getsize(trace_path) == 0:
            raise Exception("no valid trace in ", trace_dir)

    # use pt to parse trace
    command = [pt_path, trace_path, disasm]
    pt = subprocess.Popen(args=command, stdout=subprocess.PIPE)

    # parsers to different pt log items
    buffer_regex, buffer_encoder = disasm_events['buffer']
    block_regex, block_encoder = disasm_events['block']
    process_regex, process_encoder = disasm_events['process']
    thread_regex, thread_encoder = disasm_events['thread']
    syscall_regex, syscall_encoder = disasm_events['syscall']
    audit_regex, audit_encoder = disasm_events['audit']
    image_regex, image_encoder = disasm_events['image']
    xpage_regex, xpage_encoder = disasm_events['xpage']

    for line in pt.stdout:
        event = line.decode('UTF-8')
        if res := buffer_regex.match(event):
            yield(['buffer', buffer_encoder(res.groups())])
            pass
        if res := block_regex.match(event):
            yield(['block', block_encoder(res.groups())])
            pass
        elif res := process_regex.match(event):
            yield(['process', process_encoder(res.groups())])
            pass
        elif res := thread_regex.match(event):
            yield(['thread', thread_encoder(res.groups())])
            pass
        elif res := syscall_regex.match(event):
            yield(['syscall', syscall_encoder(res.groups())])
            pass
        if res := audit_regex.match(event):
            yield(['audit', audit_encoder(res.groups())])
            pass
        if res := image_regex.match(event):
            # yield(['image', image_encoder(res.groups())])
            pass
        if res := xpage_regex.match(event):
            # yield(['xpage', xpage_encoder(res.groups())])
            pass
        else:
            pass

    pt.wait()

def to_offset(addr: int, bin_addr: list):
    """concert block address to offset + binary
    
    Attributes:
        addr -- block virtual memory address
        bin_addr -- a list of binary [address, name] sorted by addresses

    Returns:
        offset -- offset address and name
    """
    for base, name in bin_addr:
        if addr > base:
            return addr -base, name
    
    raise Exception("Cannot parse offset", addr)

def print_events(parsed_events: list, trace_dir: str):
    """print events parsed from PT trace 
    
    parsed_events -- a list of parsed pt events:
    trace_dir -- file path for pt trace
    """
    bin_addr = traverse_bin(trace_dir)

    for type, content in parsed_events:
        if type == 'buffer':
            print(type, content[0], hex(content[1]))
            pass
        elif type == 'block':
            offset, name = to_offset(content, bin_addr)
            print(type, hex(content), hex(offset), name)
            pass
        elif type == 'process':
            print(type, content[0], content[1])
            pass
        elif type == 'thread':
            print(type, content[0], content[1])
            pass
        elif type == 'syscall':
            offset, name = to_offset(content, bin_addr)
            print(type, hex(content), hex(offset), name)
            pass
        elif type == 'audit':
            print(type, content[0], content[1], content[2])
            pass
        elif type == 'image':
            print(type, content[0], hex(content[1]), hex(content[2]), content[3])
            pass
        elif type == 'xpage':
            print(type, content[0], hex(content[1]), hex(content[2]))
            pass
        else:
            pass

def main():
    args = parse_args()

    pt_path = args.pt_path
    trace_dir = args.trace_dir
    disasm = args.disasm
    
    parsed_events = decode(pt_path, trace_dir, disasm)

    print_events(parsed_events, trace_dir)

if __name__ == "__main__":
    main()