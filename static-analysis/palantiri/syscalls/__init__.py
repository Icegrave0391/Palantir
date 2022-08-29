syscall_analysis_table = {
    0: "read", 1: "write", 2: "open", 3: "close",
    9: "mmap",    16: "ioctl",
    17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 22: "pipe", 32: "dup",
    33: "dup2", 40: "sendfile", 41: "socket", 42: "connect",
    43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    47: "recvmsg", 49: "bind", 50: "listen", 52: "getpeername",
    57: "fork", 58: "vfork", 59: "execve", 62: "kill",
    73: "fcntl", 82: "rename", 83: "mkdir", 84: "rmdir",
    86: "link", 87: "unlink", 220: "clone", 240: "mq_open",
    257: "openat", 263: "unlinkat", 265: "linkat", 293: "pipe2",
    297: "recvmsg", 299: "recvmmsg", 307: "sendmmsg",
}

# a rough classification for cfg trimming
syscall_to_functions = {
    "read": ["read", "fgets", "fread", "fread_unlocked", "readv", "pread64", "mmap", "file_bucket_read",
             "_IO_getc"],
    "write": ["write", "fputs", "fwrite", "fputc", "writev",
              # apache httpd special procs
              "apr_socket_sendv"],

    "open": ["fopen", "open", "fdopen", "openat"],
    "close": ["fclose", "close"],
    "mq_open": ["mq_open"],
    "mmap": ["malloc", "calloc", "realloc", "mmap"],

    "socket": ["socket", "bind", "listen", "accept"],
    "connect": ["connect"],

    "send": ["gnutls_record_send", "send", "sendmsg", "sendmmsg", "sendto", "sendfile64"],
    "recv": ["gnutls_record_recv", "recv", "recvmsg", "recvmmsg"],
    "memory": ["strcpy", "memcpy", "sprintf"],
    "fork": ["fork", "vfork", "execve"],
    "clone": ["clone"],
    "kill": ["kill"],
    "dup": ["dup", "dup2"],
    "pipe": ["pipe", "pipe2"],
}


SYSCALL_TO_PLT_TABLE = {
    "read": ("read", "fgets", "fread", "file_bucket_read", "_IO_getc"),
    "mmap": ("mmap", "file_bucket_read"),
    "pread64": ("pread64",),
    "write": ("write", "fputs", "fwrite"),
    "writev": ("writev", "apr_socket_sendv"),
    "readv": ("readv",),
    "recvfrom": ("recv", "gnutls_record_recv", "recvfrom", "recvmsg")
}


def plt_function_to_syscall(plt_func_name: str):
    for sys_name, plt_list in SYSCALL_TO_PLT_TABLE.items():
        if plt_func_name in plt_list:
            return sys_name
    return None