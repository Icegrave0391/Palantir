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

std::string Jval2str(const Json::Value jval) {
	Json::FastWriter fastWriter;
	std::string tmp = fastWriter.write(jval);
	if (tmp[0] == '\"') {
		return tmp.substr(1, tmp.rfind("\"") - 1);
	}
	else {
		return tmp.substr(0, tmp.rfind("\n"));
	}
}

biguint_t stoint128_t(std::string const & in) {
    biguint_t res = 0;
    for (size_t i = 0; i < in.size() - 1; ++i) {
        const char c = in[i];
        if (not std::isdigit(c)) {
			std::cerr << "Non-numeric character: " << in << " "<< __FILE__ << " "<<  __LINE__ << std::endl << std::endl;
            throw std::runtime_error(std::string("Non-numeric character: ") + c);
		}
        res *= 10;
        res += c - '0';
    }
    return res;
}

biguint_t Jval2int(const Json::Value jval) { 
	Json::FastWriter fastWriter;
	std::string tmp = fastWriter.write(jval);
	return (biguint_t)stoint128_t(tmp);
}

Common::Common() {
    syscall_map["read"] = SyscallType_t::READ;
    syscall_map["write"] = SyscallType_t::WRITE;
    syscall_map["open"] = SyscallType_t::OPEN;
    syscall_map["close"] = SyscallType_t::CLOSE;
    syscall_map["stat"] = SyscallType_t::STAT;
    syscall_map["fstat"] = SyscallType_t::FSTAT;
    syscall_map["lstat"] = SyscallType_t::LSTAT;
    syscall_map["poll"] = SyscallType_t::POLL;
    syscall_map["lseek"] = SyscallType_t::LSEEK;
    syscall_map["mmap"] = SyscallType_t::MMAP;
    syscall_map["mprotect"] = SyscallType_t::MPROTECT;
    syscall_map["munmap"] = SyscallType_t::MUNMAP;
    syscall_map["brk"] = SyscallType_t::BRK;
    syscall_map["rt_sigaction"] = SyscallType_t::RT_SIGACTION;
    syscall_map["rt_sigprocmask"] = SyscallType_t::RT_SIGPROCMASK;
    syscall_map["rt_sigreturn"] = SyscallType_t::RT_SIGRETURN;
    syscall_map["ioctl"] = SyscallType_t::IOCTL;
    syscall_map["pread"] = SyscallType_t::PREAD;
    syscall_map["pwrite"] = SyscallType_t::PWRITE;
    syscall_map["readv"] = SyscallType_t::READV;
    syscall_map["writev"] = SyscallType_t::WRITEV;
    syscall_map["access"] = SyscallType_t::ACCESS;
    syscall_map["pipe"] = SyscallType_t::PIPE;
    syscall_map["select"] = SyscallType_t::SELECT;
    syscall_map["sched_yield"] = SyscallType_t::SCHED_YIELD;
    syscall_map["mremap"] = SyscallType_t::MREMAP;
    syscall_map["msync"] = SyscallType_t::MSYNC;
    syscall_map["mincore"] = SyscallType_t::MINCORE;
    syscall_map["madvise"] = SyscallType_t::MADVISE;
    syscall_map["shmget"] = SyscallType_t::SHMGET;
    syscall_map["shmat"] = SyscallType_t::SHMAT;
    syscall_map["shmctl"] = SyscallType_t::SHMCTL;
    syscall_map["dup"] = SyscallType_t::DUP;
    syscall_map["dup2"] = SyscallType_t::DUP2;
    syscall_map["pause"] = SyscallType_t::PAUSE;
    syscall_map["nanosleep"] = SyscallType_t::NANOSLEEP;
    syscall_map["getitimer"] = SyscallType_t::GETITIMER;
    syscall_map["alarm"] = SyscallType_t::ALARM;
    syscall_map["setitimer"] = SyscallType_t::SETITIMER;
    syscall_map["getpid"] = SyscallType_t::GETPID;
    syscall_map["sendfile"] = SyscallType_t::SENDFILE;
    syscall_map["socket"] = SyscallType_t::SOCKET;
    syscall_map["connect"] = SyscallType_t::CONNECT;
    syscall_map["accept"] = SyscallType_t::ACCEPT;
    syscall_map["sendto"] = SyscallType_t::SENDTO;
    syscall_map["recvfrom"] = SyscallType_t::RECVFROM;
    syscall_map["sendmsg"] = SyscallType_t::SENDMSG;
    syscall_map["recvmsg"] = SyscallType_t::RECVMSG;
    syscall_map["shutdown"] = SyscallType_t::SHUTDOWN;
    syscall_map["bind"] = SyscallType_t::BIND;
    syscall_map["listen"] = SyscallType_t::LISTEN;
    syscall_map["getsockname"] = SyscallType_t::GETSOCKNAME;
    syscall_map["getpeername"] = SyscallType_t::GETPEERNAME;
    syscall_map["socketpair"] = SyscallType_t::SOCKETPAIR;
    syscall_map["setsockopt"] = SyscallType_t::SETSOCKOPT;
    syscall_map["getsockopt"] = SyscallType_t::GETSOCKOPT;
    syscall_map["clone"] = SyscallType_t::CLONE;
    syscall_map["fork"] = SyscallType_t::FORK;
    syscall_map["vfork"] = SyscallType_t::VFORK;
    syscall_map["execve"] = SyscallType_t::EXECVE;
    syscall_map["exit"] = SyscallType_t::EXIT;
    syscall_map["wait4"] = SyscallType_t::WAIT4;
    syscall_map["kill"] = SyscallType_t::KILL;
    syscall_map["uname"] = SyscallType_t::UNAME;
    syscall_map["semget"] = SyscallType_t::SEMGET;
    syscall_map["semop"] = SyscallType_t::SEMOP;
    syscall_map["semctl"] = SyscallType_t::SEMCTL;
    syscall_map["shmdt"] = SyscallType_t::SHMDT;
    syscall_map["msgget"] = SyscallType_t::MSGGET;
    syscall_map["msgsnd"] = SyscallType_t::MSGSND;
    syscall_map["msgrcv"] = SyscallType_t::MSGRCV;
    syscall_map["msgctl"] = SyscallType_t::MSGCTL;
    syscall_map["fcntl"] = SyscallType_t::FCNTL;
    syscall_map["flock"] = SyscallType_t::FLOCK;
    syscall_map["fsync"] = SyscallType_t::FSYNC;
    syscall_map["fdatasync"] = SyscallType_t::FDATASYNC;
    syscall_map["truncate"] = SyscallType_t::TRUNCATE;
    syscall_map["ftruncate"] = SyscallType_t::FTRUNCATE;
    syscall_map["getdents"] = SyscallType_t::GETDENTS;
    syscall_map["getcwd"] = SyscallType_t::GETCWD;
    syscall_map["chdir"] = SyscallType_t::CHDIR;
    syscall_map["fchdir"] = SyscallType_t::FCHDIR;
    syscall_map["rename"] = SyscallType_t::RENAME;
    syscall_map["mkdir"] = SyscallType_t::MKDIR;
    syscall_map["rmdir"] = SyscallType_t::RMDIR;
    syscall_map["creat"] = SyscallType_t::CREAT;
    syscall_map["link"] = SyscallType_t::LINK;
    syscall_map["unlink"] = SyscallType_t::UNLINK;
    syscall_map["symlink"] = SyscallType_t::SYMLINK;
    syscall_map["readlink"] = SyscallType_t::READLINK;
    syscall_map["chmod"] = SyscallType_t::CHMOD;
    syscall_map["fchmod"] = SyscallType_t::FCHMOD;
    syscall_map["chown"] = SyscallType_t::CHOWN;
    syscall_map["fchown"] = SyscallType_t::FCHOWN;
    syscall_map["lchown"] = SyscallType_t::LCHOWN;
    syscall_map["umask"] = SyscallType_t::UMASK;
    syscall_map["gettimeofday"] = SyscallType_t::GETTIMEOFDAY;
    syscall_map["getrlimit"] = SyscallType_t::GETRLIMIT;
    syscall_map["getrusage"] = SyscallType_t::GETRUSAGE;
    syscall_map["sysinfo"] = SyscallType_t::SYSINFO;
    syscall_map["times"] = SyscallType_t::TIMES;
    syscall_map["ptrace"] = SyscallType_t::PTRACE;
    syscall_map["getuid"] = SyscallType_t::GETUID;
    syscall_map["syslog"] = SyscallType_t::SYSLOG;
    syscall_map["getgid"] = SyscallType_t::GETGID;
    syscall_map["setuid"] = SyscallType_t::SETUID;
    syscall_map["setgid"] = SyscallType_t::SETGID;
    syscall_map["geteuid"] = SyscallType_t::GETEUID;
    syscall_map["getegid"] = SyscallType_t::GETEGID;
    syscall_map["setpgid"] = SyscallType_t::SETPGID;
    syscall_map["getppid"] = SyscallType_t::GETPPID;
    syscall_map["getpgrp"] = SyscallType_t::GETPGRP;
    syscall_map["setsid"] = SyscallType_t::SETSID;
    syscall_map["setreuid"] = SyscallType_t::SETREUID;
    syscall_map["setregid"] = SyscallType_t::SETREGID;
    syscall_map["getgroups"] = SyscallType_t::GETGROUPS;
    syscall_map["setgroups"] = SyscallType_t::SETGROUPS;
    syscall_map["setresuid"] = SyscallType_t::SETRESUID;
    syscall_map["getresuid"] = SyscallType_t::GETRESUID;
    syscall_map["setresgid"] = SyscallType_t::SETRESGID;
    syscall_map["getresgid"] = SyscallType_t::GETRESGID;
    syscall_map["getpgid"] = SyscallType_t::GETPGID;
    syscall_map["setfsuid"] = SyscallType_t::SETFSUID;
    syscall_map["setfsgid"] = SyscallType_t::SETFSGID;
    syscall_map["getsid"] = SyscallType_t::GETSID;
    syscall_map["capget"] = SyscallType_t::CAPGET;
    syscall_map["capset"] = SyscallType_t::CAPSET;
    syscall_map["rt_sigpending"] = SyscallType_t::RT_SIGPENDING;
    syscall_map["rt_sigtimedwait"] = SyscallType_t::RT_SIGTIMEDWAIT;
    syscall_map["rt_sigqueueinfo"] = SyscallType_t::RT_SIGQUEUEINFO;
    syscall_map["rt_sigsuspend"] = SyscallType_t::RT_SIGSUSPEND;
    syscall_map["sigaltstack"] = SyscallType_t::SIGALTSTACK;
    syscall_map["utime"] = SyscallType_t::UTIME;
    syscall_map["mknod"] = SyscallType_t::MKNOD;
    syscall_map["uselib"] = SyscallType_t::USELIB;
    syscall_map["personality"] = SyscallType_t::PERSONALITY;
    syscall_map["ustat"] = SyscallType_t::USTAT;
    syscall_map["statfs"] = SyscallType_t::STATFS;
    syscall_map["fstatfs"] = SyscallType_t::FSTATFS;
    syscall_map["sysfs"] = SyscallType_t::SYSFS;
    syscall_map["getpriority"] = SyscallType_t::GETPRIORITY;
    syscall_map["setpriority"] = SyscallType_t::SETPRIORITY;
    syscall_map["sched_setparam"] = SyscallType_t::SCHED_SETPARAM;
    syscall_map["sched_getparam"] = SyscallType_t::SCHED_GETPARAM;
    syscall_map["sched_setscheduler"] = SyscallType_t::SCHED_SETSCHEDULER;
    syscall_map["sched_getscheduler"] = SyscallType_t::SCHED_GETSCHEDULER;
    syscall_map["sched_get_priority_max"] = SyscallType_t::SCHED_GET_PRIORITY_MAX;
    syscall_map["sched_get_priority_min"] = SyscallType_t::SCHED_GET_PRIORITY_MIN;
    syscall_map["sched_rr_get_interval"] = SyscallType_t::SCHED_RR_GET_INTERVAL;
    syscall_map["mlock"] = SyscallType_t::MLOCK;
    syscall_map["munlock"] = SyscallType_t::MUNLOCK;
    syscall_map["mlockall"] = SyscallType_t::MLOCKALL;
    syscall_map["munlockall"] = SyscallType_t::MUNLOCKALL;
    syscall_map["vhangup"] = SyscallType_t::VHANGUP;
    syscall_map["modify_ldt"] = SyscallType_t::MODIFY_LDT;
    syscall_map["pivot_root"] = SyscallType_t::PIVOT_ROOT;
    syscall_map["_sysctl"] = SyscallType_t::_SYSCTL;
    syscall_map["prctl"] = SyscallType_t::PRCTL;
    syscall_map["arch_prctl"] = SyscallType_t::ARCH_PRCTL;
    syscall_map["adjtimex"] = SyscallType_t::ADJTIMEX;
    syscall_map["setrlimit"] = SyscallType_t::SETRLIMIT;
    syscall_map["chroot"] = SyscallType_t::CHROOT;
    syscall_map["sync"] = SyscallType_t::SYNC;
    syscall_map["acct"] = SyscallType_t::ACCT;
    syscall_map["settimeofday"] = SyscallType_t::SETTIMEOFDAY;
    syscall_map["mount"] = SyscallType_t::MOUNT;
    syscall_map["umount2"] = SyscallType_t::UMOUNT2;
    syscall_map["swapon"] = SyscallType_t::SWAPON;
    syscall_map["swapoff"] = SyscallType_t::SWAPOFF;
    syscall_map["reboot"] = SyscallType_t::REBOOT;
    syscall_map["sethostname"] = SyscallType_t::SETHOSTNAME;
    syscall_map["setdomainname"] = SyscallType_t::SETDOMAINNAME;
    syscall_map["iopl"] = SyscallType_t::IOPL;
    syscall_map["ioperm"] = SyscallType_t::IOPERM;
    syscall_map["create_module"] = SyscallType_t::CREATE_MODULE;
    syscall_map["init_module"] = SyscallType_t::INIT_MODULE;
    syscall_map["delete_module"] = SyscallType_t::DELETE_MODULE;
    syscall_map["get_kernel_syms"] = SyscallType_t::GET_KERNEL_SYMS;
    syscall_map["query_module"] = SyscallType_t::QUERY_MODULE;
    syscall_map["quotactl"] = SyscallType_t::QUOTACTL;
    syscall_map["nfsservctl"] = SyscallType_t::NFSSERVCTL;
    syscall_map["getpmsg"] = SyscallType_t::GETPMSG;
    syscall_map["putpmsg"] = SyscallType_t::PUTPMSG;
    syscall_map["afs_syscall"] = SyscallType_t::AFS_SYSCALL;
    syscall_map["tuxcall"] = SyscallType_t::TUXCALL;
    syscall_map["security"] = SyscallType_t::SECURITY;
    syscall_map["gettid"] = SyscallType_t::GETTID;
    syscall_map["readahead"] = SyscallType_t::READAHEAD;
    syscall_map["setxattr"] = SyscallType_t::SETXATTR;
    syscall_map["lsetxattr"] = SyscallType_t::LSETXATTR;
    syscall_map["fsetxattr"] = SyscallType_t::FSETXATTR;
    syscall_map["getxattr"] = SyscallType_t::GETXATTR;
    syscall_map["lgetxattr"] = SyscallType_t::LGETXATTR;
    syscall_map["fgetxattr"] = SyscallType_t::FGETXATTR;
    syscall_map["listxattr"] = SyscallType_t::LISTXATTR;
    syscall_map["llistxattr"] = SyscallType_t::LLISTXATTR;
    syscall_map["flistxattr"] = SyscallType_t::FLISTXATTR;
    syscall_map["removexattr"] = SyscallType_t::REMOVEXATTR;
    syscall_map["lremovexattr"] = SyscallType_t::LREMOVEXATTR;
    syscall_map["fremovexattr"] = SyscallType_t::FREMOVEXATTR;
    syscall_map["tkill"] = SyscallType_t::TKILL;
    syscall_map["time"] = SyscallType_t::TIME;
    syscall_map["futex"] = SyscallType_t::FUTEX;
    syscall_map["sched_setaffinity"] = SyscallType_t::SCHED_SETAFFINITY;
    syscall_map["sched_getaffinity"] = SyscallType_t::SCHED_GETAFFINITY;
    syscall_map["set_thread_area"] = SyscallType_t::SET_THREAD_AREA;
    syscall_map["io_setup"] = SyscallType_t::IO_SETUP;
    syscall_map["io_destroy"] = SyscallType_t::IO_DESTROY;
    syscall_map["io_getevents"] = SyscallType_t::IO_GETEVENTS;
    syscall_map["io_submit"] = SyscallType_t::IO_SUBMIT;
    syscall_map["io_cancel"] = SyscallType_t::IO_CANCEL;
    syscall_map["get_thread_area"] = SyscallType_t::GET_THREAD_AREA;
    syscall_map["lookup_dcookie"] = SyscallType_t::LOOKUP_DCOOKIE;
    syscall_map["epoll_create"] = SyscallType_t::EPOLL_CREATE;
    syscall_map["epoll_ctl_old"] = SyscallType_t::EPOLL_CTL_OLD;
    syscall_map["epoll_wait_old"] = SyscallType_t::EPOLL_WAIT_OLD;
    syscall_map["remap_file_pages"] = SyscallType_t::REMAP_FILE_PAGES;
    syscall_map["getdents64"] = SyscallType_t::GETDENTS64;
    syscall_map["set_tid_address"] = SyscallType_t::SET_TID_ADDRESS;
    syscall_map["restart_syscall"] = SyscallType_t::RESTART_SYSCALL;
    syscall_map["semtimedop"] = SyscallType_t::SEMTIMEDOP;
    syscall_map["fadvise64"] = SyscallType_t::FADVISE64;
    syscall_map["timer_create"] = SyscallType_t::TIMER_CREATE;
    syscall_map["timer_settime"] = SyscallType_t::TIMER_SETTIME;
    syscall_map["timer_gettime"] = SyscallType_t::TIMER_GETTIME;
    syscall_map["timer_getoverrun"] = SyscallType_t::TIMER_GETOVERRUN;
    syscall_map["timer_delete"] = SyscallType_t::TIMER_DELETE;
    syscall_map["clock_settime"] = SyscallType_t::CLOCK_SETTIME;
    syscall_map["clock_gettime"] = SyscallType_t::CLOCK_GETTIME;
    syscall_map["clock_getres"] = SyscallType_t::CLOCK_GETRES;
    syscall_map["clock_nanosleep"] = SyscallType_t::CLOCK_NANOSLEEP;
    syscall_map["exit_group"] = SyscallType_t::EXIT_GROUP;
    syscall_map["epoll_wait"] = SyscallType_t::EPOLL_WAIT;
    syscall_map["epoll_ctl"] = SyscallType_t::EPOLL_CTL;
    syscall_map["tgkill"] = SyscallType_t::TGKILL;
    syscall_map["utimes"] = SyscallType_t::UTIMES;
    syscall_map["vserver"] = SyscallType_t::VSERVER;
    syscall_map["mbind"] = SyscallType_t::MBIND;
    syscall_map["set_mempolicy"] = SyscallType_t::SET_MEMPOLICY;
    syscall_map["get_mempolicy"] = SyscallType_t::GET_MEMPOLICY;
    syscall_map["mq_open"] = SyscallType_t::MQ_OPEN;
    syscall_map["mq_unlink"] = SyscallType_t::MQ_UNLINK;
    syscall_map["mq_timedsend"] = SyscallType_t::MQ_TIMEDSEND;
    syscall_map["mq_timedreceive"] = SyscallType_t::MQ_TIMEDRECEIVE;
    syscall_map["mq_notify"] = SyscallType_t::MQ_NOTIFY;
    syscall_map["mq_getsetattr"] = SyscallType_t::MQ_GETSETATTR;
    syscall_map["kexec_load"] = SyscallType_t::KEXEC_LOAD;
    syscall_map["waitid"] = SyscallType_t::WAITID;
    syscall_map["add_key"] = SyscallType_t::ADD_KEY;
    syscall_map["request_key"] = SyscallType_t::REQUEST_KEY;
    syscall_map["keyctl"] = SyscallType_t::KEYCTL;
    syscall_map["ioprio_set"] = SyscallType_t::IOPRIO_SET;
    syscall_map["ioprio_get"] = SyscallType_t::IOPRIO_GET;
    syscall_map["inotify_init"] = SyscallType_t::INOTIFY_INIT;
    syscall_map["inotify_add_watch"] = SyscallType_t::INOTIFY_ADD_WATCH;
    syscall_map["inotify_rm_watch"] = SyscallType_t::INOTIFY_RM_WATCH;
    syscall_map["migrate_pages"] = SyscallType_t::MIGRATE_PAGES;
    syscall_map["openat"] = SyscallType_t::OPENAT;
    syscall_map["mkdirat"] = SyscallType_t::MKDIRAT;
    syscall_map["mknodat"] = SyscallType_t::MKNODAT;
    syscall_map["fchownat"] = SyscallType_t::FCHOWNAT;
    syscall_map["futimesat"] = SyscallType_t::FUTIMESAT;
    syscall_map["newfstatat"] = SyscallType_t::NEWFSTATAT;
    syscall_map["unlinkat"] = SyscallType_t::UNLINKAT;
    syscall_map["renameat"] = SyscallType_t::RENAMEAT;
    syscall_map["linkat"] = SyscallType_t::LINKAT;
    syscall_map["symlinkat"] = SyscallType_t::SYMLINKAT;
    syscall_map["readlinkat"] = SyscallType_t::READLINKAT;
    syscall_map["fchmodat"] = SyscallType_t::FCHMODAT;
    syscall_map["faccessat"] = SyscallType_t::FACCESSAT;
    syscall_map["pselect6"] = SyscallType_t::PSELECT6;
    syscall_map["ppoll"] = SyscallType_t::PPOLL;
    syscall_map["unshare"] = SyscallType_t::UNSHARE;
    syscall_map["set_robust_list"] = SyscallType_t::SET_ROBUST_LIST;
    syscall_map["get_robust_list"] = SyscallType_t::GET_ROBUST_LIST;
    syscall_map["splice"] = SyscallType_t::SPLICE;
    syscall_map["tee"] = SyscallType_t::TEE;
    syscall_map["sync_file_range"] = SyscallType_t::SYNC_FILE_RANGE;
    syscall_map["vmsplice"] = SyscallType_t::VMSPLICE;
    syscall_map["move_pages"] = SyscallType_t::MOVE_PAGES;
    syscall_map["utimensat"] = SyscallType_t::UTIMENSAT;
    syscall_map["epoll_pwait"] = SyscallType_t::EPOLL_PWAIT;
    syscall_map["signalfd"] = SyscallType_t::SIGNALFD;
    syscall_map["timerfd"] = SyscallType_t::TIMERFD;
    syscall_map["eventfd"] = SyscallType_t::EVENTFD;
    syscall_map["fallocate"] = SyscallType_t::FALLOCATE;
    syscall_map["timerfd_settime"] = SyscallType_t::TIMERFD_SETTIME;
    syscall_map["timerfd_gettime"] = SyscallType_t::TIMERFD_GETTIME;
    syscall_map["accept4"] = SyscallType_t::ACCEPT4;
    syscall_map["signalfd4"] = SyscallType_t::SIGNALFD4;
    syscall_map["eventfd2"] = SyscallType_t::EVENTFD2;
    syscall_map["epoll_create1"] = SyscallType_t::EPOLL_CREATE1;
    syscall_map["dup3"] = SyscallType_t::DUP3;
    syscall_map["pipe2"] = SyscallType_t::PIPE2;
    syscall_map["inotify_init1"] = SyscallType_t::INOTIFY_INIT1;
    syscall_map["preadv"] = SyscallType_t::PREADV;
    syscall_map["pwritev"] = SyscallType_t::PWRITEV;
    syscall_map["rt_tgsigqueueinfo"] = SyscallType_t::RT_TGSIGQUEUEINFO;
    syscall_map["perf_event_open"] = SyscallType_t::PERF_EVENT_OPEN;
    syscall_map["recvmmsg"] = SyscallType_t::RECVMMSG;
    syscall_map["fanotify_init"] = SyscallType_t::FANOTIFY_INIT;
    syscall_map["fanotify_mark"] = SyscallType_t::FANOTIFY_MARK;
    syscall_map["prlimit64"] = SyscallType_t::PRLIMIT64;
    syscall_map["name_to_handle_at"] = SyscallType_t::NAME_TO_HANDLE_AT;
    syscall_map["open_by_handle_at"] = SyscallType_t::OPEN_BY_HANDLE_AT;
    syscall_map["clock_adjtime"] = SyscallType_t::CLOCK_ADJTIME;
    syscall_map["syncfs"] = SyscallType_t::SYNCFS;
    syscall_map["sendmmsg"] = SyscallType_t::SENDMMSG;
    syscall_map["setns"] = SyscallType_t::SETNS;
    syscall_map["getcpu"] = SyscallType_t::GETCPU;
    syscall_map["process_vm_readv"] = SyscallType_t::PROCESS_VM_READV;
    syscall_map["process_vm_writev"] = SyscallType_t::PROCESS_VM_WRITEV;
    syscall_map["kcmp"] = SyscallType_t::KCMP;
    syscall_map["finit_module"] = SyscallType_t::FINIT_MODULE;
    syscall_map["sched_setattr"] = SyscallType_t::SCHED_SETATTR;
    syscall_map["sched_getattr"] = SyscallType_t::SCHED_GETATTR;
    syscall_map["renameat2"] = SyscallType_t::RENAMEAT2;
    syscall_map["seccomp"] = SyscallType_t::SECCOMP;
    syscall_map["getrandom"] = SyscallType_t::GETRANDOM;
    syscall_map["memfd_create"] = SyscallType_t::MEMFD_CREATE;
    syscall_map["kexec_file_load"] = SyscallType_t::KEXEC_FILE_LOAD;
    syscall_map["bpf"] = SyscallType_t::BPF;
    syscall_map["execveat"] = SyscallType_t::EXECVEAT;
    syscall_map["userfaultfd"] = SyscallType_t::USERFAULTFD;
    syscall_map["membarrier"] = SyscallType_t::MEMBARRIER;
    syscall_map["mlock2"] = SyscallType_t::MLOCK2;
    syscall_map["copy_file_range"] = SyscallType_t::COPY_FILE_RANGE;
    syscall_map["preadv2"] = SyscallType_t::PREADV2;
    syscall_map["pwritev2"] = SyscallType_t::PWRITEV2;
    syscall_map["pkey_mprotect"] = SyscallType_t::PKEY_MPROTECT;
    syscall_map["pkey_alloc"] = SyscallType_t::PKEY_ALLOC;
    syscall_map["pkey_free"] = SyscallType_t::PKEY_FREE;
    syscall_map["statx"] = SyscallType_t::STATX;
    syscall_map["io_pgetevents"] = SyscallType_t::IO_PGETEVENTS;
    syscall_map["rseq"] = SyscallType_t::RSEQ;
}

Common::~Common() {

}

int Common::syscallname2id(std::string syscall_name) {
    switch(syscall_map[syscall_name]) {
        case SyscallType_t::READ: {
	        return 0;
        }
        case SyscallType_t::WRITE: {
            return 1;
        }
        case SyscallType_t::OPEN: {
            return 2;
        }
        case SyscallType_t::CLOSE: {
            return 3;
        }
        case SyscallType_t::STAT: {
            return 4;
        }
        case SyscallType_t::FSTAT: {
            return 5;
        }
        case SyscallType_t::LSTAT: {
            return 6;
        }
        case SyscallType_t::POLL: {
            return 7;
        }
        case SyscallType_t::LSEEK: {
            return 8;
        }
        case SyscallType_t::MMAP: {
            return 9;
        }
        case SyscallType_t::MPROTECT: {
            return 10;
        }
        case SyscallType_t::MUNMAP: {
            return 11;
        }
        case SyscallType_t::BRK: {
            return 12;
        }
        case SyscallType_t::RT_SIGACTION: {
            return 13;
        }
        case SyscallType_t::RT_SIGPROCMASK: {
            return 14;
        }
        case SyscallType_t::RT_SIGRETURN: {
            return 15;
        }
        case SyscallType_t::IOCTL: {
            return 16;
        }
        case SyscallType_t::PREAD: {
            return 17;
        }
        case SyscallType_t::PWRITE: {
            return 18;
        }
        case SyscallType_t::READV: {
            return 19;
        }
        case SyscallType_t::WRITEV: {
            return 20;
        }
        case SyscallType_t::ACCESS: {
            return 21;
        }
        case SyscallType_t::PIPE: {
            return 22;
        }
        case SyscallType_t::SELECT: {
            return 23;
        }
        case SyscallType_t::SCHED_YIELD: {
            return 24;
        }
        case SyscallType_t::MREMAP: {
            return 25;
        }
        case SyscallType_t::MSYNC: {
            return 26;
        }
        case SyscallType_t::MINCORE: {
            return 27;
        }
        case SyscallType_t::MADVISE: {
            return 28;
        }
        case SyscallType_t::SHMGET: {
            return 29;
        }
        case SyscallType_t::SHMAT: {
            return 30;
        }
        case SyscallType_t::SHMCTL: {
            return 31;
        }
        case SyscallType_t::DUP: {
            return 32;
        }
        case SyscallType_t::DUP2: {
            return 33;
        }
        case SyscallType_t::PAUSE: {
            return 34;
        }
        case SyscallType_t::NANOSLEEP: {
            return 35;
        }
        case SyscallType_t::GETITIMER: {
            return 36;
        }
        case SyscallType_t::ALARM: {
            return 37;
        }
        case SyscallType_t::SETITIMER: {
            return 38;
        }
        case SyscallType_t::GETPID: {
            return 39;
        }
        case SyscallType_t::SENDFILE: {
            return 40;
        }
        case SyscallType_t::SOCKET: {
            return 41;
        }
        case SyscallType_t::CONNECT: {
            return 42;
        }
        case SyscallType_t::ACCEPT: {
            return 43;
        }
        case SyscallType_t::SENDTO: {
            return 44;
        }
        case SyscallType_t::RECVFROM: {
            return 45;
        }
        case SyscallType_t::SENDMSG: {
            return 46;
        }
        case SyscallType_t::RECVMSG: {
            return 47;
        }
        case SyscallType_t::SHUTDOWN: {
            return 48;
        }
        case SyscallType_t::BIND: {
            return 49;
        }
        case SyscallType_t::LISTEN: {
            return 50;
        }
        case SyscallType_t::GETSOCKNAME: {
            return 51;
        }
        case SyscallType_t::GETPEERNAME: {
            return 52;
        }
        case SyscallType_t::SOCKETPAIR: {
            return 53;
        }
        case SyscallType_t::SETSOCKOPT: {
            return 54;
        }
        case SyscallType_t::GETSOCKOPT: {
            return 55;
        }
        case SyscallType_t::CLONE: {
            return 56;
        }
        case SyscallType_t::FORK: {
            return 57;
        }
        case SyscallType_t::VFORK: {
            return 58;
        }
        case SyscallType_t::EXECVE: {
            return 59;
        }
        case SyscallType_t::EXIT: {
            return 60;
        }
        case SyscallType_t::WAIT4: {
            return 61;
        }
        case SyscallType_t::KILL: {
            return 62;
        }
        case SyscallType_t::UNAME: {
            return 63;
        }
        case SyscallType_t::SEMGET: {
            return 64;
        }
        case SyscallType_t::SEMOP: {
            return 65;
        }
        case SyscallType_t::SEMCTL: {
            return 66;
        }
        case SyscallType_t::SHMDT: {
            return 67;
        }
        case SyscallType_t::MSGGET: {
            return 68;
        }
        case SyscallType_t::MSGSND: {
            return 69;
        }
        case SyscallType_t::MSGRCV: {
            return 70;
        }
        case SyscallType_t::MSGCTL: {
            return 71;
        }
        case SyscallType_t::FCNTL: {
            return 72;
        }
        case SyscallType_t::FLOCK: {
            return 73;
        }
        case SyscallType_t::FSYNC: {
            return 74;
        }
        case SyscallType_t::FDATASYNC: {
            return 75;
        }
        case SyscallType_t::TRUNCATE: {
            return 76;
        }
        case SyscallType_t::FTRUNCATE: {
            return 77;
        }
        case SyscallType_t::GETDENTS: {
            return 78;
        }
        case SyscallType_t::GETCWD: {
            return 79;
        }
        case SyscallType_t::CHDIR: {
            return 80;
        }
        case SyscallType_t::FCHDIR: {
            return 81;
        }
        case SyscallType_t::RENAME: {
            return 82;
        }
        case SyscallType_t::MKDIR: {
            return 83;
        }
        case SyscallType_t::RMDIR: {
            return 84;
        }
        case SyscallType_t::CREAT: {
            return 85;
        }
        case SyscallType_t::LINK: {
            return 86;
        }
        case SyscallType_t::UNLINK: {
            return 87;
        }
        case SyscallType_t::SYMLINK: {
            return 88;
        }
        case SyscallType_t::READLINK: {
            return 89;
        }
        case SyscallType_t::CHMOD: {
            return 90;
        }
        case SyscallType_t::FCHMOD: {
            return 91;
        }
        case SyscallType_t::CHOWN: {
            return 92;
        }
        case SyscallType_t::FCHOWN: {
            return 93;
        }
        case SyscallType_t::LCHOWN: {
            return 94;
        }
        case SyscallType_t::UMASK: {
            return 95;
        }
        case SyscallType_t::GETTIMEOFDAY: {
            return 96;
        }
        case SyscallType_t::GETRLIMIT: {
            return 97;
        }
        case SyscallType_t::GETRUSAGE: {
            return 98;
        }
        case SyscallType_t::SYSINFO: {
            return 99;
        }
        case SyscallType_t::TIMES: {
            return 100;
        }
        case SyscallType_t::PTRACE: {
            return 101;
        }
        case SyscallType_t::GETUID: {
            return 102;
        }
        case SyscallType_t::SYSLOG: {
            return 103;
        }
        case SyscallType_t::GETGID: {
            return 104;
        }
        case SyscallType_t::SETUID: {
            return 105;
        }
        case SyscallType_t::SETGID: {
            return 106;
        }
        case SyscallType_t::GETEUID: {
            return 107;
        }
        case SyscallType_t::GETEGID: {
            return 108;
        }
        case SyscallType_t::SETPGID: {
            return 109;
        }
        case SyscallType_t::GETPPID: {
            return 110;
        }
        case SyscallType_t::GETPGRP: {
            return 111;
        }
        case SyscallType_t::SETSID: {
            return 112;
        }
        case SyscallType_t::SETREUID: {
            return 113;
        }
        case SyscallType_t::SETREGID: {
            return 114;
        }
        case SyscallType_t::GETGROUPS: {
            return 115;
        }
        case SyscallType_t::SETGROUPS: {
            return 116;
        }
        case SyscallType_t::SETRESUID: {
            return 117;
        }
        case SyscallType_t::GETRESUID: {
            return 118;
        }
        case SyscallType_t::SETRESGID: {
            return 119;
        }
        case SyscallType_t::GETRESGID: {
            return 120;
        }
        case SyscallType_t::GETPGID: {
            return 121;
        }
        case SyscallType_t::SETFSUID: {
            return 122;
        }
        case SyscallType_t::SETFSGID: {
            return 123;
        }
        case SyscallType_t::GETSID: {
            return 124;
        }
        case SyscallType_t::CAPGET: {
            return 125;
        }
        case SyscallType_t::CAPSET: {
            return 126;
        }
        case SyscallType_t::RT_SIGPENDING: {
            return 127;
        }
        case SyscallType_t::RT_SIGTIMEDWAIT: {
            return 128;
        }
        case SyscallType_t::RT_SIGQUEUEINFO: {
            return 129;
        }
        case SyscallType_t::RT_SIGSUSPEND: {
            return 130;
        }
        case SyscallType_t::SIGALTSTACK: {
            return 131;
        }
        case SyscallType_t::UTIME: {
            return 132;
        }
        case SyscallType_t::MKNOD: {
            return 133;
        }
        case SyscallType_t::USELIB: {
            return 134;
        }
        case SyscallType_t::PERSONALITY: {
            return 135;
        }
        case SyscallType_t::USTAT: {
            return 136;
        }
        case SyscallType_t::STATFS: {
            return 137;
        }
        case SyscallType_t::FSTATFS: {
            return 138;
        }
        case SyscallType_t::SYSFS: {
            return 139;
        }
        case SyscallType_t::GETPRIORITY: {
            return 140;
        }
        case SyscallType_t::SETPRIORITY: {
            return 141;
        }
        case SyscallType_t::SCHED_SETPARAM: {
            return 142;
        }
        case SyscallType_t::SCHED_GETPARAM: {
            return 143;
        }
        case SyscallType_t::SCHED_SETSCHEDULER: {
            return 144;
        }
        case SyscallType_t::SCHED_GETSCHEDULER: {
            return 145;
        }
        case SyscallType_t::SCHED_GET_PRIORITY_MAX: {
            return 146;
        }
        case SyscallType_t::SCHED_GET_PRIORITY_MIN: {
            return 147;
        }
        case SyscallType_t::SCHED_RR_GET_INTERVAL: {
            return 148;
        }
        case SyscallType_t::MLOCK: {
            return 149;
        }
        case SyscallType_t::MUNLOCK: {
            return 150;
        }
        case SyscallType_t::MLOCKALL: {
            return 151;
        }
        case SyscallType_t::MUNLOCKALL: {
            return 152;
        }
        case SyscallType_t::VHANGUP: {
            return 153;
        }
        case SyscallType_t::MODIFY_LDT: {
            return 154;
        }
        case SyscallType_t::PIVOT_ROOT: {
            return 155;
        }
        case SyscallType_t::_SYSCTL: {
            return 156;
        }
        case SyscallType_t::PRCTL: {
            return 157;
        }
        case SyscallType_t::ARCH_PRCTL: {
            return 158;
        }
        case SyscallType_t::ADJTIMEX: {
            return 159;
        }
        case SyscallType_t::SETRLIMIT: {
            return 160;
        }
        case SyscallType_t::CHROOT: {
            return 161;
        }
        case SyscallType_t::SYNC: {
            return 162;
        }
        case SyscallType_t::ACCT: {
            return 163;
        }
        case SyscallType_t::SETTIMEOFDAY: {
            return 164;
        }
        case SyscallType_t::MOUNT: {
            return 165;
        }
        case SyscallType_t::UMOUNT2: {
            return 166;
        }
        case SyscallType_t::SWAPON: {
            return 167;
        }
        case SyscallType_t::SWAPOFF: {
            return 168;
        }
        case SyscallType_t::REBOOT: {
            return 169;
        }
        case SyscallType_t::SETHOSTNAME: {
            return 170;
        }
        case SyscallType_t::SETDOMAINNAME: {
            return 171;
        }
        case SyscallType_t::IOPL: {
            return 172;
        }
        case SyscallType_t::IOPERM: {
            return 173;
        }
        case SyscallType_t::CREATE_MODULE: {
            return 174;
        }
        case SyscallType_t::INIT_MODULE: {
            return 175;
        }
        case SyscallType_t::DELETE_MODULE: {
            return 176;
        }
        case SyscallType_t::GET_KERNEL_SYMS: {
            return 177;
        }
        case SyscallType_t::QUERY_MODULE: {
            return 178;
        }
        case SyscallType_t::QUOTACTL: {
            return 179;
        }
        case SyscallType_t::NFSSERVCTL: {
            return 180;
        }
        case SyscallType_t::GETPMSG: {
            return 181;
        }
        case SyscallType_t::PUTPMSG: {
            return 182;
        }
        case SyscallType_t::AFS_SYSCALL: {
            return 183;
        }
        case SyscallType_t::TUXCALL: {
            return 184;
        }
        case SyscallType_t::SECURITY: {
            return 185;
        }
        case SyscallType_t::GETTID: {
            return 186;
        }
        case SyscallType_t::READAHEAD: {
            return 187;
        }
        case SyscallType_t::SETXATTR: {
            return 188;
        }
        case SyscallType_t::LSETXATTR: {
            return 189;
        }
        case SyscallType_t::FSETXATTR: {
            return 190;
        }
        case SyscallType_t::GETXATTR: {
            return 191;
        }
        case SyscallType_t::LGETXATTR: {
            return 192;
        }
        case SyscallType_t::FGETXATTR: {
            return 193;
        }
        case SyscallType_t::LISTXATTR: {
            return 194;
        }
        case SyscallType_t::LLISTXATTR: {
            return 195;
        }
        case SyscallType_t::FLISTXATTR: {
            return 196;
        }
        case SyscallType_t::REMOVEXATTR: {
            return 197;
        }
        case SyscallType_t::LREMOVEXATTR: {
            return 198;
        }
        case SyscallType_t::FREMOVEXATTR: {
            return 199;
        }
        case SyscallType_t::TKILL: {
            return 200;
        }
        case SyscallType_t::TIME: {
            return 201;
        }
        case SyscallType_t::FUTEX: {
            return 202;
        }
        case SyscallType_t::SCHED_SETAFFINITY: {
            return 203;
        }
        case SyscallType_t::SCHED_GETAFFINITY: {
            return 204;
        }
        case SyscallType_t::SET_THREAD_AREA: {
            return 205;
        }
        case SyscallType_t::IO_SETUP: {
            return 206;
        }
        case SyscallType_t::IO_DESTROY: {
            return 207;
        }
        case SyscallType_t::IO_GETEVENTS: {
            return 208;
        }
        case SyscallType_t::IO_SUBMIT: {
            return 209;
        }
        case SyscallType_t::IO_CANCEL: {
            return 210;
        }
        case SyscallType_t::GET_THREAD_AREA: {
            return 211;
        }
        case SyscallType_t::LOOKUP_DCOOKIE: {
            return 212;
        }
        case SyscallType_t::EPOLL_CREATE: {
            return 213;
        }
        case SyscallType_t::EPOLL_CTL_OLD: {
            return 214;
        }
        case SyscallType_t::EPOLL_WAIT_OLD: {
            return 215;
        }
        case SyscallType_t::REMAP_FILE_PAGES: {
            return 216;
        }
        case SyscallType_t::GETDENTS64: {
            return 217;
        }
        case SyscallType_t::SET_TID_ADDRESS: {
            return 218;
        }
        case SyscallType_t::RESTART_SYSCALL: {
            return 219;
        }
        case SyscallType_t::SEMTIMEDOP: {
            return 220;
        }
        case SyscallType_t::FADVISE64: {
            return 221;
        }
        case SyscallType_t::TIMER_CREATE: {
            return 222;
        }
        case SyscallType_t::TIMER_SETTIME: {
            return 223;
        }
        case SyscallType_t::TIMER_GETTIME: {
            return 224;
        }
        case SyscallType_t::TIMER_GETOVERRUN: {
            return 225;
        }
        case SyscallType_t::TIMER_DELETE: {
            return 226;
        }
        case SyscallType_t::CLOCK_SETTIME: {
            return 227;
        }
        case SyscallType_t::CLOCK_GETTIME: {
            return 228;
        }
        case SyscallType_t::CLOCK_GETRES: {
            return 229;
        }
        case SyscallType_t::CLOCK_NANOSLEEP: {
            return 230;
        }
        case SyscallType_t::EXIT_GROUP: {
            return 231;
        }
        case SyscallType_t::EPOLL_WAIT: {
            return 232;
        }
        case SyscallType_t::EPOLL_CTL: {
            return 233;
        }
        case SyscallType_t::TGKILL: {
            return 234;
        }
        case SyscallType_t::UTIMES: {
            return 235;
        }
        case SyscallType_t::VSERVER: {
            return 236;
        }
        case SyscallType_t::MBIND: {
            return 237;
        }
        case SyscallType_t::SET_MEMPOLICY: {
            return 238;
        }
        case SyscallType_t::GET_MEMPOLICY: {
            return 239;
        }
        case SyscallType_t::MQ_OPEN: {
            return 240;
        }
        case SyscallType_t::MQ_UNLINK: {
            return 241;
        }
        case SyscallType_t::MQ_TIMEDSEND: {
            return 242;
        }
        case SyscallType_t::MQ_TIMEDRECEIVE: {
            return 243;
        }
        case SyscallType_t::MQ_NOTIFY: {
            return 244;
        }
        case SyscallType_t::MQ_GETSETATTR: {
            return 245;
        }
        case SyscallType_t::KEXEC_LOAD: {
            return 246;
        }
        case SyscallType_t::WAITID: {
            return 247;
        }
        case SyscallType_t::ADD_KEY: {
            return 248;
        }
        case SyscallType_t::REQUEST_KEY: {
            return 249;
        }
        case SyscallType_t::KEYCTL: {
            return 250;
        }
        case SyscallType_t::IOPRIO_SET: {
            return 251;
        }
        case SyscallType_t::IOPRIO_GET: {
            return 252;
        }
        case SyscallType_t::INOTIFY_INIT: {
            return 253;
        }
        case SyscallType_t::INOTIFY_ADD_WATCH: {
            return 254;
        }
        case SyscallType_t::INOTIFY_RM_WATCH: {
            return 255;
        }
        case SyscallType_t::MIGRATE_PAGES: {
            return 256;
        }
        case SyscallType_t::OPENAT: {
            return 257;
        }
        case SyscallType_t::MKDIRAT: {
            return 258;
        }
        case SyscallType_t::MKNODAT: {
            return 259;
        }
        case SyscallType_t::FCHOWNAT: {
            return 260;
        }
        case SyscallType_t::FUTIMESAT: {
            return 261;
        }
        case SyscallType_t::NEWFSTATAT: {
            return 262;
        }
        case SyscallType_t::UNLINKAT: {
            return 263;
        }
        case SyscallType_t::RENAMEAT: {
            return 264;
        }
        case SyscallType_t::LINKAT: {
            return 265;
        }
        case SyscallType_t::SYMLINKAT: {
            return 266;
        }
        case SyscallType_t::READLINKAT: {
            return 267;
        }
        case SyscallType_t::FCHMODAT: {
            return 268;
        }
        case SyscallType_t::FACCESSAT: {
            return 269;
        }
        case SyscallType_t::PSELECT6: {
            return 270;
        }
        case SyscallType_t::PPOLL: {
            return 271;
        }
        case SyscallType_t::UNSHARE: {
            return 272;
        }
        case SyscallType_t::SET_ROBUST_LIST: {
            return 273;
        }
        case SyscallType_t::GET_ROBUST_LIST: {
            return 274;
        }
        case SyscallType_t::SPLICE: {
            return 275;
        }
        case SyscallType_t::TEE: {
            return 276;
        }
        case SyscallType_t::SYNC_FILE_RANGE: {
            return 277;
        }
        case SyscallType_t::VMSPLICE: {
            return 278;
        }
        case SyscallType_t::MOVE_PAGES: {
            return 279;
        }
        case SyscallType_t::UTIMENSAT: {
            return 280;
        }
        case SyscallType_t::EPOLL_PWAIT: {
            return 281;
        }
        case SyscallType_t::SIGNALFD: {
            return 282;
        }
        case SyscallType_t::TIMERFD: {
            return 283;
        }
        case SyscallType_t::EVENTFD: {
            return 284;
        }
        case SyscallType_t::FALLOCATE: {
            return 285;
        }
        case SyscallType_t::TIMERFD_SETTIME: {
            return 286;
        }
        case SyscallType_t::TIMERFD_GETTIME: {
            return 287;
        }
        case SyscallType_t::ACCEPT4: {
            return 288;
        }
        case SyscallType_t::SIGNALFD4: {
            return 289;
        }
        case SyscallType_t::EVENTFD2: {
            return 290;
        }
        case SyscallType_t::EPOLL_CREATE1: {
            return 291;
        }
        case SyscallType_t::DUP3: {
            return 292;
        }
        case SyscallType_t::PIPE2: {
            return 293;
        }
        case SyscallType_t::INOTIFY_INIT1: {
            return 294;
        }
        case SyscallType_t::PREADV: {
            return 295;
        }
        case SyscallType_t::PWRITEV: {
            return 296;
        }
        case SyscallType_t::RT_TGSIGQUEUEINFO: {
            return 297;
        }
        case SyscallType_t::PERF_EVENT_OPEN: {
            return 298;
        }
        case SyscallType_t::RECVMMSG: {
            return 299;
        }
        case SyscallType_t::FANOTIFY_INIT: {
            return 300;
        }
        case SyscallType_t::FANOTIFY_MARK: {
            return 301;
        }
        case SyscallType_t::PRLIMIT64: {
            return 302;
        }
        case SyscallType_t::NAME_TO_HANDLE_AT: {
            return 303;
        }
        case SyscallType_t::OPEN_BY_HANDLE_AT: {
            return 304;
        }
        case SyscallType_t::CLOCK_ADJTIME: {
            return 305;
        }
        case SyscallType_t::SYNCFS: {
            return 306;
        }
        case SyscallType_t::SENDMMSG: {
            return 307;
        }
        case SyscallType_t::SETNS: {
            return 308;
        }
        case SyscallType_t::GETCPU: {
            return 309;
        }
        case SyscallType_t::PROCESS_VM_READV: {
            return 310;
        }
        case SyscallType_t::PROCESS_VM_WRITEV: {
            return 311;
        }
        case SyscallType_t::KCMP: {
            return 312;
        }
        case SyscallType_t::FINIT_MODULE: {
            return 313;
        }
        case SyscallType_t::SCHED_SETATTR: {
            return 314;
        }
        case SyscallType_t::SCHED_GETATTR: {
            return 315;
        }
        case SyscallType_t::RENAMEAT2: {
            return 316;
        }
        case SyscallType_t::SECCOMP: {
            return 317;
        }
        case SyscallType_t::GETRANDOM: {
            return 318;
        }
        case SyscallType_t::MEMFD_CREATE: {
            return 319;
        }
        case SyscallType_t::KEXEC_FILE_LOAD: {
            return 320;
        }
        case SyscallType_t::BPF: {
            return 321;
        }
        case SyscallType_t::EXECVEAT: {
            return 322;
        }
        case SyscallType_t::USERFAULTFD: {
            return 323;
        }
        case SyscallType_t::MEMBARRIER: {
            return 324;
        }
        case SyscallType_t::MLOCK2: {
            return 325;
        }
        case SyscallType_t::COPY_FILE_RANGE: {
            return 326;
        }
        case SyscallType_t::PREADV2: {
            return 327;
        }
        case SyscallType_t::PWRITEV2: {
            return 328;
        }
        case SyscallType_t::PKEY_MPROTECT: {
            return 329;
        }
        case SyscallType_t::PKEY_ALLOC: {
            return 330;
        }
        case SyscallType_t::PKEY_FREE: {
            return 331;
        }
        case SyscallType_t::STATX: {
            return 332;
        }
        case SyscallType_t::IO_PGETEVENTS: {
            return 333;
        }
        case SyscallType_t::RSEQ: {
            return 334;
        }
        default: {
            return -1;
        }
    }
}