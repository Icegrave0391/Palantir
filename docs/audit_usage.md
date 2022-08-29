# System Auditing

Once auditbeat is installed, you can collect audit logs by
1. Configure Auditbeat and start system auditing (save system meta-information in the `test` folder):
```bash
cd runtime-monitoring/audit
sudo bash config.sh test
```
2. Stop system auditing and collect audit data into the `test` folder:
```bash
sudo bash collect.sh test
```

**Note:** PalanTir currently supports monitoring 32 types of system calls: 

`read, write, open, close, mq_open, openat, unlink, link, linkat, unlinkat, rmdir, mkdir, rename, pipe, pipe2, dup, dup2, fcntl, clone, fork, vfork, execve, kill, sendto, recvfrom, sendmsg, sendmmsg, recvmsg, recvmmsg, connect, socket, and getpeername`.

## Understand our system auditing's Output

* `auditbeat.x` describes audit logs in a JSON format
* `procinfo` contains meta-information (e.g., pid, ppid and arguments) of
  existing processes before system auditing
* `fdinfo` contains opened files of existing processes before system auditing
* `socketinfo` contains existing sockets before system auditing

## Example of an audit log

A log entry of `read` is shown as follows:
```json
{
  "@timestamp": "2021-10-31T13:18:31.013Z",
  "@metadata": {
    "beat": "auditbeat",
    "type": "doc",
    "version": "6.8.12"
  },
  "user": {
    "name_map": {
      "fsgid": "anonymized",
      "fsuid": "anonymized",
      "gid": "anonymized",
      "sgid": "anonymized",
      "uid": "anonymized",
      "auid": "anonymized",
      "egid": "anonymized",
      "euid": "anonymized",
      "suid": "anonymized"
    },
    "egid": "1000",
    "fsgid": "1000",
    "auid": "1000",
    "fsuid": "1000",
    "gid": "1000",
    "sgid": "1000",
    "euid": "1000",
    "suid": "1000",
    "uid": "1000"
  },
  "process": {
    "ppid": "14873",
    "name": "sshd",
    "exe": "/usr/sbin/sshd",
    "pid": "14936"
  },
  "auditd": {
    "result": "success",
    "session": "697",
    "data": {
      "a3": "7ffcd033f420",
      "syscall": "read",
      "tty": "(none)",
      "a2": "4000",
      "exit": "36",
      "arch": "x86_64",
      "a0": "3",
      "a1": "7ffcd033b490"
    },
    "sequence": 29541
  }
}
```