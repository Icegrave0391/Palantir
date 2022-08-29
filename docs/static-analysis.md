## PalanTir Static Binary Analysis

PalanTir's static analysis serves to profile program binaries offline to perform forward and context-, flow-, and field-sensitive analysis to extract taint propagation logics per basic block.

### Preparation

1. Activate python environment

``` bash
# (virtualenv)
$ workon palantir-env
# (anaconda)
$ conda activate palantir-env
```

2. Start redis server
``` bash
# Server starts at 127.0.0.1:6379 by default.
# To configure the redis server, please refer to this website: https://redis.io/docs
$ redis-server & 
```

### Start

Note that the root directory of the static analysis framework is at [static-analysis](../static-analysis/).

There are some provided scripts under [static-analysis/scripts](../static-analysis/scripts/) for you to run the analysis framework:
* [run_binary_eval.py](../static-analysis/scripts/run_binary_eval.py): The main script to run the analysis framework.
* [interactive_debugger.py](../static-analysis/scripts/interactive_debugger.py): A interactive debugger to debug and test functionalities.

Run `(palantir-env) python static-analysis/scripts/run_binary_eval.py --help` for the command line documentation (usage):

``` bash
usage: run_binary_eval.py [-h] [--binary_dir BINARY_DIR] -b BINARY [--binary_output_dir BINARY_OUTPUT_DIR] [--dbgsym DBGSYM]
                          [--dbg_dir DBG_DIR] [-l] [-e] [-x] [-p PARSE_TRACE] [-v] [-f START_FUNCTION] [-r MEM_RW_UPPERBOUND]
                          [-u VALUESET_UPPERBOUND] [-s SYMBOLIC_REF_DEPTH] [-d IRRELEVANT_CALL_DEPTH] [--redis_ip REDIS_IP]
                          [--redis_port REDIS_PORT] [--debug]

Palantiri Binary Pre-processing and Static (Data-flow) Analysis Framework.

Optional arguments:
  -h, --help            show this help message and exit
  --binary_dir BINARY_DIR
                        Input the directory name that contains input all binary files, by default is `binaries` and the directory will
                        be: `static-analysis/binaries/`
  -b BINARY, --binary BINARY
                        Input program binary file (please first put the binary file into the `binary_dir`)
  --binary_output_dir BINARY_OUTPUT_DIR
                        Input the directory name to store the analyses results and temporary outputs, by default is `binaries_output`
                        and the directory will be: `static-analysis/binaries_output/`
  --dbgsym DBGSYM       (Optional) input binary dbgsym file path to enrich binary symbol table
  --dbg_dir DBG_DIR     Input the directory for the temporary debug log file, by default is `debug` and the directory will be:
                        {ROOT_DIR_NAME}/debug/
  -l, --loop_revisit_mode
                        Turn on loop revisit mode for binary summary analysis
  -e, --eval_mode       Turn on evaluation mode to generate binary statistics
  -x, --without_whole_segment
                        Run different segments rather than a whole segment in analysis
  -p PARSE_TRACE, --parse_trace PARSE_TRACE
                        Input the execution trace path to parse (this option is used for debugging PT traces only)
  -v, --verbose         Input verbose level count (e.g., -vvv)
  -f START_FUNCTION, --start_function START_FUNCTION
                        (Optional) Assign the starting function for the analysis, by default is None that it will determined by CFG
                        Refinement
  -r MEM_RW_UPPERBOUND, --mem_rw_upperbound MEM_RW_UPPERBOUND
                        Set upper bound of the approximate number of memory r/w values, by default is 10
  -u VALUESET_UPPERBOUND, --valueset_upperbound VALUESET_UPPERBOUND
                        Set upper bound number of the approximate number of value site, by default is 15
  -s SYMBOLIC_REF_DEPTH, --symbolic_ref_depth SYMBOLIC_REF_DEPTH
                        Set the max level of symbolic (de)reference depth for analysis (N_sym), by default is 2
  -d IRRELEVANT_CALL_DEPTH, --irrelevant_call_depth IRRELEVANT_CALL_DEPTH
                        Set the max irrelevant call depth of out-of-scope functions for analysis (N_dep), by default is 3
  --redis_ip REDIS_IP   Set up redis database server (for taint summary storage) ip address, by default is 127.0.0.1
  --redis_port REDIS_PORT
                        Set up redis database server (for taint summary storage) port, by default is 6379
  --debug               Turn on debug mode, which will automatically draw and visualize transitive closures to the local files
```

#### From the Beginning: Set Input/Output Directory 

First of all, a reminder that the root directory of the framework is at [static-analysis](../static-analysis/).

The default input directory is at `static-analysis/binaries`, and the default output directory is at `static-analysis/binaries_output`.

To change those default directories, please use the command line options `--binary_dir INPUT_DIR` and `--binary_output_dir OUTPUT_DIR`. 
The input and output directories will be set to `static-analysis/INPUT_DIR` and `static-analysis/OUTPUT_DIR`, respectively.

Now copy the binary file into the default binary input dir `binary_dir`: `static-analysis/binaries`. Suppose the target binary file is `/usr/sbin/nginx`:

``` bash
$ cp /usr/sbin/nginx /path/to/static-analysis/binaries/nginx
```

#### Run the Analysis

Suppose the target binary name is `nginx`. Now run the following command to start the analysis:

``` bash
$ (palantir-env) python static-analysis/scripts/run_binary_eval.py --b nginx -vvv --eval_mode --debug 
```
You can see the runtime logs [as follows](./static-analysis.md#runtime-logs).

#### Results

After the analysis, all the results and temporarily generated files are stored in the directory `static-analysis/binaries_output/nginx/`.

The taint summaries are stored in the redis database. Also, they are backed up to `static-analysis/binaries_output/nginx/nginx_db0.json`.

You could also manually dump the database to a JSON file by using `redis-dump` command:
``` bash
$ redis-dump -u REDIS_SERVER_IP:REDIS_SERVER_PORT -d 0 > OUTPUT_PATH
```

#### Runtime Logs

```
$ (palantir-env) python static-analysis/scripts/run_binary_eval.py --b nginx -vvv --eval_mode --debug
INFO    | 2022-05-01 19:55:41,531 | binary.elfloader | Loading binary file /home/anonymous/Palantir/static-analysis/binaries/nginx...
WARNING | 2022-05-01 19:55:41,714 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: pcre_malloc
WARNING | 2022-05-01 19:55:41,714 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: pcre_free
WARNING | 2022-05-01 19:55:41,716 | cle.loader | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
INFO    | 2022-05-01 19:55:41,724 | binary.elfloader | Generating binary disassembly file to /home/anonymous/Palantir/static-analysis/binaries_output/nginx/nginx_asm.txt
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | Palantiri Project info:
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ working directory: /home/anonymous/Palantir/static-analysis
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ binary file: /home/anonymous/Palantir/static-analysis/binaries/nginx
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ debug output directory: /home/anonymous/Palantir/static-analysis/binaries_output/nginx/debug_temp_file.tmp
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ output directory: /home/anonymous/Palantir/static-analysis/binaries_output/nginx
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ analysis verbose level: 2
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ debug mode: False
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ analysis loop revisit mode: False
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ max symbolic reference depth: 2
INFO    | 2022-05-01 19:55:41,839 | palantiri.pal_project | ∟ max irrlevant call depth: 3
INFO    | 2022-05-01 19:55:54,405 | palantiri.cfg.cfg_util | Successfully constructed CFG.
INFO    | 2022-05-01 19:55:54,405 | palantiri.cfg.cfg_util | Saving CFG and knowledge_base...
INFO    | 2022-05-01 19:55:54,754 | palantiri.cfg.cfg_util | CFG model saved at /home/anonymous/Palantir/static-analysis/binaries_output/nginx/nginx.cfgmodel!
INFO    | 2022-05-01 19:55:55,092 | palantiri.cfg.cfg_util | knowledge_base saved at /home/anonymous/Palantir/static-analysis/binaries_output/nginx/nginx.kb!
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function gettimeofday (0x40ac40)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function memcpy (0x40ae50)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function __stack_chk_fail (0x40abb0)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function waitpid (0x40b0b0)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function sem_post (0x40af90)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function __memcpy_chk (0x40ae00)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function write (0x40ab30)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function __errno_location (0x40aa60)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function getppid (0x40b160)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function getenv (0x40a9f0)>.
INFO    | 2022-05-01 19:55:55,116 | palantiri.cfg.cfg_util | Determined calling convention for <Function __gmon_start__ (0x40b290)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function malloc (0x40af40)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function strerror (0x40b1f0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function clock_gettime (0x40ab20)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function localtime_r (0x40aaa0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function open64 (0x40b050)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function free (0x40aa20)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function uname (0x40ac10)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function getpagesize (0x40b140)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function sysconf (0x40b0e0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function getrlimit64 (0x40aef0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function srandom (0x40aa70)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function pread64 (0x40b090)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function close (0x40acd0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function strcmp (0x40adb0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function kill (0x40aea0)>.
INFO    | 2022-05-01 19:55:55,117 | palantiri.cfg.cfg_util | Determined calling convention for <Function posix_memalign (0x40b1b0)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function getsockname (0x40b110)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function getsockopt (0x40ad70)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function sigemptyset (0x40ae20)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function sigaction (0x40aaf0)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function fork (0x40b230)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function getpid (0x40ab40)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function exit (0x40b170)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function setsid (0x40acf0)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function umask (0x40ae40)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function dup2 (0x40abe0)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function strncmp (0x40aa90)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function unlink (0x40aa80)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function time (0x40aec0)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function localtime (0x40aa40)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function strftime (0x40b060)>.
INFO    | 2022-05-01 19:55:55,118 | palantiri.cfg.cfg_util | Determined calling convention for <Function gethostname (0x40b130)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function memset (0x40ac90)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function __fxstat64 (0x40ada0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function memmove (0x40b070)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function memcmp (0x40ad60)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function pwrite64 (0x40aee0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function mkdir (0x40aab0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function __xstat64 (0x40ab60)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function chown (0x40afb0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function chmod (0x40b020)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function fcntl (0x40ab10)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function munmap (0x40afe0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function setsockopt (0x40ab00)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function socket (0x40b280)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function usleep (0x40b260)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function ioctl (0x40acb0)>.
INFO    | 2022-05-01 19:55:55,119 | palantiri.cfg.cfg_util | Determined calling convention for <Function bind (0x40b030)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function listen (0x40af50)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function mmap64 (0x40af20)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function sem_init (0x40b0c0)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function sigaddset (0x40b220)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function sigprocmask (0x40aa00)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function socketpair (0x40ae60)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function sendmsg (0x40aac0)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function sigsuspend (0x40af70)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function rename (0x40b0f0)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function setitimer (0x40afc0)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function __libc_start_main (0x40ad50)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function dlopen (0x40af00)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function dlerror (0x40b250)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function dlsym (0x40b200)>.
INFO    | 2022-05-01 19:55:55,120 | palantiri.cfg.cfg_util | Determined calling convention for <Function dlclose (0x40afa0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function geteuid (0x40aca0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function getpwnam (0x40add0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function getgrnam (0x40ae70)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function strchr (0x40ac00)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function getaddrinfo (0x40b1d0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function freeaddrinfo (0x40b270)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function sched_yield (0x40ad30)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function sem_wait (0x40ade0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function raise (0x40aa10)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function abort (0x40aa50)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function sem_destroy (0x40b1e0)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function connect (0x40b180)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function random (0x40af10)>.
INFO    | 2022-05-01 19:55:55,121 | palantiri.cfg.cfg_util | Determined calling convention for <Function epoll_create (0x40b150)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function accept (0x40b100)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function accept4 (0x40abd0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function recvmsg (0x40aff0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function recv (0x40aa30)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function readv (0x40b040)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function send (0x40abf0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function writev (0x40aad0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function sendto (0x40acc0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function execve (0x40ad80)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function setrlimit64 (0x40ac30)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function setpriority (0x40ac50)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function setgid (0x40b0a0)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function prctl (0x40ae90)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function initgroups (0x40b210)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function sched_setaffinity (0x40ad00)>.
INFO    | 2022-05-01 19:55:55,122 | palantiri.cfg.cfg_util | Determined calling convention for <Function chdir (0x40aba0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function setuid (0x40b1c0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function syscall (0x40ae10)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function epoll_ctl (0x40ad20)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function read (0x40ad40)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function eventfd (0x40b190)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function epoll_wait (0x40b010)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function sendfile64 (0x40aeb0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_study (0x40b0d0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_fullinfo (0x40adc0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_free_study (0x40afd0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_config (0x40ae30)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function qsort (0x40aae0)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function glob64 (0x40ae80)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function globfree64 (0x40ab90)>.
INFO    | 2022-05-01 19:55:55,123 | palantiri.cfg.cfg_util | Determined calling convention for <Function shutdown (0x40ab80)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function strstr (0x40b240)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_compile (0x40af30)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function getuid (0x40abc0)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function pcre_exec (0x40ac80)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function openat64 (0x40aed0)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function __fxstatat64 (0x40ac70)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function posix_fadvise64 (0x40b1a0)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function pwritev64 (0x40af80)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function __realpath_chk (0x40ace0)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function utimes (0x40ad90)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function statfs64 (0x40ac60)>.
INFO    | 2022-05-01 19:55:55,124 | palantiri.cfg.cfg_util | Determined calling convention for <Function opendir (0x40ab70)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function readdir64 (0x40b080)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function closedir (0x40ad10)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function gmtime_r (0x40ac20)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function mktime (0x40af60)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function __lxstat64 (0x40b120)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function __memmove_chk (0x40adf0)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function crypt_r (0x40ab50)>.
INFO    | 2022-05-01 19:55:55,125 | palantiri.cfg.cfg_util | Determined calling convention for <Function ftruncate64 (0x40b000)>.
INFO    | 2022-05-01 19:55:55,129 | palantiri.structures.hooks.function_wrappers | Hooked function: ngx_palloc to special handler xxx_palloc.
INFO    | 2022-05-01 19:55:55,129 | palantiri.structures.hooks.function_wrappers | Hooked function: ngx_pnalloc to special handler xxx_palloc.
INFO    | 2022-05-01 19:55:55,130 | palantiri.structures.hooks.function_wrappers | Hooked function: ngx_calloc to special handler ngx_calloc.
INFO    | 2022-05-01 19:55:55,130 | palantiri.structures.hooks.function_wrappers | Hooked function: ngx_sprintf to special handler ngx_printf.
INFO    | 2022-05-01 19:55:55,163 | palantiri.cfg.cfg_util | Constructing callgraph for project <Project /home/anonymous/Palantiri/binaries/nginx>...
INFO    | 2022-05-01 19:55:55,266 | palantiri.cfg.cfg_util | Constructing acyclic callgraph for project <Project /home/anonymous/Palantiri/binaries/nginx>...
INFO    | 2022-05-01 19:55:56,824 | palantiri.cfg.callgraph | Saving Acyclic callgraph model...
INFO    | 2022-05-01 19:55:56,831 | palantiri.cfg.callgraph | Acyclic callgraph saved at /home/anonymous/Palantiri/binaries_output/nginx/callgraph_acyclic_model.dump.
INFO    | 2022-05-01 19:55:57,453 | palantiri.cfg.callgraph | Saving Acyclic callgraph model...
INFO    | 2022-05-01 19:55:57,460 | palantiri.cfg.callgraph | Acyclic callgraph saved at /home/anonymous/Palantiri/binaries_output/nginx/callgraph_acyclic_enriched_model.dump.
INFO    | 2022-05-01 19:55:57,461 | palantiri.singletons.adaptors.adaptor_manager | Pruning the callgraph for analysis of adaptor: <palantiri.singletons.adaptors.adaptor_manager.AdaptorManager object at 0x7fa2e79f4d30>...
INFO    | 2022-05-01 19:55:57,471 | palantiri.singletons.adaptors.adaptor_manager | Round 0: Pruned blacklist functions: ()
INFO    | 2022-05-01 19:55:57,473 | palantiri.singletons.adaptors.adaptor_manager | Round 0.1: Pruned rule based blacklist functions: [<CGNode func_addr: 0x40d3d7, function: ngx_log_insert>, <CGNode func_addr: 0x40d48e, function: ngx_log_errno>, <CGNode func_addr: 0x40d4e9, function: ngx_log_error_core>, <CGNode func_addr: 0x40d7f6, function: ngx_log_abort>, <CGNode func_addr: 0x40d91d, function: ngx_log_stderr>, <CGNode func_addr: 0x40da59, function: ngx_log_init>, <CGNode func_addr: 0x40dbfd, function: ngx_log_get_file_log>, <CGNode func_addr: 0x40dc1e, function: ngx_log_open_default>, <CGNode func_addr: 0x40dcb2, function: ngx_log_redirect_stderr>, <CGNode func_addr: 0x40dd2c, function: ngx_log_set_log>, <CGNode func_addr: 0x40e905, function: ngx_hash_find>, <CGNode func_addr: 0x40e977, function: ngx_hash_find_wc_head>, <CGNode func_addr: 0x40ea6c, function: ngx_hash_find_wc_tail>, <CGNode func_addr: 0x40eb28, function: ngx_hash_find_combined>, <CGNode func_addr: 0x418e10, function: ngx_rbtree_insert>, <CGNode func_addr: 0x419040, function: ngx_rbtree_insert_value>, <CGNode func_addr: 0x419078, function: ngx_rbtree_insert_timer_value>, <CGNode func_addr: 0x4190b0, function: ngx_rbtree_delete>, <CGNode func_addr: 0x4194b3, function: ngx_rbtree_next>, <CGNode func_addr: 0x41fdd8, function: ngx_conf_log_error>, <CGNode func_addr: 0x421eee, function: ngx_resolver_log_error>, <CGNode func_addr: 0x42a3f5, function: ngx_syslog_cleanup>, <CGNode func_addr: 0x42a444, function: ngx_syslog_process_conf>, <CGNode func_addr: 0x42a8d8, function: ngx_syslog_add_header>, <CGNode func_addr: 0x42a93e, function: ngx_syslog_send>, <CGNode func_addr: 0x42ab39, function: ngx_syslog_writer>, <CGNode func_addr: 0x42b189, function: ngx_event_debug_connection>, <CGNode func_addr: 0x42c8fb, function: ngx_accept_log_error>, <CGNode func_addr: 0x431bad, function: ngx_debug_point>, <CGNode func_addr: 0x43eef2, function: ngx_http_log_request>, <CGNode func_addr: 0x43f5a2, function: ngx_http_log_error>, <CGNode func_addr: 0x43f64b, function: ngx_http_log_error_handler>, <CGNode func_addr: 0x445019, function: ngx_http_log_copy_short>, <CGNode func_addr: 0x44503d, function: ngx_http_log_pipe>, <CGNode func_addr: 0x445058, function: ngx_http_log_open_file_cache>, <CGNode func_addr: 0x4452e5, function: ngx_http_log_create_loc_conf>, <CGNode func_addr: 0x445309, function: ngx_http_log_create_main_conf>, <CGNode func_addr: 0x4453b1, function: ngx_http_log_flush>, <CGNode func_addr: 0x445485, function: ngx_http_log_flush_handler>, <CGNode func_addr: 0x44549a, function: ngx_http_log_merge_loc_conf>, <CGNode func_addr: 0x4455d8, function: ngx_http_log_request_length>, <CGNode func_addr: 0x4455fd, function: ngx_http_log_body_bytes_sent>, <CGNode func_addr: 0x445634, function: ngx_http_log_bytes_sent>, <CGNode func_addr: 0x44565a, function: ngx_http_log_status>, <CGNode func_addr: 0x44569f, function: ngx_http_log_request_time>, <CGNode func_addr: 0x445711, function: ngx_http_log_msec>, <CGNode func_addr: 0x44573a, function: ngx_http_log_unescaped_variable_getlen>, <CGNode func_addr: 0x44576d, function: ngx_http_log_json_variable_getlen>, <CGNode func_addr: 0x4457c9, function: ngx_http_log_copy_long>, <CGNode func_addr: 0x4457e1, function: ngx_http_log_time>, <CGNode func_addr: 0x44580a, function: ngx_http_log_iso8601>, <CGNode func_addr: 0x445833, function: ngx_http_log_compile_format>, <CGNode func_addr: 0x445d24, function: ngx_http_log_set_format>, <CGNode func_addr: 0x445e35, function: ngx_http_log_init>, <CGNode func_addr: 0x445f4c, function: ngx_http_log_variable>, <CGNode func_addr: 0x446067, function: ngx_http_log_unescaped_variable>, <CGNode func_addr: 0x4460b2, function: ngx_http_log_json_variable>, <CGNode func_addr: 0x44611d, function: ngx_http_log_set_log>, <CGNode func_addr: 0x446934, function: ngx_http_log_write>, <CGNode func_addr: 0x446d33, function: ngx_http_log_handler>, <CGNode func_addr: 0x447177, function: ngx_http_log_variable_getlen>, <CGNode func_addr: 0x4703f7, function: ngx_http_proxy_abort_request>, <CGNode func_addr: 0x476250, function: ngx_http_fastcgi_abort_request>, <CGNode func_addr: 0x47acec, function: ngx_http_uwsgi_abort_request>, <CGNode func_addr: 0x47d789, function: ngx_http_scgi_abort_request>, <CGNode func_addr: 0x47fefc, function: ngx_http_memcached_abort_request>]
...
INFO    | 2022-05-01 19:55:57,504 | palantiri.cfg.cfg_util | Build transitive closure for functions: [<Function read (0x40ad40)>, <Function readv (0x40b040)>, <Function pread64 (0x40b090)>, <Function write (0x40ab30)>, <Function writev (0x40aad0)>, <Function send (0x40abf0)>, <Function sendmsg (0x40aac0)>, <Function sendto (0x40acc0)>, <Function sendfile64 (0x40aeb0)>, <Function recv (0x40aa30)>, <Function recvmsg (0x40aff0)>]...
ERROR   | 2022-05-01 19:55:57,510 | palantiri.cfg.callgraph | Function send is not in CallGraph.
ERROR   | 2022-05-01 19:55:57,510 | palantiri.cfg.callgraph | Function sendto is not in CallGraph.
INFO    | 2022-05-01 19:55:57,513 | palantiri.cfg.cfg_util | Built transitive closure graph for key_functions: ['read', 'readv', 'pread64', 'write', 'writev', 'send', 'sendmsg', 'sendto', 'sendfile64', 'recv', 'recvmsg']...Totally 112 functions...
INFO    | 2022-05-01 19:55:57,517 | palantiri.cfg.cfg_util | Build transitive closure for functions: [<Function read (0x40ad40)>, <Function readv (0x40b040)>, <Function pread64 (0x40b090)>, <Function recv (0x40aa30)>, <Function recvmsg (0x40aff0)>]...
INFO    | 2022-05-01 19:55:57,521 | palantiri.cfg.cfg_util | Built transitive closure graph for key_functions: ['read', 'readv', 'pread64', 'recv', 'recvmsg']...Totally 88 functions...
INFO    | 2022-05-01 19:55:57,524 | palantiri.cfg.cfg_util | Build transitive closure for functions: [<Function write (0x40ab30)>, <Function writev (0x40aad0)>, <Function send (0x40abf0)>, <Function sendmsg (0x40aac0)>, <Function sendto (0x40acc0)>, <Function sendfile64 (0x40aeb0)>]...
ERROR   | 2022-05-01 19:55:57,527 | palantiri.cfg.callgraph | Function send is not in CallGraph.
ERROR   | 2022-05-01 19:55:57,527 | palantiri.cfg.callgraph | Function sendto is not in CallGraph.
INFO    | 2022-05-01 19:55:57,529 | palantiri.cfg.cfg_util | Built transitive closure graph for key_functions: ['write', 'writev', 'send', 'sendmsg', 'sendto', 'sendfile64']...Totally 92 functions...
DEBUG   | 2022-05-01 19:55:57,532 | misc.visualize | Processing on debug_draw graph, it may take a few minutes...
INFO    | 2022-05-01 19:55:57,551 | palantiri.singletons.adaptors.adaptor_manager | Analysis Manager determined the whole segment start: ngx_http_upstream_process_request
INFO    | 2022-05-01 19:55:57,551 | palantiri.singletons.adaptors | Found binary nginx's interproc adaptor: (CalldepthAdaptor, IndirectAdaptor, LoopcallAdaptor, BlacklistAdaptor, SpecialAdaptor, SegmentAdaptor)...
INFO    | 2022-05-01 19:55:57,893 | palantiri.analyses.binary_summary | palantiri.analyses.binary_summary | BinarySummaryInterface settings:
∟ save_space_mode: False
∟ loop_revisit_mode: True
∟ max_symbol_ref_depth: 3
∟ max_irrelevant_call_depth: 3
∟ mem_rw_upperbound: 50
∟ valueset_upperbound: 50
INFO    | 2022-05-01 19:55:57,893 | __main__ | AnalysisInterface -- determined start function: ngx_http_upstream_process_request
INFO    | 2022-05-01 19:55:57,893 | __main__ | AnalysisInterface -- ready to start.
Press any key to start analysis, and press c to leave...

palantiri.analyses.binary_summary | Start binary summary for function: ngx_http_upstream_process_request. Call stack: []
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ff07
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ff39
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ff45
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ff4d
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ffc8
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ffcc
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ffd6
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x450256
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x4502a3
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ffdf
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44ffeb
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x44fff0
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x450004
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x450011
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x4500e0
palantiri.analyses.binary_summary | Start binary summary for function: ngx_pcalloc. Call stack: ['ngx_http_upstream_process_request']
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_pcalloc, node: 0x40e501
palantiri.analyses.binary_summary | Start binary summary for function: ngx_palloc. Call stack: ['ngx_http_upstream_process_request', 'ngx_pcalloc']
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_pcalloc, node: 0x40e50f
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_pcalloc, node: 0x40e517
palantiri.analyses.binary_summary | Start binary summary for function: memset. Call stack: ['ngx_http_upstream_process_request', 'ngx_pcalloc']
palantiri.analyses.binary_summary | BinarySummary handling func: memset, node: 0x40ac90
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_pcalloc, node: 0x40e527
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x4500ef
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_upstream_process_request, node: 0x4500fb
palantiri.analyses.binary_summary | Start binary summary for function: ngx_create_temp_file. Call stack: ['ngx_http_upstream_process_request']
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x415973
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x4159a5
palantiri.analyses.binary_summary | Start binary summary for function: ngx_pnalloc. Call stack: ['ngx_http_upstream_process_request', 'ngx_create_temp_file']
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x4159bd
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x4159ca
palantiri.analyses.binary_summary | Start binary summary for function: memcpy. Call stack: ['ngx_http_upstream_process_request', 'ngx_create_temp_file']
palantiri.analyses.binary_summary | BinarySummary handling func: memcpy, node: 0x40ae50
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x4159d8
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x415b77
palantiri.analyses.binary_summary | BinarySummary handling func: ngx_create_temp_file, node: 0x415a25
palantiri.analyses.binary_summary | Start binary summary for function: ngx_pnalloc. Call stack: ['ngx_http_upstream_process_request', 'ngx_create_temp_file']
...
INFO    | 2022-05-01 20:12:49,258 | palantiri.structures.value_set.engine.vs_engine | LoadMem. ins_addr = 0x44bc7d, sym_var: <BV64 fs + 0x28>, AbsRegion: <AbsRegion symbolic: fs + 0x28>.
INFO    | 2022-05-01 20:12:49,258 | palantiri.structures.value_set.engine.vs_engine | 0x44bc7d: _handle_XOR(<BV64 [fs + 0x28]>, <BV64 [fs + 0x28]>) res_val: <BV64 TOP>
                                                                                                                                           res_region: {<AbsRegion symbolic: [fs + 0x28]>}
INFO    | 2022-05-01 20:12:49,260 | palantiri.analyses.binary_summary | BinarySummary handling func: ngx_http_complex_value, node: 0x44bca5
INFO    | 2022-05-01 20:12:49,270 | palantiri.structures.value_set.engine.vs_engine | 0x44bca5: _handle_SUB(<BV64 stack_base - 0x328>, <BV64 0x8>) res_val: <BV64 stack_base - 0x330>
                                                                                                                                                         res_region: {<AbsRegion stack: -0x330>}
INFO    | 2022-05-01 20:12:49,271 | palantiri.structures.value_set.engine.vs_engine | StoreMem (strong), ins_addr = 0x44bca5, sym_val: <BV64 stack_base - 0x330>, region: <AbsRegion stack: -0x330>
INFO    | 2022-05-01 20:12:49,278 | palantiri.structures.value_set.engine.vs_engine | 0x44bca5: _handle_SUB(<BV64 stack_base - 0x330>, <BV64 0x80>) res_val: <BV64 stack_base - 0x3b0>
                                                                                                                                                         res_region: {<AbsRegion stack: -0x3b0>}
INFO    | 2022-05-01 20:12:49,279 | palantiri.structures.value_set.function_handler.bs_functionhandler | Binary Summary handling __stack_chk_fail
INFO    | 2022-05-01 20:12:49,289 | palantiri.analyses.binary_summary | Start binary summary for function: __stack_chk_fail. Call stack: ['ngx_output_chain', 'ngx_http_trailers_filter', 'ngx_http_complex_value']
INFO    | 2022-05-01 20:12:49,289 | palantiri.analyses.binary_summary | BinarySummary handling func: __stack_chk_fail, node: 0x40abb0
...
```

