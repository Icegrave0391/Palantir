import json
import os
import logging
import angr
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

callgraph_whitelist_starts = ["main", "transmit_normal", "worker_thread", "file_read"] # transmit_normal in proftpd, worker_thread in apache

external_blacklist = ("rpl_re_search", "rpl_re_match", "quotearg_buffer", "rpl_re_compile_pattern")

external_rule_blacklist = ("rpl_re", "quotearg", "quote", "log_", "abort_", "debug")

general_blacklist = ("__libc_csu_init", "_init", "__stack_chk_fail", "__libc_start_main", "_start",
                     "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux", "__cxa_finalize",
                     "frame_dummy", "__libc_csu_fini", "_fini")

#
# Functions to avoid analyzing, those are about logs and debugs.
#
binary_function_blacklist = {
    "wget": ("logprintf", "debug_logprintf", "parse_line", "quote", "logputs", "log_dump_context", "url_parse",
             "lookup_host", "url_file_name", "xalloc_die", "convert_all_links", "cleanup", "warc_start_new_file"),
    "thttpd": ("ls", "httpd_write_fully", "httpd_realloc_str"),
    "sendmail": ("getauthinfo", "safeopen", "bfrewind", "message", "usrerrenh", "chompheader", "rscheck",
                 "eatheader", "sendtolist", "finis", "usrerr", "dferror", "hvalue", "sm_errstring", "dumpfd", "logsender",
                 "sm_wbuf", "queueup", "split_by_recipient"),
    "ntpd": ("timer", "record_raw_stats"),
}

binary_function_whitelist = {
    "sendmail": ("sm_fp", "sm_bfopen", "sm_io_flush", "sm_flush", "sm_bfgetinfo"),
    "proftpd": ("xfer_retr",),
}

# rule based filter for functions
binary_rule_blacklist = {
    "wget": ("ftp", "quoting", "yy", "log",),
    "nginx": ("hash_find", "ngx_rbtree"),
    "pure-ftpd": ("command_line", "logfile", "die"),
    "curl": ("parse", "_args", "fail", "strerror", "printf", "infof", "cookie", "rand", "getconnectinfo"),
    "nano": ("die", "parse"),
    "thttpd": ("parse", "err_", "auth_"),
    "httpd2": ("config", "cfg", "md5", "flush"),
    "lighttpd": ("parse",),
    "haproxy": ("init",),
    "sendmail": ("deliver", "syslog", "syserr", "dprintf", "io_seek", "printf", "flush", "xputs", "stats", "milter", "send_command"),
    "ntpd": ("config", "report", "parse", "print", "error", "log", "toa", "crypto", "auth", "session"),
    "yafc": ("parse", "print", "ask", "init", "close", "ftp_cmd"),
    "proftpd": ("config", "help", "parse", "timer", "stash", "auth", "chdir", "setcwd", "parser",
                "timer", "cmd", "scoreboard", "trace_msg", "display", "ident"),
    "varnishd": ("error", "VSLb", "fail", "printf", "scanf", "init", "setup", "Init"),
    "cupsd": ("Conf", "syslog", "Error", "Log", "Close", "Timeout", "Stop", "Delete", "Check",),
    "zip": ("err", "getp", "check_unzip", "fcopy", "warn", "split", "print", "Display", "tree", "copy_block"),
}

# rule based filter for indirect targets
binary_indirect_rule_blacklist = {
    "wget": ("cmd_", "alloc", "print", "yy", "cmd_")
}

#
# Indirect callsites to ignore analyzing
#

binary_indirect_blacklist = {
    "wget": ("postorder", "preorder.part.14", "re_compile_internal", "hash_table_put", "hash_table_get",
             "hash_table_get_pair", "shaxxx_stream.isra.1", )
}


def search_binary_function_whitelist(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    for k, v in binary_function_whitelist.items():
        if binary_name.find(k) >= 0:
            return v
    return tuple()


def search_binary_function_blacklist(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    for k, v in binary_function_blacklist.items():
        if binary_name.find(k) >= 0:
            log.debug(f"Found binary {binary_name}'s function blacklist: {v}...")
            return v
    return tuple()


def search_binary_indirect_blacklist(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    for k, v in binary_indirect_blacklist.items():
        if binary_name.find(k) >= 0:
            log.debug(f"Found binary {binary_name}'s indirect blacklist: {v}...")
            return v
    return tuple()


def search_binary_all_blacklists(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    all_lists = list(external_blacklist) + list(general_blacklist)

    for k, v in binary_indirect_blacklist.items():
        if binary_name.find(k) >= 0:
            log.debug(f"Found binary {binary_name}'s indirect blacklist: {v}...")
            all_lists += list(v)
    for k, v in binary_function_blacklist.items():
        if binary_name.find(k) >= 0:
            log.debug(f"Found binary {binary_name}'s function blacklist: {v}...")
            all_lists += list(v)

    return all_lists


def search_binary_indirect_rule_blacklists(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    all_rules = list(external_rule_blacklist)

    for k, v in binary_indirect_rule_blacklist.items():
        if binary_name.find(k) >= 0:
            all_rules += list(v)
            break

    return all_rules


def search_binary_rule_blacklist(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    all_rules = list(external_rule_blacklist)

    for k, v in binary_rule_blacklist.items():
        if binary_name.find(k) >= 0:
            all_rules += list(v)
            break

    return all_rules


def search_indirect_enforce_list(pal_proj: 'PalProject'):
    fpath = os.path.join(pal_proj.arg_info.binary_output_path, "indirect_enforce.txt")
    if not os.path.exists(fpath):
        return {}
    with open(fpath, "r") as f:
        d = json.load(f)

    res_dict = {}
    for k, vmap in d.items():
        res_dict[k] = {}
        for k2, vlist in vmap.items():
            nk = int(k2)
            res_dict[k][nk] = vlist

    return res_dict
