import angr
import os
import logging
from .whitelist_adaptor import whitelist_adaptor
from .indirect_adaptor import indirect_adaptor
from .sockforce_adaptor import sockforce_adaptor
from .loopcall_adaptor import loopcall_adaptor
from .blacklist_adaptor import blacklist_adaptor
from .calldepth_adaptor import calldepth_adaptor
from .special_adaptor import special_adaptor
from .segment_adaptor import segment_adaptor
from .calldepth_pp_adaptor import calldepth_pp_adaptor

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

binarysummary_all_adaptors = (
    whitelist_adaptor,
    indirect_adaptor,
    sockforce_adaptor,
    loopcall_adaptor,
    blacklist_adaptor,
    calldepth_adaptor,
    special_adaptor,
)

default_adaptors = (calldepth_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor, special_adaptor, segment_adaptor)

project_adaptors = {
    # "wget": (whitelist_adaptor, sockforce_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor),
    "nginx": (calldepth_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor, special_adaptor, segment_adaptor),
    "httpd": (calldepth_pp_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor, special_adaptor, segment_adaptor),
    "sendmail": (calldepth_pp_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor, special_adaptor, segment_adaptor),
    "varnishd": (calldepth_adaptor, indirect_adaptor, loopcall_adaptor, blacklist_adaptor),
}


def get_proper_adaptors(p: angr.Project):
    binary_name: str = os.path.basename(p.filename)
    for k, v in project_adaptors.items():
        if binary_name.find(k) >= 0:
            log.info(f"Found binary {binary_name}'s interproc adaptor: {v}...")
            return v

    return default_adaptors