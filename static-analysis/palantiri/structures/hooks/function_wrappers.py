import os
import angr
from angr.knowledge_plugins.functions import Function
from typing import Union
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

function_plt_wrappers = {
    "xmalloc": "malloc", "xnmalloc": "malloc", "xzalloc": "malloc", "xcharalloc": "malloc",
    "xcalloc": "calloc",
    "xrealloc": "realloc", "x2nrealloc": "realloc", "x2realloc": "realloc",
    # for nginx
    "ngx_alloc": "malloc", "ngx_calloc": "malloc",
    "ngx_palloc": "malloc", "ngx_pnalloc": "malloc", "ngx_palloc_small": "malloc", "ngx_palloc_block": "malloc",
    "ngx_palloc_large": "malloc"
}

function_special_wrappers = {
    ("xmalloc", "xnmalloc", "xzalloc"): "malloc",
    ("xcalloc",): "calloc",
    ("xrealloc", "x2nrealloc", "x2realloc"): "realloc",
    # nginx special wrappers
    ("ngx_palloc", "ngx_pnalloc",): "xxx_palloc",
    ("ngx_calloc",): "ngx_calloc",
    ("ngx_sprintf",): "ngx_printf",
    # httpd special wrappers
    ("apr_palloc",): "xxx_palloc",
    ("apr_bucket_alloc"): "apr_bucket_alloc",
    # sendmail special wrappers
    ("sm_malloc_tagged",): "sm_malloc_tagged",
    ("sm_malloc_tagged_x",): "sm_malloc_tagged_x",
}


function_fake_wappers = {
}


def get_hooked_plt_function(proj: angr.Project, func: Union[Function, str]):
    fname = func.name if isinstance(func, Function) else func
    try:
        hook_name = function_plt_wrappers[fname]
    except KeyError:
        return None
    return proj.kb.functions[hook_name]


def apply_special_hook(proj: angr.Project):
    """
    :param proj:
    :return:
    """
    for k, v in function_special_wrappers.items():
        for func_name in k:
            try:
                func = proj.kb.functions[func_name]
                func.info["hook"] = v
                func.is_plt = True
                log.info(f"Hooked function: {func_name} to special handler {v}.")
            except KeyError:
                continue


def apply_plt_hook(proj: angr.Project):
    """
    Hook functions to relevant plt functions and mark the original functions as plts, i.e. xmalloc -> malloc.
    """
    for fname in function_plt_wrappers:
        try:
            func = proj.kb.functions[fname]
            func.is_plt = True
            log.info(f"Hooked function: {fname} to plt function {function_plt_wrappers[fname]}.")
        except KeyError:
            continue


def apply_fake_hook(proj: angr.Project):
    """
    Create fake functions and hook
    """
    hook_base_addr = 0x400000
    pname = os.path.basename(proj.filename)
    try:
        fakehook_dict = function_fake_wappers[pname]
    except KeyError:
        return

    for addr, fname in fakehook_dict.items():
        func = Function(
            proj.kb.functions, hook_base_addr + addr, fname, is_plt=True, returning=True
        )
        func.info["fake"] = True
        proj.kb.functions[func.addr] = func
        log.info(f"Hooked fake function: {func.name}.")