from asyncio.log import logger
from decimal import InvalidContext
from email import message
from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.global_configs import *
from palantiri.structures.utils.anno_utils import get_abs_regions
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues

from misc.debugger import debug_print_log
from angr.knowledge_plugins.functions import Function
from typing import Tuple
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class InvalidType:
    NoRegions = 0,
    InvalidVal = 1,
    InvalidContext = 2,


special_function_and_param_set = {
    # heuristic for nginx
    "ngx_http_trailers_filter": {"param": "rsi", "invalid_type": InvalidType.NoRegions},
    # heuristics for sendmail
    "collect_eoh": {"caller_sites": (0x4100ed, ), "invalid_type": InvalidType.InvalidContext},
    "sm_io_putc": {"caller_sites": (0x4108b5, 0x41003a), "invalid_type": InvalidType.InvalidContext},
}


class SpecialAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Special Adaptor is used for magic heuristic, to determine whether or not we should step into some `KEY` functions.

    i.e. when a filter like ngx_output_filter(_, ngx_chain_t * out) is called, however param `out` is not set well, we
    will ignore such call.
    """
    def __init__(self):
        super(SpecialAdaptor, self).__init__()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if callee.name not in special_function_and_param_set:
            return True
        invalid_desc_dict = special_function_and_param_set[callee.name]
        param = invalid_desc_dict.get("param", None)
        invalid_type = invalid_desc_dict.get("invalid_type", None)
        invalid_callersites = invalid_desc_dict.get("caller_sites", [])

        if invalid_type == InvalidType.NoRegions:
            try:
                reg_offset, size = self.project.arch.registers[param]
                param_valset = caller_state.register_definitions.load(reg_offset, size)
            except:
                return True
            # check value regions
            regions = get_abs_regions(caller_state, param_valset)
            if not regions:
                debug_print_log(self.pal_project, message=\
                    f"Special Adaptor dismiss {caller.name} -> {callee.name} (Due to param {param} value-set: "
                    f"{param_valset} has no AbsRegions.",
                    min_vlevel=1, logger=log)
                return False

        elif invalid_type == InvalidType.InvalidContext:
            caller_site = call_context[-1]
            if caller_site in invalid_callersites:
                debug_print_log(self.pal_project, message=\
                    f"Special Adaptor dismiss {caller.name} -> {callee.name} (Due to the caller site: {hex(caller_site)})"
                    f" is invalid.)",
                    min_vlevel=1, logger=log)
                return False

        return True


special_adaptor = SpecialAdaptor()