from asyncio.log import logger
from email import message
from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.global_configs import *

from misc.debugger import debug_print_log

from angr.knowledge_plugins.functions import Function
from typing import Tuple
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class LoopcallAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Loopcall Adaptor used for filtering out loop calls or recursive calls during inter-procedural analysis.
    """
    def __init__(self):
        super(LoopcallAdaptor, self).__init__()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if caller.is_plt or callee.is_plt:
            return True
        
        context_function_addrs = list(map(lambda cs: self.pal_project.cfg.model.get_any_node(cs).function_address, call_context))

        if callee.addr in context_function_addrs or callee.addr == caller.addr:
            debug_print_log(self.pal_project, message=\
                f"Loopcall Adaptor dismiss {caller.name} -> {callee.name} (loop call in context).",
                min_vlevel=1, logger=log)
            return False
        return True


loopcall_adaptor = LoopcallAdaptor()