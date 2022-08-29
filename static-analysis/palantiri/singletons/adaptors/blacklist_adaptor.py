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


class BlacklistAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Blacklist Adaptor used for filtering out calls to external blacklist functions during inter-procedural analysis.
    """
    def __init__(self):
        super(BlacklistAdaptor, self).__init__()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if caller.is_plt or callee.is_plt:
            return True
        # use rules to filter out insensitive functions
        for rule in external_rule_blacklist:
            if callee.name.find(rule) >= 0:
                debug_print_log(self.pal_project, message=\
                    f"Blacklist Adaptor dismiss {caller.name} -> {callee.name} (target in blacklist rule: {rule}).",
                    logger=log, min_vlevel=1)
                return False
        for rule in search_binary_rule_blacklist(caller_state.analysis.project):
            if callee.name.find(rule) >= 0:
                debug_print_log(self.pal_project, message=\
                    f"Blacklist Adaptor dismiss {caller.name} -> {callee.name} (target in blacklist rule: {rule}).",
                    logger=log, min_vlevel=1)
                return False
        for func_name in search_binary_function_blacklist(caller_state.analysis.project):
            if callee.name == func_name:
                debug_print_log(self.pal_project, message=\
                    f"Blacklist Adaptor dismiss {caller.name} -> {callee.name} (target in blacklist func: {func_name}).",
                    logger=log, min_vlevel=1)
                return False
        return True


blacklist_adaptor = BlacklistAdaptor()