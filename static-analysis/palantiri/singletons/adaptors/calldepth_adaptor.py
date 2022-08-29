from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.cfg.cfg_util import CGNode
from palantiri.global_configs import *

from misc.debugger import debug_print_log

from angr.knowledge_plugins.functions import Function
from typing import Tuple
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CalldepthAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Calldepth Adaptor is used for pruning deep calls which are irrelevant to syscall_slice_functions.
    # TODO(): this call depth tracker is buggy, since it won't manipulate the call depth correctly 
    # TODO(): when a function returns (denoted as https://github.com/Icegrave0391/palantiri/issues/37)
    """
    def __init__(self, max_depth):
        super(CalldepthAdaptor, self).__init__()
        self.max_depth = max_depth
        self.current_depth = 0

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if caller.is_plt or callee.is_plt:
            return True

        if callee in self.syscall_slice_functions and caller in self.syscall_slice_functions and (
            CGNode(caller.addr, caller), CGNode(callee.addr, callee)
        ) not in self.syscall_slice_graph.edges: # pruned by loop
            debug_print_log(self.pal_project, f"Calldepth Adaptor dismiss {caller.name} -> {callee.name} (In loop)",
                            logger=log, min_vlevel=1)
            return False
        elif callee in self.syscall_slice_functions:
            self.current_depth = 0
            return True
        elif caller in self.syscall_slice_functions:
            self.current_depth = 1
            if self.current_depth > self.max_depth:
                return False
            return True
        else:
            self.current_depth += 1
            if self.current_depth > self.max_depth:
                debug_print_log(self.pal_project, 
                                message=f"Calldepth Adaptor dismiss {caller.name} -> {callee.name} (max current irrelevant depth "
                                        f"{self.current_depth} > threshold {self.max_depth})",
                                min_vlevel=1, logger=log)
                self.current_depth -= 1
                return False
            else:
                return True

    def set_from_manager(self, manager):
        super().set_from_manager(manager)
        if self.pal_project.arg_info.args.irrelevant_call_depth != 3:
            self.max_depth = self.pal_project.arg_info.args.irrelevant_call_depth

            log.info(f"updated max depth: {self.max_depth}")
        pass
    

calldepth_adaptor = CalldepthAdaptor(max_depth=3)