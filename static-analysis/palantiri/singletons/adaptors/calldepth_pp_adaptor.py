from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.cfg.cfg_util import CGNode
from palantiri.global_configs import *

from misc.debugger import debug_print_log

from angr.knowledge_plugins.functions import Function
from typing import List, Tuple
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CalldepthPPAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    A fixed calldepth adaptor (currently calldepthppadaptor <calldepth++ adaptor>) for 
    sendmail only now. (resolve collect_eoh -> dfopen)
    # FIXME: generalize
    """
    def __init__(self, max_depth):
        super(CalldepthPPAdaptor, self).__init__()
        self.max_depth = max_depth

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if caller.is_plt or callee.is_plt:
            return True
        # filter caller-callee pruned by loop
        elif callee in self.syscall_slice_functions and caller in self.syscall_slice_functions and (
            CGNode(caller.addr, caller), CGNode(callee.addr, callee)
        ) not in self.syscall_slice_graph.edges: # pruned by loop
            debug_print_log(self.pal_project, f"Calldepth Adaptor dismiss {caller.name} -> {callee.name} (In loop)",
                            logger=log, min_vlevel=1)
            return False
        elif callee in self.syscall_slice_functions or caller in self.syscall_slice_functions:
            # patch: max depth=0
            if self.max_depth == 0 and not callee in self.syscall_slice_functions:
                return False
            return True
        # determine calldepth
        else:
            call_context_functions = list(map( 
            lambda callsite: self.project.kb.functions[ 
                self.pal_project.cfg.model.get_any_node(callsite).function_address
                ], 
            call_context
            ))
            depth = self._get_depth(call_context_functions)
            if depth >= self.max_depth:
                debug_print_log(self.pal_project, 
                                message=f"Calldepth Adaptor dismiss {caller.name} -> {callee.name} (max current irrelevant depth "
                                        f"{depth} > threshold {self.max_depth})",
                                min_vlevel=1, logger=log)
                return False
            else:
                return True
    
    def _get_depth(self, call_stack_functions: List[Function]):
        depth = 0
        
        while call_stack_functions:
            last_func = call_stack_functions.pop()
            if last_func in self.rw_segment_functions or depth >= self.max_depth:
                return depth
            depth += 1
            continue

        return min(depth, self.max_depth)

    def set_from_manager(self, manager):
        super().set_from_manager(manager)
        if self.pal_project.arg_info.args.irrelevant_call_depth != 3:
            self.max_depth = self.pal_project.arg_info.args.irrelevant_call_depth

            log.info(f"updated max depth: {self.max_depth}")


calldepth_pp_adaptor = CalldepthPPAdaptor(max_depth=3)