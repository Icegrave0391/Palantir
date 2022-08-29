import angr
import logging

from .singleton_base import SingletonType
from ..cfg.callgraph import CallGraphAcyclic
from typing import Dict, Tuple, Set, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

from angr.knowledge_plugins.functions import Function

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


# deprecated
class CallContextRecorder(metaclass=SingletonType):
    """
    CallContextRecorder maintains all the contexts to a call target function.
    The property context_map is to record such information. It's key is the target function's address, while it's
    value is a set of calling context (in tuple format, and each element in tuple is a (function, callsite)).
    """

    def __init__(self):
        self.context_map: Dict[int, Set[Tuple[Tuple[int, int]]]] = {}
        self.call_graph: Optional[CallGraphAcyclic] = None
        self.project: Optional[angr.Project] = None
        self.pal_project: Optional['PalProject'] = None

    def set_interface(self, interface):
        self.project: angr.Project = interface.project
        self.pal_project = interface._pal_project

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int]) -> \
            bool:
        """
        Determine whether ot not we should handle inter procedural analysis. (Remember that we should not handle the
        case that two same call targets share the same calling context. In other words, when both the whole callsites
        context and the call target are same, we should skip analyzing the target).
        """
        # we do not record context for plt functions
        if caller.is_plt or callee.is_plt:
            return True
        # record calling context for local functions

        # since interface's context only contains callsites, we add function info here
        l_call_context = []
        for callsite in call_context:
            cfgnode = self.pal_project.cfg_util.cfg.model.get_any_node(callsite)
            callsite_func_addr = cfgnode.function_address if cfgnode else 0
            l_call_context.append((callsite, callsite_func_addr))

        recorder_call_context: Tuple[Tuple[int, int]] = tuple(l_call_context)
        call_target = callee.addr
        if call_target not in self.context_map:
            self.context_map[call_target] = set()
            self.context_map[call_target].add(recorder_call_context)
            return True
        elif recorder_call_context not in self.context_map[call_target]:
            # determine whether there is a loop-call, we dismiss such calls

            caller_funcs = list(map(lambda cs: cs[1], recorder_call_context))
            if callee.addr in caller_funcs:
                log.debug(f"CallContextRecorder dismiss {hex(caller.addr)} -> {hex(callee.addr)} for loop context:"
                          f" {recorder_call_context}.")
                return False
            else:
                self.context_map[call_target].add(recorder_call_context)
                return True
        else:
            return False


context_recorder = CallContextRecorder()