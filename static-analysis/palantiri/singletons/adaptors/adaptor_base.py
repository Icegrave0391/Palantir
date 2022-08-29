from palantiri.singletons.singleton_base import SingletonType
from palantiri.cfg.callgraph import CGNode, CallGraphAcyclic

from palantiri.global_configs import *

from angr.knowledge_plugins.functions import Function
from typing import Tuple, Optional, TYPE_CHECKING, Dict, List
import logging

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class AdaptorBase(metaclass=SingletonType):

    def __init__(self):
        self.pal_project: Optional['PalProject'] = None
        self.project: Optional[angr.Project] = None
        self.callgraph = None
        self.pruned_callgraph = None
        self.syscall_slice_graph: Optional[CallGraphAcyclic] = None
        self._syscall_slice_functions = []
        self.rw_segment_functions = []

        self.resolved_indirect_dict: Optional[Dict] = None
        self.adaptor_activate = True

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        pass

    def handle_indirect_call(self, caller: Function, callsite: int) -> List[Optional[str]]:
        pass

    @property
    def syscall_slice_functions(self):
        if not self._syscall_slice_functions:
            if not self.syscall_slice_graph:
                log.warning(f"Should setup from adaptor manager first.")
                return []
            for node in self.syscall_slice_graph.nodes:
                self._syscall_slice_functions.append(node.func)
        return self._syscall_slice_functions

    def set_from_manager(self, manager):
        """
        Base implementation of set_from_manager, including set up the 
        pal_project and the manager's info for the adaptor

        Can be overwriten by subclasses to achieve more functionalities
        """
        self.pal_project = manager.pal_project
        self.project = manager.project
        self.callgraph = manager.callgraph
        self.pruned_callgraph = manager.pruned_callgraph
        self.syscall_slice_graph = manager.syscall_slice_graph
        self.resolved_indirect_dict = manager.resolved_indirect_dict
        self.rw_segment_functions = manager.rw_segment_functions

    def setup_from_other(self, other):
        for k in self.__dict__.keys():
            if k == "pal_project":
                continue
            setattr(self, k, getattr(other, k))

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k not in ("pal_project",)}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __repr__(self):
        return f"{self.__class__.__name__}"