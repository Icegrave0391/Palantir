from palantiri.singletons.singleton_base import SingletonType
from palantiri.cfg.callgraph import CGNode, CallGraphAcyclic

from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.global_configs import *

from angr.knowledge_plugins.functions import Function
from typing import Tuple, Optional, Dict
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class WhitelistAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    The adaptor for handling inter-procedural functions during static analysis.
    """
    def __init__(self):
        """
        :var whitelist_graph: a
        :var
        """
        super(WhitelistAdaptor, self).__init__()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state) -> \
            bool:
        """
        Use whitelist functions to guide inter-procedural analysis
        :return:
        """
        if caller.is_plt or callee.is_plt:
            return True
        u_node, v_node = CGNode(caller.addr, caller), CGNode(callee.addr, callee)
        if (u_node, v_node) in self.syscall_slice_graph.edges():
            return True
        else:
            log.debug(f"Whitelist Adaptor dismiss {caller.name} -> {callee.name} (contradict "
                      f"with syscall slice graph).")
            return False


whitelist_adaptor = WhitelistAdaptor()