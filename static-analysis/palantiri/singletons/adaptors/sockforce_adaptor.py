from palantiri.cfg.cfg_util import CFGAnalysis
from palantiri.singletons.singleton_base import SingletonType
from palantiri.cfg.callgraph import CGNode, CallGraphAcyclic

from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.global_configs import *

from angr.knowledge_plugins.functions import Function
from typing import Tuple, Optional
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class SockforceAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Sockforce Adaptor guided by the path of sliced call graph until socket -> connect, the inter procedural calls
    irrelevant to connect and before connect will be dismissed.
    """
    def __init__(self):
        super(SockforceAdaptor, self).__init__()
        self.force_guide_graph: Optional[CallGraphAcyclic] = None

    def set_from_manager(self, manager):
        super(SockforceAdaptor, self).set_from_manager(manager)
        self._generate_forceguide_graph()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        u_node, v_node = CGNode(caller.addr, caller), CGNode(callee.addr, callee)

        if caller.is_plt or callee.is_plt:
            return True

        # already connected, then de-activate this adaptor
        if caller_state.activate:
            self.adaptor_activate = False
            return True

        if self.force_guide_graph is not None and not caller_state.activate:
            if (u_node, v_node) not in self.force_guide_graph.edges:
                log.debug(f"Sockforce Adaptor dismiss {caller.name} -> {callee.name} (Avoid by "
                          f"socket-force-guide graph).")
                return False
        return True

    def _generate_forceguide_graph(self):
        """
        Generate force-guide graph for analysis.
        Force-guide graph is the first path that leads the analysis, which tries to avoid analyzing on substantive
        initialization steps for the program.

        For network programs, the force-guide graph will lead the path to connect first, and then that graph will be
        deprecated for conduct analysis.
        """
        connect_transitive_closure = CFGAnalysis.syscall_function_whitelist(self.project, self.pruned_callgraph,
                                                                            self.pal_project._cfg_util.cfg,
                                                                            function_keys=["connect"],
                                                                            add_indirect=False)
        self.force_guide_graph = CallGraphAcyclic(self.pal_project, graph=connect_transitive_closure) if \
            connect_transitive_closure.nodes else None


sockforce_adaptor = SockforceAdaptor()