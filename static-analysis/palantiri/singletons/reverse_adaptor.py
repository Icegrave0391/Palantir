import angr
from ..cfg.cfg_util import CFGAnalysis
from .singleton_base import SingletonType
from ..cfg.callgraph import CGNode, CallGraphAcyclic

from ..global_configs import *

from angr.knowledge_plugins.functions import Function
from typing import Tuple, Optional, TYPE_CHECKING, Dict, List
import networkx as nx
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class ReverseSummaryAdaptor(metaclass=SingletonType):
    """
    NOTE: this is experimental and unused currently.
    The adaptor for handling inter-procedural functions during FunctionSummary, in the reverse topologically sorted way.
    """
    def __init__(self):
        self.pal_project = None
        self.project: Optional[angr.Project] = None
        self.callgraph = None
        self.analyze_graph: Optional[CallGraphAcyclic] = None
        self.resolved_indirect_dict: Optional[Dict] = None
        self.sorted_functions = None

    def set_interface(self, interface):
        self.pal_project = interface._pal_project
        self.project = interface.project
        self.callgraph = interface.callgraph_acyclic

        # 1. complete call graph from indirect dict
        # try to search enforce indirect dict as resolved indirect dict
        enforce_dict = search_indirect_enforce_list(self.pal_project)
        if enforce_dict:
            self.resolved_indirect_dict = enforce_dict
            self._enrich_callgraph()

        # 2. initialize whitelist graph
        self._generate_analyze_graph()

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state) -> \
            bool:
        """
        Use whitelist functions to guide inter-procedural analysis
        :return:
        """
        # avoid self-loop call
        if caller == callee :
            log.debug(f"Reverse Adaptor dismiss {caller.name} -> {callee.name} (loop-call).")
            return False
        else:
            return True

    def _enrich_callgraph(self):
        """
        Enrich the call graph with the resolved results of indirect calls
        """
        if not self.resolved_indirect_dict:
            return
        for caller_name, vmap in self.resolved_indirect_dict.items():
            caller = self.project.kb.functions[caller_name]
            for callsite, calltargets in vmap.items():
                for tar_name in calltargets:
                    callee = self.project.kb.functions[tar_name]
                    self.callgraph.add_edge(CGNode(caller.addr, caller), CGNode(callee.addr, callee), callsite)
        # ensure the call graph is acyclic
        self.callgraph = CallGraphAcyclic(self.project, self.callgraph.graph)

    def _prune_callgraph(self) -> CallGraphAcyclic:
        """
        Prune un-interesting functions in call graph
        """
        # prune the insensitive functions from callgraph
        prune_graph = self.callgraph.graph.copy()
        # 1. prune binary blacklist
        func_to_remove = search_binary_function_blacklist(self.project)
        for fname in func_to_remove:
            try:
                func = self.project.kb.functions[fname]
                fnode = CGNode(func.addr, func)
                prune_graph.remove_node(fnode)
            except:
                continue
        # 2. prune external rule based blacklist
        rules = search_binary_rule_blacklist(self.project)
        nodes_to_remove = list(filter(lambda n: any(n.func.name.find(rule) >= 0 for rule in rules),
                                      prune_graph.nodes))
        try:
            prune_graph.remove_nodes_from(nodes_to_remove)
        except:
            pass
        return CallGraphAcyclic(self.project, prune_graph)

    def _generate_analyze_graph(self):
        """
        Generate whitelist graph for analysis.
        Whitelist graph only contains the "MUST TO ANALYZE DATA FLOW", which is reachable to read + recv + write + send
        """
        pruned_callgraph = self._prune_callgraph()
        rw_transitive_closure = CFGAnalysis.syscall_function_whitelist(self.project, pruned_callgraph,
                                                                       self.pal_project._cfg_util.cfg,
                                                                       function_keys=["read", "write", "send", "recv"],
                                                                       add_indirect=False)

        pruned_callgraph.graph.remove_nodes_from(rw_transitive_closure.nodes)

        # remove plt functions
        plt_nodes_to_remove = []
        for node in pruned_callgraph.nodes:
            if node.func.is_plt or node.func.is_simprocedure or node.func.name in ["UnresolvableCallTarget",
                                                                                   "UnresolvableJumpTarget"]:
                plt_nodes_to_remove.append(node)
        pruned_callgraph.graph.remove_nodes_from(plt_nodes_to_remove)

        # remove cold functions
        cold_nodes_to_remove = []
        for node in pruned_callgraph.nodes:
            if node.func.name.find(".cold") >= 0:
                cold_nodes_to_remove.append(node)
        pruned_callgraph.graph.remove_nodes_from(cold_nodes_to_remove)

        self.analyze_graph = CallGraphAcyclic(self.project, graph=pruned_callgraph.graph)
        self.sorted_functions = list(map(lambda n: n.func, self.analyze_graph.topological_order_funcs_reversed()))

    def setup_from_other(self, other: 'ReverseSummaryAdaptor'):
        for k in self.__dict__.keys():
            if k == "pal_project":
                continue
            setattr(self, k, getattr(other, k))

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k not in ("pal_project",)}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)


reverse_adaptor = ReverseSummaryAdaptor()