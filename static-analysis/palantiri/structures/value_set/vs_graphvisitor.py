from angr.analyses.forward_analysis.visitors import FunctionGraphVisitor
from angr.knowledge_plugins.functions import Function

from ...cfg.callgraph import CGNode

import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class VSFuncGraphVisitor(FunctionGraphVisitor):
    def __init__(self, func, graph=None):
        super(VSFuncGraphVisitor, self).__init__(func, graph)

    def next_node(self):
        """
        Get the next node to visit.

        :return: A node in the graph.
        """

        if not self._sorted_nodes:
            return None

        node = self._sorted_nodes.pop(0)
        self._nodes_set.remove(node)
        return node

    def revisit_successors(self, node, include_self=False):
        """
        TODO(): fix that, the current version only visit node once
        Since we are not a fix-point based analysis, we should not take care of this!
        """
        pass


class VSCallGraphVisitor:
    def __init__(self, callgraph):
        self.callgraph = callgraph

    def handle_inter_procedural(self, caller_func: Function, callee: Function, callsite: int) \
            -> bool:
        if caller_func.is_plt or callee.is_plt:
            return True

        unode, vnode = CGNode(caller_func.addr, caller_func), CGNode(callee.addr, callee)
        if not (unode, vnode) in self.callgraph.edges:
            return False

        callsites = self.callgraph.edges[unode, vnode]["callsite"]
        if not callsite in callsites:
            return False

        self.callgraph.remove_edge(unode, vnode, callsite=callsite)
        return True

