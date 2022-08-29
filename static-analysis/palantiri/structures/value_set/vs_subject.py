from angr.knowledge_plugins.functions import Function
from angr.analyses.reaching_definitions.subject import Subject
from typing import Union, Any, List

from palantiri.cfg.cfgtest import *
from misc.graph_utils import GraphUtils
from palantiri.structures.value_set.vs_graphvisitor import VSFuncGraphVisitor

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class VSSubject(Subject):
    def __init__(self, project: angr.Project, content, func_graph=None, cc=None, refine_graph=True):
        super(VSSubject, self).__init__(content, func_graph, cc)
        self._content: Function
        self.project = project
        self.refined_func_graph = None
        self._endpoints = []

        if not isinstance(content, Function):
            raise TypeError("VSSubject should have a Function content.")

        if refine_graph:
            self.refined_func_graph = self.refine_function_graph()
        else:
            self.refined_func_graph = func_graph

        self.acyclic_func_graph = GraphUtils.my_acyclic_graph(self.refined_func_graph)
        self._visitor = VSFuncGraphVisitor(content, self.refined_func_graph)

    @property
    def endpoints(self):
        if not self._endpoints:
            self._endpoints = self.get_endpoints()
        return self._endpoints

    @property
    def func_graph(self):
        if self._func_graph is None:
            self._func_graph = self._content.graph
        return self._func_graph

    def get_endpoints(self):
        """
        Get the transition(jumpout site) & return block addresses for the subject function
        """
        endpoints = self.content.endpoints_with_type
        sets = set()
        sets.update(endpoints['return'])
        sets.update(endpoints['transition'])
        points = []
        for node in sets:
            points.append(node.addr)
        return points

    def refine_function_graph(self):
        """
        Refine function local transition graph. Prune some aligned nodes (such as nop nodes), and also check all those
        node with no out-degree carefully, to manually complete such transition edges.
        """
        origin_graph = self.func_graph
        refined_graph = origin_graph.copy()

        # 1. prune all the aligned nodes
        # 1.1 get all aligned nodes
        aligned_nodes = []
        for node in origin_graph.nodes:
            blk = self.project.factory.block(addr=node.addr, size=node.size)
            if len(blk.capstone.insns) == 1 and \
                blk.capstone.insns[-1].mnemonic == "nop":
                aligned_nodes.append(node)
        # 1.2 prune
        for nop_node in aligned_nodes:
            in_edges = origin_graph.in_edges(nop_node)
            out_edges = origin_graph.out_edges(nop_node)
            if not len(in_edges):
                for _, out_node in out_edges:
                    refined_graph.remove_edge(nop_node, out_node)
                refined_graph.remove_node(nop_node)
            elif not len(out_edges):
                for in_node, _ in in_edges:
                    refined_graph.remove_edge(in_node, nop_node)
                refined_graph.remove_node(nop_node)
            else:
                pass
                # FIXME: in order to adapt the PT trace, now we do not filter 
                # FIXME: such nops 
                # for u_node, _ in in_edges:
                #     for _, v_node in out_edges:
                #         # remove original edges
                #         refined_graph.remove_edge(u_node, nop_node)
                #         refined_graph.remove_edge(nop_node, v_node)
                #         # add new connected edge
                #         refined_graph.add_edge(u_node, v_node)
                # refined_graph.remove_node(nop_node)

        return refined_graph

    def get_function_node(self, nodekey: Union[int, Any]):
        nodekey = nodekey if isinstance(nodekey, int) else nodekey.addr
        for node in self.refined_func_graph.nodes:
            if node.addr == nodekey:
                return node
        return None

    def get_predecessor_nodes(self, nodekey: Union[int, Any]) -> List:
        nodekey = nodekey if isinstance(nodekey, int) else nodekey.addr
        node = self.get_function_node(nodekey)
        if not node:
            return []

        return list(filter(lambda n: n.addr != nodekey, self.refined_func_graph.predecessors(node)))

    def __hash__(self) -> int:
        return hash((self.project.filename, self.content.name))

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, VSSubject):
            return False
        return self.content.name == __o.content.name

    def __repr__(self):
        return f"<VSSubject {self.content.name}>"