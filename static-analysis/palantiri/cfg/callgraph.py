
from typing import Dict, List, Optional, Union, Set, TYPE_CHECKING
from collections import deque
from functools import reduce

import angr
from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.codenode import BlockNode
from angr.block import Block
from angr.knowledge_plugins.functions import Function
import networkx as nx

from palantiri.cfg.cfgtest import *

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CGNode:
    """
    This class stands for the node of callgraph, which could be recovered from CFG
    """
    def __init__(self, addr: int, func: Function):
        self.addr = addr
        self.func = func
        self.is_plt = func.is_plt

    def setup_from_dump(self, project: angr.Project):
        self.func = project.kb.functions[self.addr]

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        if not isinstance(other, CGNode):
            return False
        return self.addr == other.addr

    def __repr__(self):
        return f"<CGNode func_addr: {hex(self.addr)}, function: {self.func.name}>"

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k != "func"}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.func = None


class CallGraph:
    """
    Call Graph
    """
    def __init__(self, pal_project: 'PalProject', graph: Optional[nx.DiGraph]=None):
        self.pal_project = pal_project
        self.angr_project = pal_project.angr_project
        self.graph = nx.DiGraph() if not graph else graph

    @property
    def nodes(self):
        return self.graph.nodes

    @property
    def edges(self):
        return self.graph.edges

    def add_node(self, node: CGNode):
        self.graph.add_node(node)

    def add_edge(self, unode: CGNode, vnode: CGNode, callsite=None):
        if (unode, vnode) in self.graph.edges:
            self.graph.edges[unode, vnode]["callsite"].append(callsite)
        else:
            self.graph.add_edge(unode, vnode, callsite=[callsite])

    def remove_edge(self, unode: CGNode, vnode: CGNode, callsite=None):
        if not (unode, vnode) in self.edges:
            log.error(f"({unode}, {vnode}) is not in callgraph.")
            return

        if callsite is None:
            self.graph.remove_edge(unode, vnode)
            return

        callsites: List = self.edges[unode, vnode]["callsite"]
        if callsite in callsites:
            callsites.remove(callsite)

        if len(callsites) == 0:
            self.graph.remove_edge(unode, vnode)

    def setup_from_dump(self, pal_project: 'PalProject'):
        self.pal_project = pal_project
        new_graph = nx.DiGraph()

        for u, v, d in self.graph.edges(data=True):
            u_addr, v_addr = u.addr, v.addr
            u_node = CGNode(u_addr, self.angr_project.kb.functions[u_addr])
            v_node = CGNode(v_addr, self.angr_project.kb.functions[v_addr])

            new_graph.add_node(u_node)
            new_graph.add_node(v_node)
            new_graph.add_edge(u_node, v_node, callsite=d["callsite"])

        self.graph.clear()
        self.graph = new_graph

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k != "pal_project"}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.pal_project = None

    def __repr__(self):
        return "CallGraph"


class CallGraphAcyclic(CallGraph):

    def __init__(self, pal_project: 'PalProject', graph: Optional[nx.DiGraph], force_dump_path=None, auto_save=True,
                 force_generate=False):
        """
        :param force_generate: Just pass the graph and return the CallGraphAcyclic object
        :param topo_sort_order_list: An optional order list to guide pruning the cycle, since nx.find_cycle() may not
                                     precisely find a cycle in topological sorting order
        """

        super(CallGraphAcyclic, self).__init__(pal_project, graph)
        dump_path = force_dump_path if force_dump_path else self.dump_path

        if not force_generate and os.path.exists(dump_path):
            with open(dump_path, "rb") as f:
                self.graph = pickle.load(f)
            self.setup_from_dump(pal_project)
        else:
            self.graph = graph.copy() if graph is not None else nx.DiGraph()
            if not force_generate:
                # FIXME: hard code method now
                if self.pal_project.angr_project.filename.find("postgres") >= 0 or \
                    self.pal_project.angr_project.filename.find("proftpd") >= 0:
                    self._dfs_prune_cycle()
                else:
                    self._prune_cycle()
                # for memoization of transitive_closure
                self._transitive_closures: Dict = {}
                if auto_save:
                    self._save(force_save_path=force_dump_path)

    @property
    def dump_path(self):
        return os.path.join(self.pal_project.arg_info.binary_output_path, "callgraph_acyclic_model.dump")

    def _prune_cycle(self):
        # TODO(): this function needs to be refined
        try:
            while True:
                cycle_edges = list(nx.find_cycle(self.graph, orientation="original"))
                prune_edge = cycle_edges[-1]
                self.graph.remove_edge(prune_edge[0], prune_edge[1])
        except:
            pass
    
    def _dfs_prune_cycle(self):
        active_node_queue = CFGUtils.quasi_topological_sort_nodes(graph=self.graph) 
        proceeded_nodes = set()

        # DFS in a top-bottom style 
        while active_node_queue:

            current_node = active_node_queue.pop(0)
            
            if current_node in proceeded_nodes:
                continue
            
            # the queue for dfs starting from current node
            dfs_queue = deque([current_node])
            node_visited_map = {current_node: set([current_node])} # node: set(visited)
            
            while dfs_queue:
                node = dfs_queue.popleft()
                # add to global proceeded set
                proceeded_nodes.add(node)

                visited_set = node_visited_map[node]

                out_nodes = set(vnode for _, vnode in self.graph.out_edges(node))

                # recognize and delete loop edges
                looped_outnodes = set(filter(lambda n: n in visited_set, out_nodes))
                for looped_out_n in looped_outnodes:
                    self.graph.remove_edge(node, looped_out_n)
                # child nodes to proceed
                next_nodes = set(filter(lambda n: n not in proceeded_nodes, 
                                        out_nodes - looped_outnodes))
                for next_node in next_nodes:
                    node_visited_map[next_node] = visited_set | {next_node}
                
                dfs_queue.extendleft(next_nodes)
        pass


    def _save(self, force_save_path=None):
        # FIXME: DBG
        log.info(f"Saving Acyclic callgraph model...")
        save_path = force_save_path if force_save_path else self.dump_path
        if os.path.exists(save_path):
            log.info(f"Acyclic callgraph model already saved at {save_path}.")
            return
        with open(save_path, "wb") as f:
            pickle.dump(self.graph, f, protocol=pickle.HIGHEST_PROTOCOL)
            log.info(f"Acyclic callgraph saved at {save_path}.")

    def get_node(self, thing: Union[int, BlockNode, Block, Function]):
        if isinstance(thing, BlockNode) or isinstance(thing, Block):
            addr = thing.addr
        elif isinstance(thing, Function):
            addr = thing.addr
        else:
            addr = thing
        for node in self.nodes:
            if node.addr == addr:
                return node
        return None

    def transitive_closure(self, function: Function) -> Optional[nx.DiGraph]:
        """
        Get the transitive closure for the function
        :param function:
        :return:
        """
        all_functions = self.retrieve_all_functions()
        if function not in all_functions:
            log.error(f"Function {function.name} is not in CallGraph.")
            return None
        # reset
        self._transitive_closures = {}
        def _transitive_closure(func: CGNode, graph: nx.DiGraph, result: nx.DiGraph,
                                visited: Optional[Set[CGNode]]=None):
            if func in self._transitive_closures:
                closure = self._transitive_closures[func]
                # merge closure into result
                result.add_edges_from(closure.edges())
                return result

            if func not in graph:
                return result

            predecessors = list(graph.predecessors(func))
            result.add_node(func)
            result.add_edges_from(list(map(
                lambda e: (*e, graph.get_edge_data(*e)),
                map(
                    lambda p: (p, func),
                    predecessors
                )
            )))

            visited = visited or set()
            visited.add(func)
            predecessors_to_visit = set(predecessors) - set(visited)

            closure = reduce(
                lambda acc, func0: _transitive_closure(func0, graph, acc, visited),
                predecessors_to_visit,
                result
            )

            self._transitive_closures[func] = closure
            return closure

        func_node = CGNode(function.addr, function)
        res = _transitive_closure(func_node, self.graph, nx.DiGraph())
        # clear tmp map
        self._transitive_closures = {}
        return res

    def retrieve_all_functions(self):
        funcs = []
        for node in self.nodes:
            node: CGNode
            funcs.append(node.func)
        return funcs

    def topological_order_funcs_reversed(self):
        return list(reversed(list(nx.topological_sort(self.graph))))

    def topological_order_funcs(self):
        return list(nx.topological_sort(self.graph))

    def __repr__(self):
        return "CallGraphAcyclic"


class AcGenerator():

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph.copy() # Callgraph
        self.acyclic_graph = None
        
    def _process(self):
        if self.acyclic_graph:
            return

        active_node_queue = CFGUtils.quasi_topological_sort_nodes(graph=self.graph) 
        proceeded_nodes = set()

        # DFS in a top-bottom style 
        while active_node_queue:

            current_node = active_node_queue.pop(0)
            
            if current_node in proceeded_nodes:
                continue
            
            # the queue for dfs starting from current node
            dfs_queue = deque([current_node])
            node_visited_map = {current_node: set([current_node])} # node: set(visited)
            
            while dfs_queue:
                node = dfs_queue.popleft()
                # add to global proceeded set
                proceeded_nodes.add(node)

                visited_set = node_visited_map[node]

                out_nodes = set(vnode for _, vnode in self.graph.out_edges(node))

                # recognize and delete loop edges
                looped_outnodes = set(filter(lambda n: n in visited_set, out_nodes))
                for looped_out_n in looped_outnodes:
                    self.graph.remove_edge(node, looped_out_n)
                # child nodes to proceed
                next_nodes = set(filter(lambda n: n not in proceeded_nodes, 
                                        out_nodes - looped_outnodes))
                for next_node in next_nodes:
                    node_visited_map[next_node] = visited_set | {next_node}
                
                dfs_queue.extendleft(next_nodes)

        self.acyclic_graph = self.graph
        pass
