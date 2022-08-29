import networkx as nx
from networkx import NetworkXNoCycle


def has_path(graph: nx.DiGraph, src_name: str, dst_name: str):
    src_node = next(iter(filter(lambda n: n.func.name == src_name, graph.nodes)))
    dst_node = next(iter(filter(lambda n: n.func.name == dst_name, graph.nodes)))
    return nx.has_path(graph, src_node, dst_node)


def func_in_graph(graph: nx.DiGraph, func_name_rule: str):
    nodes = list(filter(lambda n: n.func.name.find(func_name_rule) >= 0, graph.nodes))
    return nodes


class SCCPlaceholder:
    __slots__ = ['scc_id']

    def __init__(self, scc_id):
        self.scc_id = scc_id

    def __eq__(self, other):
        return isinstance(other, SCCPlaceholder) and other.scc_id == self.scc_id

    def __hash__(self):
        return hash('scc_placeholder_%d' % self.scc_id)


class GraphUtils:
    @staticmethod
    def my_acyclic_graph(G: nx.DiGraph) -> nx.DiGraph:
        nG = G.copy()
        try:
            while True:
                prune_edge = list(nx.find_cycle(nG, orientation="original"))[-1]
                nG.remove_edge(prune_edge[0], prune_edge[1])
        except NetworkXNoCycle:
            pass
        return nG

    @staticmethod
    def angr_acyclic_graph(graph) -> nx.DiGraph:

        if graph.number_of_nodes() == 1:
            return graph

        # make a copy to the graph since we are gonna modify it
        graph_copy = nx.DiGraph()

        # find all strongly connected components in the graph
        sccs = [ scc for scc in nx.strongly_connected_components(graph) if len(scc) > 1 ]

        # collapse all strongly connected components
        for src, dst in graph.edges():
            scc_index = GraphUtils._components_index_node(sccs, src)
            if scc_index is not None:
                src = SCCPlaceholder(scc_index)
            scc_index = GraphUtils._components_index_node(sccs, dst)
            if scc_index is not None:
                dst = SCCPlaceholder(scc_index)

            if isinstance(src, SCCPlaceholder) and isinstance(dst, SCCPlaceholder) and src == dst:
                continue
            if src == dst:
                continue

            graph_copy.add_edge(src, dst)

        # add loners
        out_degree_zero_nodes = [node for (node, degree) in graph.out_degree() if degree == 0]
        for node in out_degree_zero_nodes:
            if graph.in_degree(node) == 0:
                graph_copy.add_node(node)

        # topological sort on acyclic graph `graph_copy`
        return graph_copy

    @staticmethod
    def _components_index_node(components, node):

        for i, comp in enumerate(components):
            if node in comp:
                return i
        return None