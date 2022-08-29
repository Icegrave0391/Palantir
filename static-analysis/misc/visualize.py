
# first      pip install pygraphviz
#            pip install graphviz
# If ^ doesn't work, then try
#            sudo apt-get install -y graphviz-dev
import pygraphviz as pgv
import networkx as nx
import angr
import os
from pathlib import Path
from palantiri.arginfo import ArgInfo
from angr.analyses.cfg import CFGFast
from angr.knowledge_plugins.cfg import CFGNode
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions import Function

from palantiri.cfg.callgraph import CallGraph, CGNode
import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class V:
    def __init__(self, p: angr.Project, a: ArgInfo):
        self.proj = p
        self.a = a

    def draw_transitive_graph(self, transitive_closure: nx.DiGraph, name=None):
        out = nx.DiGraph()
        name = "whole_transitive_closure" if name is None else name
        log.debug(f"Processing on debug_draw graph, it may take a few minutes...")

        def out_node(n: CGNode):
            addr = hex(n.addr)
            funcname = n.func.name
            if n.is_plt:
                funcname += "@plt"
            return addr + " " + funcname

        for n in transitive_closure.nodes:
            out.add_node(out_node(n))

        for e in transitive_closure.edges:
            out.add_edge(out_node(e[0]), out_node(e[1]))
        
        drop = str(Path(self.a.transitive_graph_output_path).joinpath(f"{name}"))
        nx.drawing.nx_agraph.write_dot(out, drop + ".dot")
        G = pgv.AGraph(drop + ".dot")
        G.draw(drop + ".pdf", prog="dot")
        os.system(f"rm {drop}.dot")
        

    def draw_call_graph(self, callgraph: CallGraph):
        out = nx.DiGraph()
        log.debug(f"Processing on debug_draw graph, it may take a few minutes...")
        def out_node(n:CGNode):
            addr = hex(n.addr)
            funcname = n.func.name
            if n.is_plt:
                funcname += "@plt"
            return addr + " " + funcname

        for n in callgraph.graph.nodes:
            out.add_node(out_node(n))

        for e in callgraph.graph.edges:
            label = ""
            cs = callgraph.graph.edges[e[0], e[1]]["callsite"]
            for addr in cs:
                label = label + hex(addr) + ", "
            out.add_edge(out_node(e[0]), out_node(e[1]), label=label)

        drop = str(Path(self.a.binary_output_path).joinpath(f"{self.__repr__()}"))
        nx.drawing.nx_agraph.write_dot(out, drop+".dot")
        G = pgv.AGraph(drop+".dot")
        G.draw(drop+".pdf", prog="dot")
        os.system(f"rm {drop}.dot")

    def draw_function_graph(self, function: Function, graph=None):
        """
        Draw the graph and save it to a PNG file.
        """
        import matplotlib.pyplot as pyplot  # pylint: disable=import-error
        from networkx.drawing.nx_agraph import graphviz_layout  # pylint: disable=import-error

        def node(n: BlockNode):
            blk = self.proj.factory.block(n.addr, n.size)
            addr = hex(n.addr)
            insn_s = ""
            for insn in blk.capstone.insns:
                insn_desp = "%#x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)
                if insn.mnemonic == "call":
                    tar = function.get_call_target(n.addr)
                    if isinstance(tar, int):
                        try:
                            tar_name = self.proj.kb.functions[tar].name
                        except KeyError:
                            tar_name = "???"
                        insn_s = (insn_s + insn_desp + f"({tar_name})" + "\n")
                    else:
                        insn_s = (insn_s + insn_desp + '\n')
                else:
                    insn_s = (insn_s + insn_desp + '\n')
            sym = function.name
            return "<" + addr + " " + sym + ">" + "\n" + insn_s

        tmp_graph = nx.DiGraph()

        grh = graph if graph is not None else function.graph

        for from_block, to_block in grh.edges():
            node_a, node_b = node(from_block), node(to_block)
            tmp_graph.add_edge(node_a, node_b)
        if not len(tmp_graph.edges):
            for n in grh.nodes:
                tmp_graph.add_node(node(n))
        # pos = graphviz_layout(tmp_graph, prog='fdp')   # pylint: disable=no-member
        drop = os.path.join(self.a.function_graph_output_path, "function_%s" % function.name)
        nx.drawing.nx_agraph.write_dot(tmp_graph, drop + '.dot')
        G = pgv.AGraph(drop + '.dot')
        G.draw(drop + '.pdf', prog='dot')
        os.system(f"rm {drop}.dot")

    def draw_cfg(self, cfg: CFGFast):
        """
        Draw the graph and save it to a PNG file.
        """
        import matplotlib.pyplot as pyplot  # pylint: disable=import-error
        from networkx.drawing.nx_agraph import graphviz_layout  # pylint: disable=import-error

        def node(n: CFGNode):
            blk = n.block
            addr = hex(n.addr)
            insn_s = ""
            if blk is not None:
                for insn in blk.capstone.insns:
                    insn_desp = "%#x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)
                    insn_s = (insn_s + insn_desp + '\n')
            sym = ""
            if n.function_address in self.proj.kb.functions:
                sym = self.proj.kb.functions[n.function_address].name
            return "<" + addr + " " + sym + ">" + "\n" + insn_s

        tmp_graph = nx.DiGraph()
        for from_block, to_block in cfg.graph.edges:
            node_a, node_b = node(from_block), node(to_block)
            tmp_graph.add_edge(node_a, node_b)

        if not len(tmp_graph.edges):
            for n in cfg.graph.nodes:
                tmp_graph.add_node(node(n))
        # pos = graphviz_layout(tmp_graph, prog='fdp')   # pylint: disable=no-member
        drop = os.path.join(self.a.binary_output_path, "cfg")
        nx.drawing.nx_agraph.write_dot(tmp_graph, drop + '.dot')
        G = pgv.AGraph(drop + '.dot')
        G.draw(drop + '.pdf', prog='dot')
        os.system(f"rm {drop}.dot")