import logging
import os
import pickle
from collections import deque
from pathlib import Path

import angr
from angr.analyses.cfg import CFGFast, CFGEmulated
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
import networkx as nx


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def get_block_exit(p: angr.Project, addr):
    exit_insn = None
    try:
        exit_insn = p.factory.block(addr).capstone.insns[-1].insn
    except BaseException:
        pass
    return exit_insn


def test_jumpkind(p: angr.Project, cfg: CFGFast):

    for node in cfg.graph.nodes:
        node: CFGNode
        exit_insn = get_block_exit(p, node.addr)

        if exit_insn is None:
            continue

        conflict = 0

        jumpkind = None
        # get jumpkind from cfg
        saj = node.successors_and_jumpkinds()
        for suc, jpk in saj:
            if jpk == "Ijk_Call":
                jumpkind = "Call"
            else:
                jumpkind = "Jump"
            break

        # get jumpkind from capstone (call or jump)
        j = None
        mnemonic = exit_insn.mnemonic
        if mnemonic == "call" or mnemonic.startswith("j"):
            j = "Call" if mnemonic == "call" else "Jump"

        if jumpkind != j:
            log.error(f"conflict occured.")
            log.info(node)

        # assert (jumpkind == j)


def get_unreachable_nodes(p: angr.Project, cfg: CFGFast):
        r = []
        for n in cfg.graph.nodes:
            n: CFGNode
            if len(n.predecessors) == 0:
                r.append(n)
        return r


def get_indirect_calls(p: angr.Project, cfg: CFGFast):
    sites = []
    for n in cfg.graph.nodes:
        n: CFGNode
        out_insn = get_block_exit(p, n.addr)
        if not out_insn:
            continue
        mnemonic = out_insn.mnemonic
        if mnemonic == "call" or mnemonic.startswith("j"):
            jpk = "Ijk_Call" if mnemonic == "call" else "Ijk_boring"
            if(
                out_insn.reg_name(out_insn.operands[0].value.reg) or
                "ptr" in out_insn.op_str or
                out_insn.disp != 0
            ):
                log.info(f"node {hex(n.addr)}, {jpk}, {out_insn}")
                sites.append([(n.addr, jpk, out_insn)])

    return sites