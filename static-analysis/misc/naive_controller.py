from palantiri.analyses.binary_summary import BinarySummaryInterface, BinarySummary
from palantiri.pal_project import PalProject
from palantiri.structures.value_set.function_handler.bs_functionhandler import BSFunctionHandler
from palantiri.structures.value_set.vs_state import ValueSetState
from palantiri.cfg.cfg_util import CFGAnalysis
from arginfo import ArgInfo
from typing import Dict, Set, List
from collections import defaultdict

import claripy
from angr.knowledge_plugins.key_definitions.tag import TaintTag
from palantiri.structures.value_set.taint.taint_summary import TaintSummary, TaintType, TaintTag

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

a = ArgInfo()
pal_proj = PalProject(a)
log.debug(f"root dir: {a.root_dir_path}")
log.debug(f"debug file path: {a.dbg_file_path}")
log.debug(f"binary file path: {a.binary_file_path}")
log.debug(f"binary output path: {a.binary_output_path}")

c = pal_proj.cfg_util
p, cfg = c.proj, c.cfg
cg, cga = CFGAnalysis.recover_call_graph(pal_proj, cfg)
CFGAnalysis.fast_cc_analysis(p, cfg)
main = p.kb.functions['main']
handler = BSFunctionHandler()
bsi = BinarySummaryInterface(pal_proj, function_handler=handler, start_function=main)

reg_taint: Dict[int, Set[TaintTag]] = defaultdict(set)
mem_taint: Dict[int, Set[TaintTag]] = defaultdict(set)
stack_taint: Dict[int, Set[TaintTag]] = defaultdict(set)
heap_taint: Dict[int, Set[TaintTag]] = defaultdict(set)
symbol_taint: Dict[claripy.ast.Base, Set[TaintTag]] = defaultdict(set)

from palantiri.structures.value_set.taint import TaintSummary

global_taint_summary = TaintSummary(p, None, set)

def update_taint_summary(ts: TaintSummary, stack_base:int):
    defined = ts._state_defined
    # update register taint
    def _adjust_to_global_offset(taints: Set[TaintTag]):
        adjusted_taints = set()
        for t in taints:
            if "tagged_tp" not in t.metadata.keys():
                print(t)
            else:
                if t.metadata["tagged_tp"] == "stack":
                    t.metadata["tagged_off"] += stack_base
            adjusted_taints.add(t)
        return adjusted_taints

    #
    to_update_transactions = {}
    for reg_off, reg_size in defined[TaintType.REG]:
        defined_taints = ts.load(TaintType.REG, reg_off, reg_size, False)
        adjusted_taints = _adjust_to_global_offset(defined_taints)

        _, to_update = global_taint_summary.base_to_update_region_with_taints(adjusted_taints, TaintType.REG, reg_off, reg_size)
        to_update_transactions.update(to_update)
    for stack_off, stack_sz in defined[TaintType.STACK]:
        defined_taints = ts.load(TaintType.STACK, stack_off, stack_sz, False)
        adjusted_taints = _adjust_to_global_offset(defined_taints)

        _, to_update = global_taint_summary.base_to_update_region_with_taints(adjusted_taints, TaintType.STACK, stack_off + stack_base, stack_sz)
        to_update_transactions.update(to_update)

    for heap_off, heap_sz in defined[TaintType.HEAP]:
        defined_taints = ts.load(TaintType.HEAP, heap_off, heap_sz, False)
        adjusted_taints = _adjust_to_global_offset(defined_taints)

        _, to_update = global_taint_summary.base_to_update_region_with_taints(adjusted_taints, TaintType.HEAP, heap_off, heap_sz)
        to_update_transactions.update(to_update)

    for off, sz in defined[TaintType.GLB]:
        defined_taints = ts.load(TaintType.GLB, off, sz, False)
        adjusted_taints = _adjust_to_global_offset(defined_taints)
        _, to_update = global_taint_summary.base_to_update_region_with_taints(adjusted_taints, TaintType.GLB, off, sz)
        to_update_transactions.update(to_update)

    for off, _ in defined[TaintType.SYM]:
        defined_taints = ts.load(TaintType.SYM, off, None, False)
        adjusted_taints = _adjust_to_global_offset(defined_taints)
        _, to_update = global_taint_summary.base_to_update_region_with_taints(adjusted_taints, TaintType.SYM, off, None)
        to_update_transactions.update(to_update)
    global_taint_summary._commit_transaction(to_update_transactions)


plt_addrs = list(map(lambda f: f.addr, filter(lambda x: x.is_plt, p.kb.functions.values())))


class TraceUnit:
    def __init__(self, rawstr):
        self._rawstr: str = rawstr
        self.prop = None
        self.deprecated = False
        self._process()

    def _process(self):
        if self._rawstr.startswith("process"):
            self.prop = "process"
            self.deprecated = False
        elif self._rawstr.startswith("thread"):
            self.prop = "thread"
            self.deprecated = True
        elif self._rawstr.startswith("audit"):
            self.prop = "audit"
        elif self._rawstr.startswith("block"):
            self.prop = "block"
        elif self._rawstr.startswith("syscall"):
            self.prop = "syscall"
        else:
            self.prop = None
            self.deprecated = True
            return
        self._rawstr = self._rawstr.replace(self.prop, "").strip()
        if self.prop == "process":
            self.procname = self._rawstr.split()[-1]
        if self.prop == "block":
            self.block_addr, _, self.block_proc = self._rawstr.split()
            self.block_addr = int(self.block_addr, 16)

            if self.block_addr > 0x5000000:
                self.deprecated = True
            else:
                self.is_call = True if p.factory.block(self.block_addr).capstone.insns[-1].mnemonic.find("call") >= 0 \
                    else False
                self.is_ret = True if p.factory.block(self.block_addr).capstone.insns[-1].mnemonic.find("ret") >= 0 else False
                self.is_plt = True if self.block_addr in plt_addrs else False


        if self.prop == "audit":
            self.audit_name = self._rawstr.split()[0]

    def __repr__(self):
        return f"<TraceUnit {self.prop}>"

def repr_call_stack(cs):
    repr = ""
    for callsite in cs:
        repr += f"{hex(callsite)}, "
    return repr

if __name__ == "__main__":
    trace_file = "/home/chuqiz/Downloads/hello_world.trace"
    trace_list = []
    with open(trace_file, "r") as f:
        lines = f.readlines()
        trace_list = [TraceUnit(l) for l in lines]
    print(trace_file)

    audit_idx = 0
    CUR_PROC_NAME = None
    CUR_AUDIT_SEQ = []
    max_idx = len(trace_list)
    start_analyze = False

    CUR_CALL_STACK = []
    FUNC_STACK_BASE_S = [0]  # a stack which stores each function's stack base
    CURRENT_STACK_BASE = None
    CURRENT_STACK = 0

    handle_call = False
    handle_ret = False

    knowledge_base = bsi.output_state

    #
    # Simulating process the traces
    #
    idx = 0
    while True:
        if idx >= max_idx:
            break

        trace_unit = trace_list[idx]

        if trace_unit.deprecated:
            idx += 1
            continue

        if trace_unit.prop == "process":
            CUR_PROC_NAME = trace_unit.procname
            idx += 1
            continue

        elif trace_unit.prop == "block" and (not start_analyze or trace_unit.block_proc != CUR_PROC_NAME):
            if trace_unit.block_addr == main.addr:   # start analyze at main
                start_analyze = True
                CURRENT_STACK_BASE = FUNC_STACK_BASE_S[-1] # initialize main's stack base <= 0
            else:
                idx += 1
                continue

        elif trace_unit.prop == "audit":
            CUR_AUDIT_SEQ.append((trace_unit.audit_name, audit_idx))
            audit_idx += 1
            idx += 1
            continue

        elif trace_unit.prop == "syscall":
            idx += 1
            continue

        if trace_unit.prop == "block":

            if trace_unit.block_addr == 0x4008db: # main's return. handle over
                start_analyze = False

            if handle_call is True: # update callstack and function stack base at callee function
                if len(FUNC_STACK_BASE_S):
                    CURRENT_STACK_BASE = FUNC_STACK_BASE_S[-1]
                handle_call = False # finish handle callee

            if handle_ret is True:
                if len(FUNC_STACK_BASE_S):
                    CURRENT_STACK_BASE = FUNC_STACK_BASE_S[-1]
                handle_ret = False

            print(f"Handler block {hex(trace_unit.block_addr)}:\n"
                  f" current callstack: {repr_call_stack(CUR_CALL_STACK)}\n"
                  f" current stackbase: {hex(CURRENT_STACK_BASE)}\n"
                  f" current stack:     {hex(CURRENT_STACK)}")

            _state: ValueSetState = knowledge_base[tuple(CUR_CALL_STACK)][trace_unit.block_addr]
            tt_summary: TaintSummary =  _state.taint_summary
            # FIXME; dbug
            if trace_unit.block_addr == 0x4005c0:
                log.debug("aa")
            from palantiri.knowledge_base import RedisKB
            kb = RedisKB(pal_proj)
            kb.store_taint_summary(CUR_CALL_STACK, trace_unit.block_addr, tt_summary)

            stack_base = CURRENT_STACK_BASE
            # update global taint summary
            update_taint_summary(tt_summary, stack_base)

            # manipulate stack
            CURRENT_STACK = CURRENT_STACK + _state._stack_change_offset
            if trace_unit.is_call:
                handle_call = True
                CUR_CALL_STACK += [trace_unit.block_addr]
                FUNC_STACK_BASE_S.append(CURRENT_STACK)

            elif trace_unit.is_ret or trace_unit.is_plt:
                handle_ret = True
                if len(CUR_CALL_STACK):
                    CUR_CALL_STACK.pop(-1)
                if len(FUNC_STACK_BASE_S):
                    FUNC_STACK_BASE_S.pop(-1)

            idx += 1
            continue

    global_taint_summary
    print(global_taint_summary)