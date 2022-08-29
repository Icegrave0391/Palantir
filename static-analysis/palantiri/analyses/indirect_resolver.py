import os
from collections import defaultdict
from typing import List, Set, Optional
import pickle
import json

import claripy
from angr.knowledge_plugins.functions import Function

from palantiri.cfg.cfgtest import *
from palantiri.cfg import CFGAnalysis
from palantiri.cfg.callgraph import CGNode, CallGraphAcyclic
from palantiri.analyses.function_summary import FunctionSummary
from ..pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class IndirectJmpResolver:
    """
    NOTE: this is an experimental class
    Use heuristics (TypeArmor; piCFI) to resolve indirect calls and jmps
    """
    _solver = claripy.Solver()
    _tmp_function_summaries = {}

    def __init__(self, pal_project: PalProject, callgraph: Optional[CallGraphAcyclic]=None):
        self.pal_project = pal_project
        self.project = pal_project.angr_project
        self.cfg = pal_project.cfg_util.cfg
        self.callgraph: CallGraphAcyclic = callgraph if callgraph is not None else \
            CFGAnalysis.recover_call_graph(self.pal_project, self.cfg)[1]

        self_isolated_functions = []

        self._resolved_dict = {}
        self._analyze()
        self.dump_result()

    def _analyze(self, fine_grain_match=True):
        """
        Resolve indirect calls in a heuristic way. First of all, resolver leverages the acyclic call graph and
        recognize all the isolated functions (those without callers), they will be marked as potential callees.
        Resolver then performs function summary on those marked functions, to recover their function type and parameter
        information. The resolver will also perform VSA on the functions which have indirect call, and tries to solve
        the memory-alias problem of those indirect callsites. If failed, the heuristic way of matching between the
        callsites' parameter type and the marked functions' type will tries to resolve the indirect jump, in spite of
        inducing false-positive.
        """
        log.info(f"Trying to resolve indirect calls in heuristic way...")

        # 1. mark those potential callee functions
        isolated_functions: List[Function] = []
        for node in self.callgraph.nodes:
            node: CGNode
            in_es = self.callgraph.graph.in_edges(node)
            if len(in_es) == 0 and (node.func.name != "main" and node.func.name != "UnresolvableJumpTarget"
                                    and node.func.name != "UnresolvableCallTarget"):
                log.info(f"Found isolated function (potential callee): {node.func.name}")
                isolated_functions.append(node.func)
        log.info(f"Totally found {len(isolated_functions)} isolated functions.")

        # 2. make function summary on those callee functions
        isolated_function_summary_map = {}
        for callee in isolated_functions:
            summary = FunctionSummary(callee, self.project, self.pal_project)
            summary_map = summary.register_use_def_analysis()
            isolated_function_summary_map[callee] = summary_map

            # update function summary
            IndirectJmpResolver._tmp_function_summaries[callee] = summary

        # 3. find those indirect callsites and jumpout sites
        indirect_call_map = CFGAnalysis.get_indirect_callers(self.project, self.callgraph)
        indirect_jmp_map = CFGAnalysis.get_indirect_jmps(self.project, self.cfg)

        indirect_caller_map = defaultdict(list)
        for node in self.callgraph.topological_order_funcs():
            func = node.func
            try:
                if func.has_unresolved_calls:
                    indirect_caller_map[func].extend(indirect_call_map[func])
                if func.has_unresolved_jumps:
                    indirect_caller_map[func].extend(indirect_jmp_map[func])
            except KeyError:
                log.error(f"Found unresolvable indirect caller: {func.name}")

        # 4. use the heuristic steps as described in docstring, to resolve
        for caller, callsites in indirect_caller_map.items():
            caller_summary = self._get_tmp_function_summary(caller)
            for callsite in callsites:
                # 4.1 first tries to resolve the indirect call via individually function VSA results
                # try:
                #     resolved_values = caller_summary._callsite_calltarget_map[callsite]
                #     log.info(f"VSA has resolved caller {caller}, callsite {hex(callsite)}, targets: {resolved_values}")
                #     resolved = False
                #     for val in resolved_values:
                #         val: claripy.Base
                #         if val.concrete:
                #             resolved = True
                #             self._update_resolved(caller, callsite, IndirectJmpResolver._solver.eval(val, 1)[0])
                #     if resolved:
                #         continue
                # except KeyError:
                #     log.error(f"VSA did not resolved caller {caller}, callsite {hex(callsite)},"
                #               f" please check FunctionSummary.")

                # 4.2 heuristic matching!
                caller_type_map = caller_summary.callsite_registers_use_def(callsite)
                caller_parameter_regs, caller_retval = caller_type_map["parameter_regs"], caller_type_map["return_val"]
                resolved = False

                for isolated_func, marked_type_map in isolated_function_summary_map.items():
                    marked_regs, marked_retval = marked_type_map["parameter_regs"], marked_type_map["return_val"]
                    if caller_retval != marked_retval:
                        continue

                    if not fine_grain_match:
                        match = True
                        for marked_para_reg, size in marked_regs.items():
                            try:
                                caller_size = caller_parameter_regs[marked_para_reg]
                                if caller_size >= size:
                                    continue
                            except KeyError:
                                match = False
                                break
                    else:
                        match = (caller_type_map["parameter_nums"] == marked_type_map["parameter_nums"])
                        # or # caller_type_map["parameter_nums"] == marked_type_map["parameter_nums"] + 1

                    if match:
                        log.info(f"Heuristic has resolved caller {caller.name}, callsite {hex(callsite)}, "
                                 f"target: {isolated_func.name}")
                        self._update_resolved(caller, callsite, isolated_func.addr)
                        resolved = True

                if not resolved:
                    log.warning(f"Resolver failed to resolve function: {caller.name} at callsite {hex(callsite)}")

    def _update_resolved(self, caller_func, callsite: int, callee: int):
        caller_addr = caller_func.addr
        if caller_addr not in self._resolved_dict.keys():
            self._resolved_dict[caller_addr] = defaultdict(set)

        if callsite not in self._resolved_dict[caller_addr].keys():
            self._resolved_dict[caller_addr].setdefault(callsite, set([callee]))
            return

        self._resolved_dict[caller_addr][callsite].add(callee)

    def _get_tmp_function_summary(self, func: Function):
        if func in IndirectJmpResolver._tmp_function_summaries.keys():
            return IndirectJmpResolver._tmp_function_summaries[func]
        summary = FunctionSummary(func, self.project, self.pal_project)
        IndirectJmpResolver._tmp_function_summaries[func] = summary
        return summary

    @property
    def dump_dir(self):
        return self.pal_project.arg_info.analyses_output_path

    def dump_result(self):
        res_dump_path = os.path.join(self.dump_dir, "indirect_resolver_result.dump")
        info_dump_path = os.path.join(self.dump_dir, "indirect_resolver_info.txt")
        with open(res_dump_path, "wb") as f:
            pickle.dump(self._resolved_dict, f, protocol=pickle.HIGHEST_PROTOCOL)

        info_dict = {}
        for func_addr, vmap in self._resolved_dict.items():
            nk = self.project.kb.functions[func_addr].name
            nv = defaultdict(list)
            for callsite, calltargets in vmap.items():
                for calltarget in calltargets:
                    nv[hex(callsite)].append(self.project.kb.functions[calltarget].name)
            info_dict[nk] = nv

        with open(info_dump_path, "w+") as f:
            for func_name, callsite_and_target_dict in info_dict.items():
                f.write(f"====== Function {func_name} results: =======\n")
                for callsite, targets in callsite_and_target_dict.items():
                    f.write(f"callsite {callsite}: {targets}\n")

