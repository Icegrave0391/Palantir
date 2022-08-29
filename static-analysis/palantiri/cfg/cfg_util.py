import logging
import os
import pickle
from collections import deque
from pathlib import Path
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, TYPE_CHECKING

from ..syscalls import syscall_to_functions

import angr
from angr.analyses.cfg import CFGFast
from angr.analyses.vfg import VFG
from angr.knowledge_plugins.functions import Function
from angr.analyses.cfg.cfg_utils import CFGUtils
import networkx as nx


from palantiri.cfg.cfgtest import *
from palantiri.cfg.callgraph import CallGraph, CallGraphAcyclic, CGNode

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CFGUtil:
    """
    Class for CFG reconstruction and static analysis
    """
    def __init__(self, pal_project: 'PalProject', auto_save=True, load_local=False):
        self._pal_proj = pal_project
        self.proj: angr.Project = pal_project.angr_project
        self._cfg = self._load_local(auto_save) if load_local else self._fcfg(auto_save)

    @property
    def cfg(self) -> CFGFast:
        if self._cfg is None:
            self._cfg = self._fcfg()
        return self._cfg

    def vfg(self) -> VFG:
        # unused function
        log.info(f"Constructing VFG...")
        start = time.time()
        function_start = self.proj.kb.functions["main"].addr
        vfg = self.proj.analyses.VFG(
            cfg=self.cfg,
            start=function_start,
            function_start=function_start,
            interfunction_level=0,
            max_iterations=40,
            context_sensitivity_level=2,
            record_function_final_states=True
        )
        duration = time.time() - start
        log.info(f"VFG generated in %f seconds.", duration)
        return vfg


    def _fcfg(self, with_save=True) -> CFGFast:
        # cfg = self.proj.analyses.CFGFast(normalize=True, data_references=True)
        cfg = self.proj.analyses.CFGFast(normalize=True, data_references=True,)
        log.info(f"Successfully constructed CFG.")
        if with_save:
            self._save(cfg)
        return cfg

    def _save(self, cfg):
        log.info(f"Saving CFG and knowledge_base...")
        cfgmodel_path = str(Path(self._pal_proj.arg_info.binary_output_path).joinpath(
            f"{self._pal_proj.arg_info.binary_name}.cfgmodel"))
        kb_path = str(Path(self._pal_proj.arg_info.binary_output_path).joinpath(
            f"{self._pal_proj.arg_info.binary_name}.kb"))
        with open(cfgmodel_path, "wb") as f:
            f.write(pickle.dumps(cfg, -1))
            log.info(f"CFG model saved at {cfgmodel_path}!")
        with open(kb_path, "wb") as f:
            f.write(pickle.dumps(cfg.kb, -1))
            log.info(f"knowledge_base saved at {kb_path}!")

    def _load_local(self, with_save=True):
        """
        Load CFG and knowledge_base from local file
        :return:
        """
        # load cfg model
        cfgmodel_path = str(Path(self._pal_proj.arg_info.binary_output_path).joinpath(
            f"{self._pal_proj.arg_info.binary_name}.cfgmodel"))

        try:
            f = open(cfgmodel_path, "rb")
            cfg = pickle.loads(f.read())
            f.close()
        except FileNotFoundError:
            log.warning(f"CFG model path {cfgmodel_path} not found. Recover from local failed.")
            log.info(f"Trying to re-reconstruct CFG instead.")
            ncfg = self._fcfg(with_save)
            return ncfg

        # load kb
        kb_path = str(Path(self._pal_proj.arg_info.binary_output_path).joinpath(
            f"{self._pal_proj.arg_info.binary_name}.kb"))
        try:
            f = open(kb_path, "rb")
            kb = pickle.loads(f.read())
            f.close()
        except FileNotFoundError:
            log.warning(f"Knowledge_base path {kb_path} not found. Recover from local failed.")
            log.info(f"Trying to re-reconstruct CFG instead.")
            ncfg = self._fcfg(with_save)
            return ncfg
        # recover kb for project and CFG
        cfg.kb = kb
        self.proj.kb = kb
        return cfg


class CFGAnalysis:
    """
    A static class presents several static analysis methods for CFG
    """
    @staticmethod
    def get_indirect_jmps(p: angr.Project, cfg: CFGFast) -> Dict[Function, List[int]]:
        """
        Get all the indirect jump codeblock locations at cfg, excluding jumps induced by external functions
        :return: A dictionary formatted {Function: [(callsite_blk_addr, target), (), ..]
        """
        log.info(f"Finding all indirect jumps in CFG...")
        function_indirects_map = defaultdict(list)

        for callsite_addr, indirect_tar in cfg.indirect_jumps.items():
            node = cfg.model.get_any_node(callsite_addr)
            try:
                func = p.kb.functions[node.function_address]
            except:
                continue
            # skip those external functions
            if func.is_plt or func.is_syscall or func.name == "init":
                continue

            function_indirects_map[func].append(callsite_addr)

        return function_indirects_map

    @staticmethod
    def function_floor_ceiling_block(p: angr.Project, function: Function) -> Tuple[int, int]:
        """
        Given a function, return its floor block and ceiling block address.
        """
        sorted_addr = sorted(function.block_addrs)
        return sorted_addr[0], sorted_addr[-1]

    @staticmethod
    def recover_caller_sites(p: angr.Project, cfg: CFGFast, function: Function) -> Dict[Function, List[Tuple[int, int]]]:
        """
        Recover all the caller for a given function, as well as all the callsites of callers.
        :param cfg: CFGFast object for project
        :param function: Function to analyze
        :return:  A Dict formatted {function: [(callsite_blk_addr, callsite_insn_addr), ...]}
        """
        log.info(f"Recovering callers and those callsites for function {function.name}...")
        node = cfg.model.get_any_node(function.addr)
        if node is None:
            log.warning(f"function {function.name} is not in cfg.")
            return defaultdict(list)

        in_edges = cfg.graph.in_edges(node, data=True)
        callsites_by_function: Dict[Function, List[Tuple[int, int]]] = defaultdict(list)

        for call_loc, _, data in in_edges:
            call_loc: CFGNode
            e_type = data.get("jumpkind")
            if e_type != "Ijk_Call":
                continue
            if not p.kb.functions.contains_addr(call_loc.function_address):
                continue
            caller = p.kb.functions[call_loc.function_address]
            if caller.is_simprocedure or caller.is_syscall:
                continue
            callsites_by_function[caller].append((call_loc.addr, call_loc.instruction_addrs[-1]))

        return callsites_by_function

    @staticmethod
    def recover_call_graph(pp: 'PalProject', cfg: CFGFast, exclude_plt=True, exclude_external=True)\
            -> Tuple[CallGraph, CallGraphAcyclic]:
        """
        Generate concise call grpah for the whole CFG
        """
        p = pp.angr_project
        log.info(f"Constructing callgraph for project {p}...")
        callgraph, callgraph_acyclic = CallGraph(pp), nx.DiGraph()

        # 0.filter useless functions such as .plt sections, and mistake functions such as padding instruction 'nop'
        filtered_funcs = {}
        plt_section_info = pp.pal_loader.get_section_info(".plt")
        filter_plt = (True and exclude_plt) if len(plt_section_info) else False

        def should_filter_func(func_addr):
            func = p.kb.functions[func_addr]
            if filter_plt and func_addr in range(plt_section_info["vaddr_start"], plt_section_info["vaddr_end"] + 1):
                return True
            # filter external
            if exclude_external and func_addr in range(p.loader.extern_object.min_addr,
                                                       p.loader.extern_object.max_addr + 1):
                return True
            if exclude_external and func.name in ["__libc_csu_init", "_init", "__stack_chk_fail", "__libc_start_main",
                                                  "_start", "register_tm_clones", "deregister_tm_clones",
                                                  "__do_global_dtors_aux", "__cxa_finalize", "frame_dummy",
                                                  "__libc_csu_fini", "_fini"]:
                return True
            # filter nop fakefuncs
            if len(func.block_addrs_set) == 1:
                block = cfg.model.get_any_node(list(func.block_addrs_set)[0]).block
                if (block is not None and
                        (not block.capstone.insns or
                         (block.capstone.insns[0].mnemonic == "nop" or block.capstone.insns[0].mnemonic == "hlt")
                        )
                ):
                    return True
            return False

        for func_addr, func in sorted(p.kb.functions.items()):
            # filter .plt (not .plt.got!!)
            if should_filter_func(func_addr):
                continue
            filtered_funcs[func_addr] = func

        # 1. recover all nodes represents the functions
        for func_addr, func in sorted(filtered_funcs.items()):
            callgraph.add_node(CGNode(func_addr, func))

        # 2. extract callsite info (caller -> callee), and complete callgraph
        for func_addr, func in filtered_funcs.items():
            func: Function
            # call out sites
            for callsite in func.get_call_sites():
                cs_node = cfg.model.get_any_node(callsite)

                # for indirect call, there may be several potential callees
                successors = [s for s, _ in cs_node.successors_and_jumpkinds(excluding_fakeret=True)]
                for succ_node in successors:
                    if succ_node.addr not in p.kb.functions:
                        log.error(f"Caller: {func.name}, callsite: {hex(callsite)}, Callee address "
                                  f"{hex(succ_node.addr)} is not in function addresses.")
                        continue

                    caller_func_addr, callsite_addr, callee_func_addr = func_addr, callsite, succ_node.addr
                    callgraph.add_edge(CGNode(caller_func_addr, func),
                                       CGNode(callee_func_addr, p.kb.functions[callee_func_addr]),
                                       callsite=callsite_addr)

            # jump out sites
            for jumpsite_blknode in func.jumpout_sites:
                callsite = jumpsite_blknode.addr
                cs_node = cfg.model.get_any_node(callsite)
                successors = [s for s, _ in cs_node.successors_and_jumpkinds(excluding_fakeret=True)]
                for succ_node in successors:
                    if succ_node.function_address == func_addr:
                        continue
                    if succ_node.addr not in p.kb.functions:
                        log.error(f"Caller: {func.name}, jumpout site: {hex(callsite)}, Jumpout target address "
                                  f"{hex(succ_node.addr)} is not in function addresses.")
                        continue

                    caller_func_addr, callsite_addr, callee_func_addr = func_addr, callsite, succ_node.addr
                    callgraph.add_edge(CGNode(caller_func_addr, func),
                                       CGNode(callee_func_addr, p.kb.functions[callee_func_addr]),
                                       callsite=callsite_addr)

        # 3. generate acyclic callgraph
        log.info(f"Constructing acyclic callgraph for project {p}...")
        callgraph_acyclic = CallGraphAcyclic(pp, callgraph.graph)
        return callgraph, callgraph_acyclic

    @staticmethod
    def get_indirect_callers(p: angr.Project, callgraph_acyclic: CallGraphAcyclic) -> Dict[Function, List]:
        #find those indirect callsites
        indirect_caller_map = defaultdict(list)
        for node in callgraph_acyclic.topological_order_funcs():
            func = node.func
            try:
                aaa= func.get_call_sites()
            except:
                print('a')
            for callsite in func.get_call_sites():
                target_func_addr = func.get_call_target(callsite)
                try:
                    tar_func = p.kb.functions[target_func_addr]
                    if tar_func.name == "UnresolvableCallTarget" or \
                            tar_func.name == "UnresolvableJumpTarget":
                        log.info(f"Found indirect call of caller: {func.name} and callsite block: {hex(callsite)}")
                        indirect_caller_map[func].append(callsite)
                except KeyError:
                    # indirect_caller_map[func].append(callsite)
                    log.info(f"Found unresolvable caller: {func.name} and callsite block: {hex(callsite)}")
        return indirect_caller_map

    @staticmethod
    def syscall_function_whitelist(p: angr.Project, call_graph: CallGraphAcyclic, cfg, function_keys=None,
                                   add_indirect=True) \
            -> nx.DiGraph:
        """
        Get whitelist and blacklist for analysis
        """
        key_functions = []
        for f_k, func_list in syscall_to_functions.items():
            if function_keys is None:
                pass
            elif f_k not in function_keys:
                continue

            for fname in func_list:
                try:
                    key_functions.append(p.kb.functions[fname])
                except KeyError:
                    continue
        
        # FIXME: set key functions for posgres / proftpd
        if p.filename.find("postgres") >= 0:
            key_functions = []
            if "read" in function_keys:
                key_functions.append(p.kb.functions["pread"])
            if "write" in function_keys:
                key_functions.append(p.kb.functions["sendto"])
        elif p.filename.find("proftpd") >= 0:
            key_functions = []
            if "read" in function_keys:
                key_functions.append(p.kb.functions["read"])
            if "write" in function_keys:
                key_functions.append(p.kb.functions["write"])
        elif p.filename.find("varnish") >= 0:
            key_functions = []
            if "read" in function_keys:
                key_functions.append(p.kb.functions["read"])
            if "write" in function_keys:
                key_functions.append(p.kb.functions["writev"])
        elif p.filename.find("zip") >= 0:
            key_functions = []
            if "read" in function_keys:
                key_functions.append(p.kb.functions["read"])
            if "write" in function_keys:
                key_functions.append(p.kb.functions["fwrite"])

        log.info(f"Build transitive closure for functions: {key_functions}...")

        whole_transitive_closure = nx.DiGraph()
        for key_f in key_functions:
            transitive_closure = call_graph.transitive_closure(key_f)
            try:
                whole_transitive_closure.add_edges_from(transitive_closure.edges())
            except:
                pass
        # we add all indirect callsite functions to whitelist
        if add_indirect:
            indirect_call_funcs = set(CFGAnalysis.get_indirect_callers(p, call_graph).keys())
            indirect_jmp_funcs = set(CFGAnalysis.get_indirect_jmps(p, cfg).keys())
            indirect_funcs = indirect_call_funcs | indirect_jmp_funcs
            for func in indirect_funcs:
                transitive_closure = call_graph.transitive_closure(func)
                if transitive_closure:
                    whole_transitive_closure.add_edges_from(transitive_closure.edges())

        log.info(f"Built transitive closure graph for key_functions: {list(map(lambda f: f.name, key_functions))}..."
                 f"Totally {len(whole_transitive_closure.nodes)} functions...")
        return whole_transitive_closure

    @staticmethod
    def key_dataflow_transitive_closure(p: angr.Project, call_graph: CallGraphAcyclic, cfg) -> nx.DiGraph:
        read_trans_closure = CFGAnalysis.syscall_function_whitelist(p, call_graph, cfg, function_keys=['read', 'recv'],
                                                                    add_indirect=False)
        write_trans_closure = CFGAnalysis.syscall_function_whitelist(p, call_graph, cfg,
                                                                     function_keys=['write', 'send'],
                                                                     add_indirect=False)

        whole_trans_closure = nx.DiGraph()
        whole_trans_closure.add_edges_from(read_trans_closure.edges())
        whole_trans_closure.add_edges_from(write_trans_closure.edges())

        read_nodes = set(read_trans_closure.nodes)
        write_nodes = set(write_trans_closure.nodes)

        nodes_to_remove = (read_nodes | write_nodes) - (read_nodes & write_nodes)
        whole_trans_closure.remove_nodes_from(nodes_to_remove)

        return whole_trans_closure


    @staticmethod
    def calling_convention_analysis(p: angr.Project, cfg: CFGFast,
                                    function: Optional[Function]=None,
                                    analyze_callsites=False,
                                    recover_variables=False
                                    ):
        """
        Perform classic CallingConventionAnalysis from angr's builtin analysis
        """
        # for the case no function provided, just recover all function's calling convention
        if function is None:
            p.analyses.CompleteCallingConventions(recover_variables=recover_variables, analyze_callsites=analyze_callsites)
            return None
        # analyze the calling convention for function
        else:
            res = p.analyses.CallingConvention(func=function, cfg=cfg, analyze_callsites=analyze_callsites)
            return res.cc

    @staticmethod
    def fast_cc_analysis(p: angr.Project, cfg: CFGFast):
        """
        Perform a fast calling convention analysis, especially for glibc functions.
        """
        sorted_funcs = CFGUtils.quasi_topological_sort_nodes(p.kb.functions.callgraph)

        for idx, func_addr in enumerate(reversed(sorted_funcs)):
            func = p.kb.functions.get_by_addr(func_addr)

            if func.calling_convention is None:
                if func.alignment:
                    # skip all alignments
                    continue

                if not func.is_plt or func.is_syscall:
                    continue
                # determine the calling convention of each function
                cc_analysis = p.analyses.CallingConvention(func, cfg=cfg)
                if cc_analysis.cc is not None:
                    log.info("Determined calling convention for %r.", func)
                    func.calling_convention = cc_analysis.cc
                else:
                    log.info("Cannot determine calling convention for %r.", func)

