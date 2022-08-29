from asyncio.log import logger
import os.path
import json
from telnetlib import IP

import claripy
import psutil
# from memory_profiler import profile
from typing import List, Optional, Union, Dict, Tuple, TYPE_CHECKING

from angr.codenode import BlockNode
from angr.factory import Block
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.atoms import Register

from angr.analyses.reaching_definitions.function_handler import FunctionHandler

from palantiri.cfg.cfgtest import *
from misc.debugger import dbg_generate_subtransitive, dbgLog, debug_print_log
from .analyses_base import PalAnalyses, PalInterface
from palantiri.singletons.adaptors.whitelist_adaptor import whitelist_adaptor

from ..special_filters import special_filter
from ..singletons.adaptors.adaptor_manager import AdaptorManager
from ..singletons.adaptors import get_proper_adaptors
from ..structures.value_set.simmemory.vs_multivalues import VSMultiValues
from ..singletons.global_symdict import global_symmem_dict

from palantiri.structures.value_set.vs_state import ValueSetState
from palantiri.structures.value_set.engine.bs_engine import SimEngineBSVEX
from palantiri.structures.value_set.vs_subject import VSSubject
from palantiri.analyses.indirect_resolver import IndirectJmpResolver

import time

if TYPE_CHECKING:
    from ..pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

DBG_LOCATION = [0x47e1bd]
# 43f6b2: invalid load region


class BinarySummaryInterface(PalInterface):
    """
    - Binary Summary Analysis (aka. Taint Summarization) is a pure static analysis performs at whole-binary level. 
      It starts from the initial point (the start function of a tainting scope) of the binary, and performs in an
      inter-procedural way. It's exploration is guided by the VSFuncGraphVisitor (at intra-procedural level) and
      different adaptors (at inter-procedural level, see adaptors under `singletons.adaptors`).
        - For abstract domains, we fully support the representations of: register region, stack region, heap region,
          global memory region, and symbolic memory region (for those memory alias could not be resolved statically).

    - Binary Summary Analysis works at granularity of the "code block state" (basic block). For each code block,
      it gathers the analysis result information, including abstract results, def-use chain, and our TaintSummary.
        - The definition of code block state:
          The format of code block state (also referred as ValueSetState) is similar to basic block in CFG,
          which ends up in calls and jmps to other functions/blocks. If the type of the other function is external
          function (glibc functions), then the state contains the result of such a function, by external summary
          technique (we manually wrap the semantics of external functions, see 
                                                `structures.value_set.function_handler.bs_functionhandler.py`).
          Otherwise, the state should be defined as all the results before that function call.

    - Binary summary Analysis is context-sensitive. For each context, it maintains a callstack to mark the context
      information.
    
    - BinarySummaryInterface is a singleton interface during the binary analysis, and it will spawn BinarySummary for 
      individual functions (from the starting function)
    """
    def __init__(self, pal_proj: 'PalProject', callgraph_acyclic=None,
                 function_handler=None,
                 start_function: Optional[Function]=None,
                 save_space_mode=False,
                 auto_save=False,
                 recover_from_disk=False,
                 function_summary_dict=None,
                 force_propagate_taint_summary=False,
                 loop_revisit_mode=False,
                 max_symbol_reference_depth=2,
                 eval_mode=False,
                 without_whole_segment=False,
                 force_revisit_func_and_node=None,
                 mem_rw_upperbound=10,
                 valueset_upperbound=15,
                 ):
        """
        :param pal_proj:
        :param callgraph_acyclic:
        :param save_space_mode: If True, binarysummary will immediately update result to redis after each node's
                                calculation.
        :param auto_save: If True, binarysummary will serialize mediate analysis state to local file at start function's
                          callsites.
        :param recover_from_disk: If True, interface will try to recover the last saved mediate state from the localfile
                                  and resume the analysis.
        :param force_propagate_taint_summary: If True, the binary summary won't produce taint logic summary, instead, it
        will perform static taint analysis. (experimental feature)
        """
        super(BinarySummaryInterface, self).__init__(pal_proj=pal_proj, callgraph_acyclic=callgraph_acyclic,
                                                     function_handler=function_handler, auto_save=auto_save,
                                                     loop_revisit_mode=loop_revisit_mode,
                                                     max_symbol_reference_depth=max_symbol_reference_depth,
                                                     without_whole_segment=without_whole_segment,
                                                     mem_rw_upperbound=mem_rw_upperbound,
                                                     valueset_upperbound=valueset_upperbound)
        self.start_function = start_function

        self.save_space_mode = save_space_mode

        self.states_to_standardize_map: Optional[Dict[int, ValueSetState]] = {}
        self.nodeaddr_next_standardize: Optional[List[int]] = []

        self.output_state: Dict[Tuple, Dict[int, ValueSetState]] = {} # callstack : {addr: state}
        self.function_summary_dict = function_summary_dict
        self.force_propagate_taint_summary = force_propagate_taint_summary

        self.force_revisit_func_and_node: Optional[Tuple[str, int]] = force_revisit_func_and_node

        self.eval_mode = eval_mode
        self.eval_function_subj_set = set()
        self.peak_mem_usage = 0   # peak memory usage for evaluation

        self.global_state_to_merge: Optional[ValueSetState] = None

        self._debug_describe()
        if not eval_mode:
            self.start(start_function, recover_from_disk=recover_from_disk)

    def _debug_describe(self):
        if self.force_revisit_func_and_node:
            debug_print_log(self._pal_project, message=\
                f"BinarySummaryInterface settings: \n"
                f"∟ save_space_mode: {self.save_space_mode}\n"
                f"∟ loop_revisit_mode: {self.loop_revisit_mode}\n"
                f"∟ force_revisit_func: {self.force_revisit_func_and_node[0]}\n"
                f"∟ force_revisit_node: {hex(self.force_revisit_func_and_node[1])}\n"
                f"∟ max_symbol_ref_depth: {self.max_symbol_reference_depth}\n"
                f"∟ mem_rw_upperbound: {self.mem_rw_upperbound}\n"
                f"∟ valueset_upperbound: {self.valueset_upperbound}",
                min_vlevel=1, logger=log)
        else:
            debug_print_log(self._pal_project, message=\
                f"BinarySummaryInterface settings: \n"
                f"∟ save_space_mode: {self.save_space_mode}\n"
                f"∟ loop_revisit_mode: {self.loop_revisit_mode}\n"
                f"∟ max_symbol_ref_depth: {self.max_symbol_reference_depth}\n"
                f"∟ max_irrelevant_call_depth: {self._pal_project.arg_info.args.irrelevant_call_depth}\n"
                f"∟ mem_rw_upperbound: {self.mem_rw_upperbound}\n"
                f"∟ valueset_upperbound: {self.valueset_upperbound}",
                min_vlevel=1, logger=log)

    def start(self, start_function: Optional[Function]=None, recover_from_disk=False):
        # dump section info into db first
        kb = self._pal_project.redis_kb
        kb.store_section_info(".plt")
        # create binary summary task and start
        start_functions = [start_function] if start_function else self.interproc_manager.start_functions
        if not recover_from_disk:
            for start_function in start_functions:
                BinarySummary(function=start_function, pal_proj=self._pal_project,
                              project=self.project, interface=self._get_weakref(),
                              function_handler=self._function_handler,
                              call_stack=[],
                              do_taint_summary=True,
                              immediate_update=self.save_space_mode,
                              auto_save=self.auto_save,
                              max_symbol_reference_depth=self.max_symbol_reference_depth
                              )
        else:
            reloaded_bs = self.reload_binary_summary()
            reloaded_bs._analyze()

    def dump_state(self, callstack, block_addr, taint_summary):
        """
        Dump a single output state to the knowledge base.
        This method is called when "save_space_mode" is True.
        """
        kb = self._pal_project.redis_kb
        kb.store_taint_summary(callstack, block_addr, taint_summary)

    def dump_redirect_info(self, callstack, src_addr, tar_addr):
        self._pal_project.redis_kb.store_redirect_info(callstack, src_addr, tar_addr)

    def dump_stack_info(self, binarysummary: 'BinarySummary'):
        """
        Dump the initial stack info of a binarysummary instance.
        """
        kb = self._pal_project.redis_kb
        func_addr = binarysummary._subject.content.addr
        initial_stack_offset = binarysummary._init_stack_offset
        callsites = tuple(binarysummary._call_stack)
        kb.store_stack_info(callsites=callsites, function_addr=func_addr, initial_stack_offset=initial_stack_offset)

    def dump_symbol_num(self):
        """
        Dump the total number of symbolic values produced during the analysis
        """
        kb = self._pal_project.redis_kb
        kb.store_symbol_num(len(global_symmem_dict.global_symmem_dict))

    def dump_pruned_function(self, callsites, function_addr):
        kb = self._pal_project.redis_kb
        kb.store_pruned_function(callsites, function_addr)
    
    def dump_start_functions(self, functions):
        kb = self._pal_project.redis_kb
        kb.store_start_func_info(functions)

    def dump_pruned_node(self, callsites, node_addr):
        kb = self._pal_project.redis_kb
        kb.store_pruned_node(callsites, node_addr)

    def update_output_state(self, binarysummary: 'BinarySummary', node_addr: int, state: ValueSetState):
        """
        Update a single state immediately after a node in binarysummary has computed,
        This function should ONLY BE CALLED when "save_space_mode" is on.
        """
        if not self.save_space_mode:
            raise AssertionError(f"PalInterface didn't set save_space_mode, should not update single state.")

        if node_addr in self.nodeaddr_next_standardize:
            self.states_to_standardize_map[node_addr] = state
            self.nodeaddr_next_standardize.remove(node_addr)

        # result state is not needed to be standardized, then dump to db
        if not state._should_standardize:
            self.dump_state(binarysummary._call_stack, node_addr, state.taint_summary)

        # the result state should be standardized, we record it and its successor to the map, and standardize them
        # after the bianry summary is finished.
        else:
            self.states_to_standardize_map[node_addr] = state
            self.nodeaddr_next_standardize.append(node_addr + state._block_size)

    def do_standardize_states(self, binary_summary: 'BinarySummary'):
        """
        Standardize the states (recorded in self.states_to_standardize_map) and clear the map.
        """
        if not self.save_space_mode:
            raise AssertionError(f"PalInterface didn't set save_space_mode, should not standardize.")
        # 1. filter states for the binarysummary
        sub_addrs, sub_map = [], {}
        for addr, state in self.states_to_standardize_map.items():
            if tuple(state.analysis._call_stack) == tuple(binary_summary._call_stack) and \
                    state.analysis._subject == binary_summary._subject:
                sub_addrs.append(addr)
        for addr in sub_addrs:
            sub_map[addr] = self.states_to_standardize_map.pop(addr)

        if not sub_addrs:
            return

        for addr, state in sub_map.items():
            # ignore the tail state to standardize
            if not state._should_standardize:
                continue

            next_addr = state._block_addr + state._block_size
            standardize_list = []
            while True:
                try:
                    o: ValueSetState = sub_map[next_addr]
                except KeyError:
                    # this occurs when backward standardize occurs, we ignore such standardize
                    break
                standardize_list.append(o)
                if o._should_standardize:
                    next_addr = o._block_addr + o._block_size
                    continue
                else:
                    break
            
            # write debug log
            message = f"BinarySummary: {state.analysis._subject.content.name} should standardize block \
                        {hex(state._block_addr)} with\
                        {list(map(lambda x: hex(x._block_addr), standardize_list))}"
            debug_print_log(self._pal_project, message, logger=log, min_vlevel=3, to_tmp_file=False)

            self.dump_state(binary_summary._call_stack, addr, state.standardize(*standardize_list).taint_summary)

    def reload_binary_summary(self) -> Optional['BinarySummary']:
        """
        Reload the archived binarysummary from disk storage, and set up all the properties properly for the binary
        summary analysis.
        :return:
        """
        if not os.path.exists(self.summary_dump_path):
            log.error(f"BinarySummary archive not found.")
            return None
        with open(self.summary_dump_path, 'rb') as f:
            reloaded_binary_summary: 'BinarySummary' = pickle.load(f)
            node_addr: int = pickle.load(f)
        # set up the missing properties during archive
        # 1. set up for binary summary
        reloaded_binary_summary.interface = self._get_weakref()
        reloaded_binary_summary.project = self.project
        reloaded_binary_summary.pal_project = self._pal_project
        reloaded_binary_summary._function_handler = self._function_handler
        reloaded_binary_summary._function_handler = reloaded_binary_summary._function_handler.hook(reloaded_binary_summary)
        reloaded_binary_summary._engine = SimEngineBSVEX(self.project,
                                                         reloaded_binary_summary._call_stack,
                                                         reloaded_binary_summary._max_local_call_depth,
                                                         functions=self.project.kb.functions,
                                                         function_handler=self._function_handler,
                                                         )
        # also set up the next node
        node = BlockNode(node_addr, self.project.factory.block(node_addr).size)
        reloaded_binary_summary._subject.visitor._sorted_nodes.insert(0, node)
        reloaded_binary_summary._subject.visitor._nodes_set.add(node)
        # 2. set up for state
        for state_list in reloaded_binary_summary._input_node_map.values():
            for input_state in state_list:
                # set up input states
                input_state: ValueSetState
                input_state.analysis = reloaded_binary_summary._get_weakref()
                # set up live definitions
                input_state.live_definitions.set_state(input_state)
                input_state.live_definitions.project = self.project
                input_state.register_definitions.set_state(input_state.live_definitions)
                input_state.stack_definitions.set_state(input_state.live_definitions)
                input_state.heap_definitions.set_state(input_state.live_definitions)
                input_state.memory_definitions.set_state(input_state.live_definitions)
                input_state.symbolic_definitions.set_state(input_state.live_definitions)
                # set up taint summary
                input_state.taint_summary.project = self.project
                input_state.taint_summary.analysis = input_state.analysis
        # 3. setup global singletons
        global_dict_path = os.path.join(os.path.dirname(self.summary_dump_path), "global_symmem_dict.dump")
        with open(global_dict_path, "rb") as f:
            other_global_dict = pickle.load(f)
            global_symmem_dict.setup_from_other(other_global_dict)

        # 4. setup adaptor
        adaptor_path = os.path.join(self._pal_project.arg_info.analyses_output_path, "interproc_manager.dump")
        with open(adaptor_path, "rb") as f:
            other_adaptor = pickle.load(f)
            whitelist_adaptor.setup_from_other(other_adaptor)
        whitelist_adaptor.pal_project = self._pal_project

        return reloaded_binary_summary

    @property
    def summary_dump_path(self):
        dir = self._pal_project.arg_info.analyses_output_path
        return os.path.join(dir, "binary_summary_archive.dump")

    def _setup_adaptors(self):
        """Set up the inter-procedural adaptors"""
        adaptor_manager = AdaptorManager()
        # 1. setup interface
        adaptor_manager.set_interface(self)

        # debug mode
        if self._pal_project.arg_info.args.debug:
            from misc.visualize import V
            from palantiri.cfg.cfg_util import CFGAnalysis
            v = V(self.project, self._pal_project.arg_info)
            v.draw_transitive_graph(adaptor_manager.syscall_slice_graph.graph, "whole_transitive_closure")
            v.draw_transitive_graph(CFGAnalysis.key_dataflow_transitive_closure(self.project,
                                                                                adaptor_manager.pruned_callgraph,
                                                                                self._pal_project.cfg_util.cfg),
                                    "read&write_transitive_closure")
        # 2. resolve indirect
        # if already set enforce dict, then pass
        if adaptor_manager.resolved_indirect_dict is not None or not adaptor_manager.resolve_indirect:
            pass
        else:
            # first search on the disk
            try:
                f = open(os.path.join(self._pal_project.arg_info.analyses_output_path, "indirect_resolver_result.dump"),
                         "rb")
                resolved_dict = pickle.load(f)
                f.close()
            except FileNotFoundError:
                ijr = IndirectJmpResolver(self._pal_project, adaptor_manager.syscall_slice_graph)
                resolved_dict = ijr._resolved_dict
            adaptor_manager.update_resolved_dict(resolved_dict)
        # 3. register adaptors
        adaptor_manager.register_adaptors(get_proper_adaptors(self.project))
        # 4. set up adaptors
        adaptor_manager.setup_adaptors()
        # dump to file
        with open(os.path.join(self._pal_project.arg_info.analyses_output_path, "interproc_manager.dump"), "wb") as f:
            pickle.dump(adaptor_manager, f, protocol=pickle.HIGHEST_PROTOCOL)

        return adaptor_manager

    def _update_outputs(self, binarysummary: 'BinarySummary', tmp_save=False):
        """
        Update the binarysummary's ALL outputs to the kb.
        This method should only be called when "save_space_mode" is False.
        We no longer save those in interface, due to high memory cost.
        """

        # dump the redirect_info (callsite redirect due to standardize)
        vs_subject = binarysummary._subject
        if not vs_subject.content.is_plt and binarysummary._output_node_map:
            for callsite in binarysummary._subject.content.get_call_sites():
                # callsite is the redirect target, we check its predecessors
                pred_queue = deque(vs_subject.get_predecessor_nodes(callsite))
                while pred_queue:
                    pred_node = pred_queue.popleft()
                    vs_state: ValueSetState = binarysummary._output_node_map[pred_node.addr]
                    # add redirect (should standardize addr -> callsite addr)
                    if vs_state._should_standardize:
                        self.dump_redirect_info(binarysummary._call_stack, pred_node.addr, callsite)
                        pred_queue.extendleft(vs_subject.get_predecessor_nodes(pred_node))
                    else:
                        pass

        cs = tuple(binarysummary._call_stack)
        # dump the output states
        for k, v in binarysummary._output_node_map.items():
            v: ValueSetState
            if not v._should_standardize:
                if tmp_save:
                    self.output_state[cs][k] = v
                else:
                    # dump to db
                    self.dump_state(cs, k, v.taint_summary)
            else:
                # do standardize the outputs
                next_key = v._block_addr + v._block_size
                standardize_list = []
                while True:
                    o: ValueSetState = binarysummary._output_node_map[next_key]
                    standardize_list.append(o)
                    if o._should_standardize:
                        next_key = o._block_addr + o._block_size
                        continue
                    else:
                        break
                
                dbg_message = f"Binary summary: {binarysummary._subject.content.name} should standardize block \
                                {hex(v._block_addr)} with\
                                {list(map(lambda x: hex(x._block_addr), standardize_list))}"
                debug_print_log(self._pal_project, dbg_message, log, min_vlevel=3, to_tmp_file=False)

                if tmp_save:
                    self.output_state[cs][k] = v.standardize(*standardize_list)
                else:
                    # dump to db
                    self.dump_state(cs, k, v.standardize(*standardize_list).taint_summary)


class BinarySummary(PalAnalyses):
    """
    BinarySummary is a function-level task spawned from the BinarySummaryInterface, which performs analysis on 
    a single function.
    (This is a lightweight way to perform angr's native ForwardAnalysis.)
    
    When encounters an inter-procedural call/jmp, it will forks another BinarySummary. All the BinarySummary 
    instances share the same BinarySummaryInterface.
    """
    def __init__(self, function: Union[Function, VSSubject], pal_proj: 'PalProject',
                 project: angr.Project, interface: BinarySummaryInterface,
                 func_graph=None, track_tmps=False, function_handler: Optional[FunctionHandler]=None,
                 init_state: Optional[ValueSetState]=None, dep_graph: Optional[DepGraph]=None, canonical_size=8,
                 max_iterations=2, call_stack: Optional[List[int]]=None,
                 do_taint_summary=True, immediate_update=True, auto_save=True,
                 max_symbol_reference_depth=2):
        """
        :param function: The subject function of the analysis, note that this analysis is function-level
        :param project: angr.Project
        :param func_graph: Alternative graph for function.graph
        :param track_tmps: Whether or not temporary values should be taken into consideration during the analysis
        :param init_state: An optional initialization state, and the analysis creates and works on a copy.
        :param dep_graph: An initial dependency graph to add the result of the analysis to. (unused)
        :param canonical_size: The sizes (byte-united) that objects with unknown size are treated as.
        :param do_taint_summary: Whether do static taint summary when performing analysis
        """
        analyze_function = function if isinstance(function, Function) else function.content

        propagate_taint_summary = True if interface.force_propagate_taint_summary else analyze_function.is_plt
        super(BinarySummary, self).__init__(function=function, pal_proj=pal_proj, project=project, interface=interface,
                                            func_graph=func_graph, track_tmps=track_tmps,
                                            function_handler=function_handler, init_state=init_state,
                                            dep_graph=dep_graph, canonical_size=canonical_size,
                                            max_iterations=max_iterations, call_stack=call_stack,
                                            do_taint_summary=do_taint_summary,
                                            propagate_taint_summary=propagate_taint_summary,
                                            immediate_update=immediate_update, auto_save=auto_save,
                                            max_symbol_reference_depth=max_symbol_reference_depth)
        self.interface: 'BinarySummaryInterface'
        
        if self._subject.content in self.interface.interproc_manager.rw_segment_functions:
            self._call_stack = []
        self._engine = SimEngineBSVEX(self.project, self._call_stack, self._max_local_call_depth,
                                      functions=self.project.kb.functions,
                                      function_handler=self._function_handler,
                                      )
        if self.interface.eval_mode:
            self.interface.eval_function_subj_set.add(self._subject)
        
        # FIXME: force revisit
        self.force_revisit_node = None
        if self.interface.force_revisit_func_and_node:
            func_name, node = self.interface.force_revisit_func_and_node
            if self._subject.content.name == func_name:
                self.force_revisit_node = node

        # do analyze
        self._analyze()

    def get_block_summary(self, block_key:Union[BlockNode, int, Block], after_call=False) -> ValueSetState:
        """
        Get block summary from the binarysummary function.
        :param after_call: If true, then get summary with the semantic including its call target summary
        """
        # TODO(): refine the format of summary, rather than use fs_state directly
        if isinstance(block_key, BlockNode) or isinstance(block_key, Block):
            key = self._node_key(block_key)
        else:
            key = block_key

        if self._immediate_update and key not in self._subject.get_endpoints():
            log.error(f"Binarysummary: {self._subject.content.name} immediate_update mode on. "
                      f"Node {hex(key)} is not in endpoints, no summary returns.")
            raise ValueError()

        try:
            if after_call is False:
                summary: ValueSetState = self._output_node_map[key]
            else:
                summary: ValueSetState = self._aftercalled_node_map[key]
        except KeyError:
            log.error(f"Failed to get block summary of {hex(block_key)}.")
            raise KeyError
        return summary

    def should_archive_summary(self, node: BlockNode):
        """
        We archive the summary for the interface's start function before each call to the non-external function
        """
        if not self._auto_save or self._subject.content != self.interface.start_function:
            return False, None, None
        block = self.project.factory.block(node.addr, node.size)
        if block.capstone.insns[-1].mnemonic != 'call' and\
                node.addr not in self.interface.start_function.get_call_sites():
            return False, None, None

        call_target = self.interface.start_function.get_call_target(node.addr)
        target_func = self.project.kb.functions[call_target]
        if target_func.is_plt:
            return False, None, None
        log.info(f"BinarySummary start to archive at node {hex(node.addr)}, before call to"
                 f"{target_func.name}...")
        return True, node.addr, target_func.name

    def dump_initialized_state(self, output_path: str, node_addr, target_name):
        """
        Serialize the BinarySummary in storage. This method should only called immediately after each execution of
        the main binarysummary, in order to catch the latest version.
        We dump all the parameters and properities of BinarySummary, in order to serialize and recovery the startpoint
        of analysis later on.
        # TODO(): dump global_symbol_map and whitelist_recorder
        """
        dump_path = output_path
        info_path = str(os.path.join(os.path.dirname(dump_path), "info.txt"))
        global_dict_path = os.path.join(os.path.dirname(dump_path), "global_symmem_dict.dump")
        info = {
            "binarysummary_subject": self._subject.content.name,
            "call_stack_info": self._call_stack,
            "current_global_symbols": global_symmem_dict.global_symmem_dict,
            "visited_blocks": list(map(lambda n: n.addr, self.visited_blocks)),
            "before_run_on_node": hex(node_addr),
            "callsite_target_name": target_name
        }

        # 1. dump binarysummary
        with open(dump_path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)
            pickle.dump(node_addr, f, protocol=pickle.HIGHEST_PROTOCOL) # a

        # 2. dump global symmem dict
        with open(global_dict_path, "wb") as f:
            pickle.dump(global_symmem_dict, f, protocol=pickle.HIGHEST_PROTOCOL)

        # 2. dump info
        with open(info_path, "w") as f:
            json.dump(info, f)

    def _initialize_global_region(self):
        # TODO(): refine the logic
        data_section_dict = self.pal_project.pal_loader.get_section_info(".data")
        gotplt_section_dict = self.pal_project.pal_loader.get_section_info(".got.plt")
        got_section_dict = self.pal_project.pal_loader.get_section_info(".got")
        bss_section_dict = self.pal_project.pal_loader.get_section_info(".bss")
        rodata_section_dict = self.pal_project.pal_loader.get_section_info(".rodata")
        if not len(data_section_dict):
            log.error(f"Initialize global .data section failed.")
            raise ValueError
        return range(rodata_section_dict["vaddr_start"], bss_section_dict["vaddr_end"])

    def _pre_analyze(self):
        """
        Determine whether the subject is a special hooked function. If true, we call its special handler directly and
        abort the analysis.
        """
        analyze_func: Function = self._subject.content
        init_state = self._init_input_state(do_taint_summary=self._do_taint_summary)
        # hook adaption
        hook_handler_name = analyze_func.info.get("hook", None)
        if not hook_handler_name:
            if not special_filter.handle_analyze(self._subject, init_state):
                self.abort()
            return
        log.info(f"Binary analysis <{analyze_func.name}> is hooked as <{hook_handler_name}>...")
        handler_name = "handle_%s" % hook_handler_name
        assert hasattr(self._function_handler, handler_name)

        node = self._graph_visitor.next_node()
        codeloc = CodeLocation(node.addr, None, ins_addr=None, context=tuple(self._call_stack))

        # use special handler to handle the hooked function
        _, state = getattr(self._function_handler, handler_name)(init_state, codeloc, original_function=analyze_func)

        # update the result state
        self._update_output_state(self._node_key(node), state, aftercalled=False)
        self.abort()

    def _analyze(self):
        """
        Core analysis procedure for a task.
        """
        debug_print_log(self.pal_project, 
                        message=f"Start binary summary for function: {self._subject.content.name}. "
                                f"Call stack: {self._dbg_callstack()}",
                        logger=log,
                        min_vlevel=0)
        self._pre_analyze()
        # analyze
        while not self.should_abort:
            node = self._graph_visitor.next_node()
            if node is None:
                break
            # archive
            should_archive, node_addr, target_name = self.should_archive_summary(node)
            if should_archive:
                self.dump_initialized_state(self.interface.summary_dump_path, node_addr, target_name)
            debug_print_log(self.pal_project,
                            message=f"BinarySummary handling func: {self._subject.content.name}, "
                                    f"node: {hex(node.addr)}",
                            min_vlevel=2,
                            logger=log)
            block = self.project.factory.block(addr=node.addr, size=node.size)
            # 1. get the input state for function node
            state = self._get_and_update_input_state(node)
            if state is None:
                state = self._init_input_state(do_taint_summary=self._do_taint_summary)
                # FIXME: sendmail force merge
                # if self._subject.content.name == "sm_io_flush":
                #     state.heap_definitions.merge([self.interface.global_state_to_merge.heap_definitions], None)
            # 2. process the node and state
            _, output_state = self._run_on_node(node, state)
            # 3. update output node (only for those node are not end with call, or call to @plt)
            if self._should_update_output(node):
                self._update_output_state(self._node_key(node), output_state, aftercalled=False)
            if self._should_update_aftercalled_output(node):
                self._update_output_state(self._node_key(node), output_state, aftercalled=True)
            # update its successors' input state
            self._add_input_state(node, output_state)
            # determine whether should re-visit some of its successors
            self._set_revisit_successors_of_node(node, output_state)
        # post analyze
        self._post_analyze()

    def _set_revisit_successors_of_node(self, node, state):
        """
        Determine if a node's successors should be visited
        """
        # In this case, the revisit mode is off, or the revisit mode has not been activated. We'll do nothing.
        if (not self.interface.loop_revisit_mode or not self.revisit_activate_node) and\
            not self.force_revisit_node:
            return

        successors = set(self._graph_visitor.successors(node))
        # only successors which iteration times in (1, max_iter) will be pending, we will discard those nodes have not
        # been visited once or have exceeded the max iteration threshold.
        pending_revisit_succs = list(filter(
            lambda sc: self._node_iterations[self._node_key(sc)] in range(1, self._max_iterations),
            successors
        ))
        # revisit (for nginx)
        if not self.force_revisit_node:
            if len(pending_revisit_succs) == 1:
                pending_succ = next(iter(pending_revisit_succs))
                self._input_node_map[self._node_key(pending_succ)] = [state]
                self._graph_visitor.revisit_node(pending_succ)
            else:
                # heuristic
                for pending_succ in pending_revisit_succs:
                    if nx.has_path(self._subject.acyclic_func_graph, pending_succ, self.revisit_activate_node):
                        continue
                    self._input_node_map[self._node_key(pending_succ)] = [state]
                    self._graph_visitor.revisit_node(pending_succ)
        # force revisit (for sendmail)
        else:
            # we use the force-revisit-node as the revisit_activate_node
            if not self.revisit_activate_node:

                for pending_succ in pending_revisit_succs:
                    if pending_succ.addr == self.force_revisit_node:
                        self._input_node_map[self._node_key(pending_succ)] = [state]
                        self._graph_visitor.revisit_node(pending_succ)
                        self.revisit_activate_node = self.force_revisit_node
            
            else:
                for pending_succ in pending_revisit_succs:
                    self._graph_visitor.revisit_node(pending_succ)
            
    def _should_update_output(self, node):
        """
        Determine whether the summarized result should be added for a node.
        If a node ends up with call, or jumps out, then the summary which contains its calltarget result should not
        be add to output_node_map. Instead, this summary should be added to aftercalled_node_map.

        However, the plt function (which ends up with jump out) summary should always be added.
        """
        node_key = self._node_key(node)

        if not self.interface.loop_revisit_mode:
            already_updated = self._output_node_map.get(node_key, 0)
            if not already_updated:
                return True
            return False

        else:

            func = self._subject.content
            if func.is_plt:
                return True

            # should turn over the update before engine.handle_func
            if node.addr in list(map(lambda n: n.addr, func.jumpout_sites)) :
                return False

            if node.addr not in func.get_call_sites():
                return True
            else:
                return False

    def _should_update_aftercalled_output(self, node):
        """
        Determine whether we should update the node's processed result to output_aftercalled map. If the code ends up
        with function call(jmp), then we always add the processed state to the output_aftercalled map.
        """
        func = self._subject.content
        return node.addr in list(map(lambda n: n.addr, func.jumpout_sites)) or node.addr in func.get_call_sites()

    def _update_output_state(self, block_addr: int, state: ValueSetState, aftercalled=False):
        """
        Update output state after computing a basic block.
        If save_space_mode (immediate_update) is on, then take callback to interface and update (dump
        to db and record for standardize). And in such case, we just need to update endpoint-typed states to the result
        map, for later use (inter-procedural usage).
        Else, update the output state to relevant map.
        """
        state._block_addr = block_addr
        if self._immediate_update:
            # 1. update the output state for interface immediately
            if not aftercalled:
                # padding, just mark the node is already updated
                self._output_node_map[block_addr] = 1
                # update
                self.interface.update_output_state(self, block_addr, state)
            # 2. it the node is not in function's endpoints, we don't need to temp save the state, since it won't be
            #    used in inter-proc handler any more.
            if block_addr not in self._subject.endpoints:
                return
        # update to output
        if not aftercalled:
            self._output_node_map[block_addr] = state
        else:
            self._aftercalled_node_map[block_addr] = state

    def _get_input_state(self, node):
        if self._node_key(node) not in self._input_node_map:
            # log.warning(f"Get input state for node {hex(node.addr)} failed...")
            return None

        all_input_states = self._input_node_map.get(self._node_key(node))
        if node.addr in self.block_testcond_constraint.values():
            src_blk_addr, reg_name_list = list(self.block_testcond_constraint.keys())[list(self.block_testcond_constraint.values()).index(node.addr)]
            updated_all_input_states = []
            for o_state in all_input_states:
                if o_state._block_addr == src_blk_addr:
                    n_state: ValueSetState
                    n_state = o_state.copy()
                    for reg_name in reg_name_list:
                        reg_off, reg_size = self.project.arch.registers[reg_name]
                        reg_atom = Register(reg_off, reg_size)
                        n_state.kill_and_add_definition(reg_atom, CodeLocation(node.addr, stmt_idx=0,ins_addr=node.addr),
                                                        data=VSMultiValues(
                                                            offset_to_values={0: {claripy.BVV(0, reg_size * self.project.arch.bytes)}}
                                                        ))
                    updated_all_input_states.append(n_state)
                else:
                    updated_all_input_states.append(o_state)
                all_input_states = updated_all_input_states
        if len(all_input_states) == 1:
            return all_input_states[0]
        merged_state, _ = self._merge_states(node, *all_input_states,
                                             update_taint_summary=self._propagate_taint_summary)
        return merged_state

    def _post_analyze(self):
        """
        After the analysis, we should update the results to its interface (when immediate_update is False).
        """

        # FIXME: special handler to merge the output of sendmail sm_io_putc
        if self._subject.content.name == "sm_io_putc":
            ret_state = self._function_handler.get_child_analysis_retstate(self)
            self.interface.global_state_to_merge = ret_state
            # import IPython; IPython.embed()
            pass
        
        # dump the initial stack info of binary analysis
        self.interface.dump_stack_info(self)
        # dump out-of-scope for hooked functions
        if self._subject.content.info.get("hook", None):
            nodes = filter(lambda n: n.addr != self._subject.content.addr, self._subject.refined_func_graph.nodes)
            for node in nodes:
                self.interface.dump_pruned_node(self._call_stack, node.addr)

        # if the immediate_update mode is off, we feedback all results to the interface and dump it.
        if not self._immediate_update:
            self.interface._update_outputs(self)
        # if the immediate_update mode is on, we just need to standardize the states, since the results are immediately
        # updated.
        else:
            # TODO(): handle callsite redirect in this case
            self.interface.do_standardize_states(self)
        # process memory usage
        if self.interface.eval_mode:
            mem_usage = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 # in MB
            self.interface.peak_mem_usage = max(self.interface.peak_mem_usage, mem_usage)

    def _merge_states(self, node, *states, update_taint_summary):
        merged_state, merge_occured = states[0].merge(*states[1:], update_taint_summary=update_taint_summary)
        return merged_state, not merge_occured

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k not in \
             ("pal_project", "project", "interface", "_function_handler")
             }
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.pal_project = None
        self.project = None
        self.interface = None
        self._function_handler = None
