import weakref
# from memory_profiler import profile
from collections import defaultdict
from typing import List, Optional, Union, DefaultDict, Set, Any, Dict, TYPE_CHECKING

import networkx as nx
import claripy.ast
import pyvex
from angr.codenode import BlockNode
from angr.errors import SimMemoryMissingError
from angr.factory import Block
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.functions import Function
from angr.code_location import CodeLocation
from angr.calling_conventions import DEFAULT_CC
from angr.analyses.reaching_definitions.function_handler import FunctionHandler

from palantiri.cfg.cfgtest import *
from ..cfg.cfg_util import CFGAnalysis
from ..singletons.adaptors.adaptor_manager import AdaptorManager
from ..structures.key_definitions import GENERAL_REGS_NO_STACKS_x64
from ..structures.value_set.value_domains.taint_logic import TaintTag
from ..structures.value_set.taint import TaintType, str_to_taint_type, str_to_tagged_tp

from palantiri.structures.value_set.vs_state import ValueSetState
from ..structures.value_set import identical_ast
from ..structures.utils import simplify_ast
from ..structures.value_set.value_domains.abstract_region import AbstractRegion, AbstractType
from ..structures.utils.symbol_utils import extract_bvs, extract_sym_and_off
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues
from palantiri.structures.value_set.engine.bs_engine import SimEngineBSVEX
from palantiri.structures.value_set.vs_subject import VSSubject
from palantiri.structures.value_set.vs_graphvisitor import VSFuncGraphVisitor

if TYPE_CHECKING:
    from ..pal_project import PalProject


class PalInterface:
    def __init__(self, pal_proj: 'PalProject', callgraph_acyclic=None, function_handler=None, auto_save=True,
                 loop_revisit_mode=False, max_symbol_reference_depth=3,
                 without_whole_segment=False,
                 mem_rw_upperbound=10,
                 valueset_upperbound=15,
                 ):
        self._pal_project = pal_proj
        self.project = pal_proj.angr_project
        # track plt function times and assign unique symbolic return value
        self._plt_function_times_map = defaultdict(lambda: 0)

        self._function_handler = function_handler
        self.callgraph_acyclic = callgraph_acyclic if callgraph_acyclic is not None \
            else self._initialize_call_graph()

        self.without_whole_segment = without_whole_segment

        # set interproc adaptor
        self.interproc_manager: AdaptorManager = self._setup_adaptors()

        self.loop_revisit_mode = loop_revisit_mode
        self.max_symbol_reference_depth = max_symbol_reference_depth
        self.auto_save = auto_save

        # approximate limitation for analysis
        self.mem_rw_upperbound = mem_rw_upperbound
        self.valueset_upperbound = valueset_upperbound
        # determine the segments to analysis

    def _setup_adaptors(self):
        raise NotImplementedError

    def _initialize_call_graph(self, resolve_indirect_call=True):
        # cfg = self._pal_project.cfg_util.cfg
        # _, callgraph_acyclic = CFGAnalysis.recover_call_graph(self._pal_project, cfg)
        # return callgraph_acyclic
        return self._pal_project.callgraph

    def _get_weakref(self):
        return weakref.proxy(self)

    @property
    def summary_dump_path(self):
        return None


class PalAnalyses:

    def __init__(self, function: Union[Function, VSSubject], pal_proj: 'PalProject',
                 project: angr.Project, interface: PalInterface,
                 func_graph=None, track_tmps=False, function_handler: Optional[FunctionHandler] = None,
                 init_state: Optional[ValueSetState] = None, dep_graph: Optional[DepGraph] = None, canonical_size=8,
                 max_iterations=2, call_stack: Optional[List[int]] = None,
                 do_taint_summary=True, propagate_taint_summary=False, immediate_update=True, auto_save=True,
                 max_symbol_reference_depth=2):
        """
        :param function: The subject function of function summary analysis, note that this analysis is function-level
        :param project: angr.Project
        :param func_graph: Alternative graph for function.graph
        :param track_tmps: Whether or not temporary values should be taken into consideration during the analysis
        :param init_state: An optional initialization state, and the analysis creates and works on a copy.
        :param dep_graph: An initial dependency graph to add the result of the analysis to.
        :param canonical_size: The sizes (byte-united) that objects with unknown size are treated as.
        :param do_taint_summary: Whether do static taint summary when performing VSA
        :param tmp_to_file: it True, then _output_node_map is useless, the tmp result is immediately to local file
        """

        if isinstance(function, Function):
            self._subject: VSSubject = VSSubject(project, function, func_graph, function.calling_convention,
                                                 refine_graph=True)
        else:
            self._subject: VSSubject = function
        self._graph_visitor: VSFuncGraphVisitor = self._subject.visitor
        self.pal_project = pal_proj
        self.project = project
        self.interface: PalInterface = interface
        self.max_symbol_reference_depth = max_symbol_reference_depth

        self._init_state = init_state
        self._init_stack_offset = 0
        self._canonical_size = canonical_size

        self.global_section_range = self._initialize_global_region()

        self._should_abort = False
        self._dep_graph = dep_graph
        self._function_handler = function_handler
        if self._function_handler is not None:
            self._function_handler = self._function_handler.hook(self)

        self._do_taint_summary = do_taint_summary
        self._propagate_taint_summary = propagate_taint_summary and do_taint_summary
        # simple constraint
        # only solve (test reg): test rax, tax; je ->
        # (src_blk, reg_name): (dst_blk_addr)
        self.block_testcond_constraint = {}

        if self._init_state is not None:
            self._init_state = self._init_state.copy(copy_taint_summary=False)
            self._init_state.analysis = self

        self._visited_blocks: Set[Any] = set()

        self._max_iterations = max_iterations
        self._node_iterations: DefaultDict[int, int] = defaultdict(int)

        self.revisit_activate_node = None

        self._immediate_update = immediate_update
        self._auto_save = auto_save

        self._call_stack = call_stack

        self._track_tmps = track_tmps
        self._max_local_call_depth = 30
        self._engine = SimEngineBSVEX(self.project, self._call_stack, self._max_local_call_depth,
                                      functions=self.project.kb.functions,
                                      function_handler=self._function_handler,
                                      )
        #
        self._alloca_map = {}
        # A mapping between a node and its input state
        self._input_node_map: DefaultDict[Any, List[Any]] = defaultdict(list)
        self._output_node_map: DefaultDict[Any, Any] = defaultdict()
        self._aftercalled_node_map: DefaultDict[Any, Any] = defaultdict()

        #
        self.reg_side_effect_set = set()
        self.global_side_effect_set = set()
        self.stack_side_effect_set = set()
        self.heap_side_effect_set = set()
        self.sym_side_effect_set = set()
        # function type recovery
        self._parameter_registers = None
        self._return_val = None

    @property
    def should_abort(self):
        return self._should_abort

    @property
    def dep_graph(self):
        return self._dep_graph

    @property
    def visited_blocks(self):
        return self._visited_blocks

    def abort(self):
        self._should_abort = True

    def _dbg_callstack(self):
        l = []
        for cs in self._call_stack:
            cfgnode = self.interface._pal_project.cfg_util.cfg.get_any_node(cs)
            func_addr = cfgnode.function_address
            name = self.project.kb.functions[func_addr].name
            l.append(name)
        return l

    def _initialize_global_region(self):
        # TODO(): refine the logic of determining global regions
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
        pass

    def _post_analyze(self):
        pass

    def _analyze(self):
        pass

    def update_from_function_summary(self, state: ValueSetState, fs_result_dict: Dict, codeloc: CodeLocation):
        """
        Forward update the function summary's result
        NOTE: This function is experimental and unused in the current implementation
        """
        updated_state = state.copy(copy_taint_summary=self._propagate_taint_summary)
        # 1. update values
        # should update symbolic values and taint summary first, to ensure that if other domains later on uses the
        # FIXME: need update those stack parameters
        transaction_dict = {}
        d0 = self._update_value_from_function_summary(updated_state, fs_result_dict["sym_side_effect_map"], "sym")
        d1 = self._update_value_from_function_summary(updated_state, fs_result_dict["reg_side_effect_map"], "reg")
        d2 = self._update_value_from_function_summary(updated_state, fs_result_dict["heap_side_effect_map"], "heap")
        d3 = self._update_value_from_function_summary(updated_state, fs_result_dict["global_side_effect_map"], "global")
        for d in [d0, d1, d2, d3]:
            transaction_dict.update(d)

        for trans_key, trans_v in transaction_dict.items():
            v, strong_update = trans_v
            try:
                updated_state.taint_summary._commit_transaction({trans_key: v}, weak_update=not strong_update)
            except:
                print("dbg")
        return updated_state

    def _update_value_from_function_summary(self, state: ValueSetState, value_dict: Dict, side_effect_type: str) \
            -> Dict:
        """
        :param side_effect_type: the type of side effect dict to update
        :return transaction_dict for the state to update, and a bool value indicates whether strong update (True then
                strong update)
        NOTE: This function is experimental and unused in the current implementation    
        """
        _cc = DEFAULT_CC[self.project.arch.name](self.project.arch)
        current_sp_val = state.register_definitions.load(state.arch.sp_offset, state.arch.byte_width).one_value()
        current_stack_relevant_offset = state.get_stack_offset(current_sp_val) - state.analysis._init_stack_offset

        def _update_val_and_state_taints(state: ValueSetState, val: claripy.ast.Base, taint_type, taint_offset, taint_size):
            """
            Use the state as taint summary base, and the update a value's taint tags, as well as updating the
            state's taint summary
            """
            taint_tags = state.extract_taint_tags(val)
            # 1. re-offset those stack tags for the child functions,
            #    set the offset as the relevant-offset to the currnet caller function
            rotated_taint_tags = set()

            for tag in taint_tags:
                if tag.metadata["tagged_tp"] == "stack":
                    ntag = TaintTag.from_other(tag)
                    ntag.metadata["tagged_off"] += current_stack_relevant_offset
                    rotated_taint_tags.add(ntag)

                elif tag.metadata["tagged_tp"] == "symbol":
                    # try to convert symbolic memory address to its region, based on the state
                    # and we mark the original symbolic taint tags -> those region, for further lookup
                    to_update_regions = set()
                    symaddr = tag.metadata["tagged_off"]
                    symbase, offset = extract_sym_and_off(symaddr)
                    if symbase not in GENERAL_REGS_NO_STACKS_x64:
                        to_update_regions.add(AbstractRegion(AbstractType.Symbolic, offset, symbolic_base=symbase))
                    else:
                        symreg_offset = self.project.arch.registers[symbase][0]
                        for loaded_val in state.register_definitions.load(symreg_offset, taint_size).values[0]:
                            regions = state.extract_abs_regions(loaded_val)
                            for region in regions:
                                to_update_regions.add(region + offset)

                    for region in to_update_regions:
                        rotate_tagged_type = str_to_tagged_tp(region.type)
                        rotate_tag = TaintTag(metadata={
                            "tagged_tp": rotate_tagged_type,
                            "tagged_off": region.offset if rotate_tagged_type != "symbol" else region.symbol_address(),
                            "tagged_sz": taint_size if rotate_tagged_type != "symbol" else 1,
                            "tagged_by": region.type + hex(region.offset)
                        })
                        rotated_taint_tags.add(rotate_tag)
                else:
                    rotated_taint_tags.add(tag)

            updated_tags, to_update_transaction = \
                state.taint_summary.base_to_update_region_with_taints(rotated_taint_tags, taint_type, taint_offset,
                                                                      taint_size)
            return updated_tags, to_update_transaction


        to_update_transcations = {}

        if side_effect_type != "sym":

            taint_type = str_to_taint_type(side_effect_type)

            for skey, data in value_dict.items():
                offset, update_size = skey
                # re-calculate values to update symbol-references
                d = VSMultiValues()
                data: VSMultiValues
                for off, vals in data.values.items():
                    for val in vals:
                        if val.concrete:
                            updated_taint_tags, to_update = _update_val_and_state_taints(state, val, taint_type,
                                                                                         offset, update_size)
                            to_update_transcations.update({k: (v, True) for k, v in to_update.items()})
                            nval = state.annotate_with_taint_tags(val, updated_taint_tags)
                            d.add_value(offset=off, value=nval)
                        else:
                            symbol = extract_bvs(val)
                            if not symbol.args[0] in GENERAL_REGS_NO_STACKS_x64:
                                nval = val
                                # update taint summary (use state as the base)
                                updated_taint_tags, to_update = _update_val_and_state_taints(state, nval, taint_type,
                                                                                             offset, update_size)
                                to_update_transcations.update({k: (v, True) for k, v in to_update.items()})
                                nval = state.annotate_with_taint_tags(nval, updated_taint_tags)
                                d.add_value(offset=off, value=nval)
                            # do update
                            else:
                                symreg_offset = self.project.arch.registers[symbol.args[0]][0]
                                for loaded_val in state.register_definitions.load(symreg_offset, update_size).values[0]:
                                    try:
                                        original_sz = None
                                        if symbol.size() != val.size():
                                            original_sz = symbol.size()
                                            symbol.length = val.size()
                                        nval = simplify_ast( val.replace(symbol, loaded_val) )
                                        if original_sz:
                                            symbol.length = original_sz
                                    except:
                                        print("dbg")
                                    nval.append_annotations( val.annotations )
                                    # update taint tags
                                    updated_taint_tags, to_update = _update_val_and_state_taints(state, nval, taint_type,
                                                                                                 offset, update_size)
                                    to_update_transcations.update({k: (v, True) for k, v in to_update.items()})
                                    nval = state.annotate_with_taint_tags(nval, updated_taint_tags)
                                    d.add_value(offset=off, value=nval)
                # commit change to taints
                # update values
                if side_effect_type == "reg":
                    # since the values' taint tags and the state's taint summary has been updated,
                    # we just need to update value here
                    state.register_definitions.store(offset, data=d, size=update_size)
                    self.reg_side_effect_set.add((offset, update_size))
                elif side_effect_type == "heap":
                    state.heap_definitions.store(offset, data=d, size=update_size, endness=state.arch.memory_endness)
                    self.heap_side_effect_set.add((offset, update_size))
                elif side_effect_type == "global":
                    state.memory_definitions.store(offset, data=d, size=update_size, endness=state.arch.memory_endness)
                    self.global_side_effect_set.add((offset, update_size))
                else: # stack, just pass for now
                    pass

            return to_update_transcations

        else:
            for sym_k, data in value_dict.items():
                symaddr, update_size = sym_k
                symbase, offset = extract_sym_and_off(symaddr)

                # 1. try to convert symbolic memory address to its region, based on the state
                potential_update_regions = set()

                if symbase not in GENERAL_REGS_NO_STACKS_x64:
                    potential_update_regions.add(AbstractRegion(AbstractType.Symbolic, offset, symbolic_base=symbase))
                else:
                    symreg_offset = self.project.arch.registers[symbase][0]
                    for loaded_val in state.register_definitions.load(symreg_offset, 8).values[0]:
                        regions = state.extract_abs_regions(loaded_val)
                        for region in regions:
                            potential_update_regions.add(region + offset)

                # if there are more than 1 region, then we should weak update its taints
                to_update_taint_types = set()
                strong_update = True if len(potential_update_regions) == 1 else False

                for region in potential_update_regions:
                    taint_type = str_to_taint_type(region.type)
                    taint_offset = region.offset if taint_type != TaintType.SYM else region.symbol_address()
                    taint_size = update_size if taint_type != TaintType.SYM else 1
                    to_update_taint_types.add((taint_type, taint_offset, taint_size))

                # 2. update values
                d = VSMultiValues()
                data: VSMultiValues
                for off, vals in data.values.items():
                    for val in vals:
                        if val.concrete:
                            updated_taint_tags = set()

                            for taint_update_unit in to_update_taint_types:
                                taint_type, offset, size = taint_update_unit
                                type_updated_tags, to_update = _update_val_and_state_taints(state, val, taint_type,
                                                                                            offset, size)
                                to_update_transcations.update({k: (v, strong_update) for k, v in to_update.items()})
                                updated_taint_tags.update(type_updated_tags)

                            nval = state.annotate_with_taint_tags(val, updated_taint_tags)
                            d.add_value(offset=off, value=nval)
                        else:
                            symbol = extract_bvs(val)
                            if not symbol.args[0] in GENERAL_REGS_NO_STACKS_x64:
                                nval = val
                                # update taint summary (use state as the base)
                                updated_taint_tags = set()
                                for taint_update_unit in to_update_taint_types:
                                    taint_type, offset, size = taint_update_unit
                                    type_updated_tags, to_update = _update_val_and_state_taints(state, nval, taint_type,
                                                                                                offset, size)
                                    to_update_transcations.update({k: (v, strong_update) for k, v in to_update.items()})
                                    updated_taint_tags.update(type_updated_tags)

                                nval = state.annotate_with_taint_tags(nval, updated_taint_tags)
                                d.add_value(offset=off, value=nval)
                            # do update
                            else:
                                symreg_offset = self.project.arch.registers[symbol.args[0]][0]

                                for loaded_val in state.register_definitions.load(symreg_offset, update_size).values[0]:
                                    original_sz = None
                                    if symbol.size() != val.size():
                                        original_sz = symbol.size()
                                        symbol.length = val.size()
                                    try:
                                        nval = simplify_ast(val.replace(symbol, loaded_val))
                                    except:
                                        print("dbg")
                                    if original_sz:
                                        symbol.length = original_sz
                                    nval.append_annotations(val.annotations)
                                    # update taint tags
                                    updated_taint_tags = set()
                                    for taint_update_unit in to_update_taint_types:
                                        taint_type, offset, size = taint_update_unit
                                        type_updated_tags, to_update = _update_val_and_state_taints(state, nval,
                                                                                                     taint_type,
                                                                                                     offset, size)
                                        to_update_transcations.update({k: (v, strong_update) for k, v in to_update.items()})
                                        updated_taint_tags.update(type_updated_tags)

                                    nval = state.annotate_with_taint_tags(nval, updated_taint_tags)
                                    d.add_value(offset=off, value=nval)

                # update value to regions
                for region in potential_update_regions:
                    if region.type == AbstractType.Stack:
                        stackaddr = state.live_definitions.stack_offset_to_stack_addr(region.offset)
                        if strong_update:
                            store_data = d
                        else:
                            try:
                                store_data = d.merge(state.stack_definitions.load(stackaddr, update_size, endness=state.arch.memory_endness))
                            except SimMemoryMissingError:
                                store_data = d
                        state.stack_definitions.store(stackaddr, store_data, size=update_size, endness=state.arch.memory_endness)
                        self.stack_side_effect_set.add((stackaddr, update_size))
                    elif region.type == AbstractType.Heap:
                        heapaddr = region.offset
                        if strong_update:
                            store_data = d
                        else:
                            try:
                                store_data = d.merge(state.heap_definitions.load(heapaddr, update_size, endness=state.arch.memory_endness))
                            except SimMemoryMissingError:
                                store_data = d
                        state.heap_definitions.store(heapaddr, store_data, size=update_size, endness=state.arch.memory_endness)
                        self.heap_side_effect_set.add((heapaddr, update_size))
                    elif region.type == AbstractType.Global:
                        global_addr = region.offset
                        if strong_update:
                            store_data = d
                        else:
                            try:
                                store_data = d.merge(state.memory_definitions.load(global_addr, update_size, endness=state.arch.memory_endness))
                            except SimMemoryMissingError:
                                store_data = d
                        state.memory_definitions.store(global_addr, store_data, size=update_size, endness=state.arch.memory_endness)
                        self.global_side_effect_set.add((global_addr, update_size))
                    else:
                        symaddr = region.symbol_address()
                        if strong_update:
                            store_data = d
                        else:
                            try:
                                store_data = d.merge(state.symbolic_definitions.load(symaddr, update_size))
                            except SimMemoryMissingError:
                                store_data = d
                        state.symbolic_definitions.store(symaddr, store_data, size=update_size, endness=state.arch.memory_endness)
                        self.sym_side_effect_set.add((symaddr, update_size))
            return to_update_transcations


    def get_alloca_map(self, key):
        for k in self._alloca_map.keys():
            if identical_ast(key, k):
                return self._alloca_map[k]
        return None

    def set_alloca_map(self, key, value):
        for k in self._alloca_map.keys():
            if identical_ast(key, k):
                self._alloca_map[k] = value
                return
        self._alloca_map[key] = value

    def _node_key(self, node):
        if isinstance(node, BlockNode):
            return node.addr
        return node

    def _run_on_node(self, node, state):
        """
        Process the node, with the input state.
        :param node: a node which generated following the visitor
        :param state: input state of the node
        """
        assert isinstance(node, BlockNode) or isinstance(node, Block)
        self._visited_blocks.add(node)
        # it's important for us to do not open cross_insn_opt, since we should do some optimization heuristically
        # to reduce the false positive in static computation
        node_to_block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
        # copy the original input state
        state = state.copy(copy_taint_summary=self._propagate_taint_summary)
        # process the state via the engine
        state, self._visited_blocks, self._dep_graph = self._engine.process(
            state,
            block=node_to_block,
            fail_fast=None,
            visited_blocks=self._visited_blocks,
            dep_graph=self._dep_graph,
        )
        # add node iterations
        self._node_iterations[self._node_key(node)] += 1
        # TODO(): update global def and use
        # update node status. If the iterations of the node doesn't exceed the threshold,
        # the analysis should consider that node as living node, and re-process its successors.
        return True, state

    def _merge_states(self, node, *states, update_taint_summary):
        merged_state, merge_occured = states[0].merge(*states[1:], update_taint_summary=update_taint_summary)
        return merged_state, not merge_occured

    def _get_and_update_input_state(self, node):
        """
        Get the input abstract state for this node, and remove it from the state map.
        #TODO(): Does it is needed to force-clear the input state for the next iteration?
        :param node: The node in graph.
        :return:     A merged state, or None if there is no input state for this node available.
        """

        if self._node_key(node) in self._input_node_map:
            input_state = self._get_input_state(node)
            # self._input_node_map[self._node_key(node)] = [ input_state ]
            self._input_node_map.pop(self._node_key(node))
            return input_state
        log.warning(f"Get input state for node {hex(node.addr)} failed...")
        return None

    def _get_input_state(self, node):
        """
        Due to the path-insensitivity, a state's input is a joint of its predecessors.
        """
        if self._node_key(node) not in self._input_node_map:
            log.warning(f"Get input state for node {hex(node.addr)} failed...")
            return None

        # merge all input states
        all_input_states = self._input_node_map.get(self._node_key(node))
        if len(all_input_states) == 1:
            return all_input_states[0]
        merged_state, _ = self._merge_states(node, *all_input_states,
                                             update_taint_summary=self._propagate_taint_summary)
        # select SP value carefully, we only reserve one value
        sp_candidate_vals = merged_state.register_definitions.load(self.project.arch.sp_offset, self.project.arch.bytes)
        if len(sp_candidate_vals.values[0]) == 1:
            return merged_state

        offset_to_sp = { }
        for sp in sp_candidate_vals.values[0]:
            offset = merged_state.get_stack_offset(sp)
            offset_to_sp[offset] = sp

        log.debug(f"Multiple SP values: {offset_to_sp.values()}, occurred at {hex(node.addr)}")
        least_val = sorted(offset_to_sp.keys())[0]
        sp_val = VSMultiValues(offset_to_values={0: {offset_to_sp[least_val]}})
        merged_state.register_definitions.store(self.project.arch.sp_offset, sp_val, self.project.arch.bytes)
        return merged_state

    def _init_input_state(self, do_taint_summary):
        if self._init_state is not None:
            # update initial stack offset of the summary
            sp = self._init_state.register_definitions.load(self.project.arch.sp_offset, self.project.arch.bytes)
            sp = sp.one_value()
            offset = self._init_state.get_stack_offset(sp)
            self._init_stack_offset = offset
            return self._init_state
        return ValueSetState(self.project.arch, self._subject, self._track_tmps,
                             analysis=self._get_weakref(), canonical_size=self._canonical_size,
                             do_taint_summary=do_taint_summary)

    def _add_input_state(self, node, input_state):
        """
        Add the input state to all successors of the given node.

        :param node:        The node whose successors' input states will be touched.
        :param input_state: The state that will be added to successors of the node.
        :return:            None
        """
        successors = set(self._graph_visitor.successors(node))
        for succ in successors:
            # if a node has only one predecessor, we overwrite existing input states
            # otherwise, we add the state as a new input state
            # this is an approximation for removing input states for all nodes that `node` dominates
            if sum(1 for _ in self._graph_visitor.predecessors(succ)) == 1:
                self._input_node_map[self._node_key(succ)] = [ input_state ]
            else:
                # TODO(): clear self
                self._input_node_map[self._node_key(succ)].append(input_state)
        return successors

    def _set_revisit_successors_of_node(self, node, state):
        """
        Determine if a node's successors should be visited
        """
        # In this case, the revisit mode is off, or the revisit mode has not been activated. We'll do nothing.
        if (not self.interface.loop_revisit_mode or not self.revisit_activate_node):
            return

        successors = set(self._graph_visitor.successors(node))

        # only successors which iteration times in (1, max_iter) will be pending, we will discard those nodes have not
        # been visited once or have exceeded the max iteration threshold.
        pending_revisit_succs = list(filter(
            lambda sc: self._node_iterations[self._node_key(sc)] in range(1, self._max_iterations),
            successors
        ))
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

    def _get_weakref(self):
        return weakref.proxy(self)

    def _is_cold_jmpoutnode(self, jumpout_node):
        """
        Determine whether a node jumps to a .cold function
        """
        block = self.project.factory.block(jumpout_node.addr, jumpout_node.size)
        # Filter all non 'jmp' tail calls (filter tail calls with 'js' or 'jz'). The observation is that non 'jmp'
        # calls are likely to be to .cold.n functions
        if block.capstone.insns[-1].mnemonic != "jmp":
            return True
        # indirect jump will not jump to .cold functions
        if not isinstance(block.vex.next, pyvex.expr.Const):
            return False
        tar_func_addr = block.vex.next.con.value
        tar_func = self.project.kb.functions[tar_func_addr]
        # try to use symbol first
        if tar_func.name.find(".cold") >= 0:
            return True
        # when there is no such symbol, we assert .cold function always call abort()
        func_blocks = list(tar_func.blocks)
        if len(func_blocks) == 1:
            block = func_blocks[0]
            callout_addrs = list(map(lambda n: n.addr, tar_func.callout_sites))
            if block.addr in callout_addrs:
                calltarget = self.project.kb.functions[tar_func.get_call_target(block.addr)]
                if calltarget.name in ['abort']:
                    return True
            return False
        else:
            return False

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
