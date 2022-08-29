import logging
import weakref
from collections import defaultdict
from typing import List, Optional, Union, DefaultDict, Set, Any, Tuple, TYPE_CHECKING, Dict

import pyvex
from angr.codenode import BlockNode
from angr.factory import Block
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.functions import Function
from angr.calling_conventions import DEFAULT_CC
from angr.errors import SimMemoryMissingError
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset, HeapAddress

from .analyses_base import PalAnalyses, PalInterface
from ..structures.value_set import identical_ast, abstract_to_register
from ..singletons.reverse_adaptor import reverse_adaptor

from palantiri.cfg.cfgtest import *
from palantiri.cfg import CFGAnalysis
from palantiri.structures.value_set.vs_state import ValueSetState
from palantiri.structures.value_set.engine.fs_engine import SimEngineFSVEX
from palantiri.structures.value_set.vs_subject import VSSubject
if TYPE_CHECKING:
    from ..pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class FunctionSummaryInterface(PalInterface):
    """
    NOTE: this is an experimental class which is unused in the current implementation.

    FunctionSummaryInterface stands as the interface for each function-summary. It performs function summary for each
    in-sensitive function, in reverse-sorted manner.
    When inter-proc occurs in a single function, the function will leverage the pre-summarized function summary for its
    callee to enrich its own summary.
    """

    def __init__(self, pal_proj: 'PalProject', callgraph_acyclic=None, function_handler=None,
                 recover_from_disk=True, auto_save=True,
                 ):
        super(FunctionSummaryInterface, self).__init__(pal_proj=pal_proj, callgraph_acyclic=callgraph_acyclic,
                                                       function_handler=function_handler, auto_save=auto_save)

        self.function_summary_dict: Dict[Function, Dict] = {}
        self._start(recover_from_disk=recover_from_disk)

    def _start(self, recover_from_disk=True):
        # try to recover from serialized local file first
        if recover_from_disk and not os.path.exists(self.summary_dump_path):
            log.error(f"De-serialize function summaries result from local file {self.summary_dump_path} failed.")
        elif recover_from_disk:
            with open(self.summary_dump_path, "rb") as f:
                log.info(f"De-serializing function summaries result from local file {self.summary_dump_path}...")
                self.function_summary_dict = pickle.load(f)
                return

        # start the reversed-topological-style analysis and forward update
        sorted_functions: List = self.interproc_manager.sorted_functions
        log.info(f"Starting function summary analysis...")
        while sorted_functions:
            func_to_analyze = sorted_functions.pop(0)
            FunctionSummary(
                function=func_to_analyze, project=self.project, pal_proj=self._pal_project,
                interface=self._get_weakref(), function_handler=self._function_handler,
                do_taint_summary=True, propagate_taint_summary=True
            )

        # after analysis, serialize the results
        if self.auto_save:
            with open(self.summary_dump_path, "wb") as f:
                log.info(f"Serializing function summaries result to {self.summary_dump_path}...")
                pickle.dump(self.function_summary_dict, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _setup_adaptors(self):
        reverse_adaptor.set_interface(self)
        return reverse_adaptor

    @property
    def summary_dump_path(self):
        dir = self._pal_project.arg_info.analyses_output_path
        return os.path.join(dir, "function_summary_archive.dump")

    def update_function_summary_result(self, func: Function, fs_result_map: Dict):
        self.function_summary_dict[func] = fs_result_map


class FunctionSummary(PalAnalyses):
    """
    FunctionSummary performs analysis on single function, which is a intra-procedural task.
    # TODO(): perform sound graph visiting methods
    """
    def __init__(self, function: Union[Function, VSSubject], project: angr.Project, pal_proj,
                 interface: FunctionSummaryInterface=None, func_graph=None, track_tmps=False,
                 function_handler: Optional[FunctionHandler]=None,
                 init_state: Optional[ValueSetState]=None, do_taint_summary=True, propagate_taint_summary=True,
                 dep_graph: Optional[DepGraph]=None, canonical_size=8, max_iterations=5):
        """
        :param function: The subject function of function summary analysis, note that this analysis is function-level
        :param project: angr.Project
        :param func_graph: Alternative graph for function.graph
        :param track_tmps: Whether or not temporary values should be taken into consideration during the analysis
        :param init_state: An optional initialization state, and the analysis creates and works on a copy.
        :param dep_graph: An initial dependency graph to add the result of the analysis to.
        :param canonical_size: The sizes (byte-united) that objects with unknown size are treated as.
        """
        super(FunctionSummary, self).__init__(function=function, pal_proj=pal_proj, project=project,
                                              interface=interface, func_graph=func_graph, track_tmps=track_tmps,
                                              function_handler=function_handler, init_state=init_state,
                                              dep_graph=dep_graph, canonical_size=canonical_size,
                                              max_iterations=max_iterations,
                                              do_taint_summary=do_taint_summary,
                                              propagate_taint_summary=propagate_taint_summary)
        self.interface: FunctionSummaryInterface
        self._visited_blocks: Set[Any] = set()

        self._init_stack_offset = 0

        self._call_stack = None
        self._max_local_call_depth = 10
        self._engine = SimEngineFSVEX(self.project, self._call_stack, self._max_local_call_depth,
                                      functions=self.project.kb.functions,
                                      function_handler=self._function_handler)
        # A mapping between a node and its input state
        self._input_node_map: DefaultDict[Any, List[Any]] = defaultdict(list)
        self._output_node_map: DefaultDict[Any, Any] = defaultdict()
        #
        self._alloca_map = {}
        # side effect map
        self.reg_side_effect_set = set()
        self.global_side_effect_set = set()
        self.stack_side_effect_set = set()
        self.heap_side_effect_set = set()
        self.sym_side_effect_set = set()
        log.info(f"Start Function Summary for {self._subject.content.name}...")
        self._analyze()

    def _analyze(self):
        """
        """
        # pre analyze
        self._pre_analyze()
        log.debug(f"FunctionSummary handling function :{self._subject.content.name}")
        while True:
            node = self._graph_visitor.next_node()
            if node is None:
                break
            # TODO: FIXME DEBUG """debug!!"""
            if node.addr in [0x4011c9]:
                log.debug("aaaa")

            # 1. get the input state for function node
            state = self._get_and_update_input_state(node)
            if state is None:
                state = self._init_input_state(self._do_taint_summary)
            log.debug(f"Current node: {hex(node.addr)}.")
            # 2. process the node and state
            node_liveness, output_state = self._run_on_node(node, state)
            # FIXME: remove debug hook
            output_state._dbg_hook(node.addr)

            if node_liveness is False:
                # update output node (only plt functions)
                if self._should_update_output(node):
                    self._output_node_map[self._node_key(node)] = output_state
                continue
            else:
                # update output node (only plt functions)
                if self._should_update_output(node):
                    self._output_node_map[self._node_key(node)] = output_state
                # update its successors' input state
                self._add_input_state(node, output_state)
                # revisit all its successors
                self._graph_visitor.revisit_successors(node, include_self=False)
                continue
        # post analyze
        self._post_analyze()

    def _pre_analyze(self):
        pass

    def _post_analyze(self):
        """
        generate function summary and update to interface
        """
        if self._subject.content.is_plt:
            return
        states = self._output_node_map.values()
        if not states:
            return
        final_state, _ = self._merge_states(None, *states, update_taint_summary=self._propagate_taint_summary)
        fs_result_map = {
            "reg_side_effect_map": {},
            "stack_side_effect_map": {},
            "heap_side_effect_map": {},
            "global_side_effect_map": {},
            "sym_side_effect_map": {},
        }
        # we only update a minimal values to the interface
        # pass side effect maps for update
        for reg_unit in self.reg_side_effect_set:
            reg_offset, size = reg_unit
            if reg_offset > 136 or reg_offset in [48, 56]:   # FIXME: hard coded non GPRs and SP, BP registers
                continue
            try:
                fs_result_map["reg_side_effect_map"][(reg_offset, size)] = \
                    final_state.register_definitions.load(addr=reg_offset, size=size)
            except SimMemoryMissingError:
                continue
        for stack_unit in self.stack_side_effect_set:
            stack_offset, size = stack_unit
            if stack_offset < 0:
                continue
            stack_addr = final_state.live_definitions.stack_offset_to_stack_addr(stack_offset)
            try:
                fs_result_map["stack_side_effect_map"][(stack_offset, size)] = \
                    final_state.stack_definitions.load(addr=stack_addr, size=size, endness=final_state.arch.memory_endness)
            except SimMemoryMissingError:
                continue
        for heap_unit in self.heap_side_effect_set:
            heap_offset, size = heap_unit
            try:
                fs_result_map["heap_side_effect_map"][(heap_offset, size)] = \
                    final_state.heap_definitions.load(addr=heap_offset, size=size, endness=final_state.arch.memory_endness)
            except SimMemoryMissingError:
                continue
        for global_unit in self.global_side_effect_set:
            global_offset, size = global_unit
            try:
                fs_result_map["global_side_effect_map"][(global_offset, size)] = \
                    final_state.memory_definitions.load(addr=global_offset, size=size, endness=final_state.arch.memory_endness)
            except SimMemoryMissingError:
                continue
        for sym_str, size in self.sym_side_effect_set:
            try:
                fs_result_map["sym_side_effect_map"][(sym_str, size)] = \
                    final_state.symbolic_definitions.load(addr=sym_str, size=size)
            except SimMemoryMissingError:
                continue
        # update
        self.interface: FunctionSummaryInterface
        self.interface.update_function_summary_result(self._subject.content, fs_result_map)

    def _should_update_output(self, node):
        """
        """
        func: Function = self._subject.content
        if func.is_plt:
            return True
        # only record endpoints for post analyze (update fs)
        function_endpoints = self._subject.content.endpoints_with_type
        ret_points, call_points, trans_points = function_endpoints["return"], function_endpoints["call"], \
                                                function_endpoints["transition"]
        ret_points, tail_ret_points = list(ret_points), list(trans_points)
        tail_ret_points_not_cold = []
        for codenode in tail_ret_points:
            if not self._is_cold_jmpoutnode(codenode):
                tail_ret_points_not_cold.append(codenode)
        final_ret_point_addrs = list(map(lambda n: n.addr, ret_points + tail_ret_points_not_cold))
        if node.addr in final_ret_point_addrs:
            return True
        return False

    def update_side_effect_set(self, side_effect_set: Set, new_offset, new_size):
        for side_effect_unit in side_effect_set:
            offset, size = side_effect_unit
            if new_offset == offset and new_size > size:
                side_effect_set.remove(side_effect_unit)
                side_effect_set.add((new_offset, new_size))
                return
        side_effect_set.add((new_offset, new_size))

    def register_use_def_analysis(self):
        """
        Analyse the registers, specifically the parameter registers of x64 ABI for Linux.
        1. Analyze the parameter regs (rdi, rsi, rdx, rcx, r8, r9), to determine the parameters' number and type
        (TypeArmor):
           Get the function's ceiling block's output state, and query the definitions of those parameter regs,
           and determine any of them are: a) could be used by the external definition (definitely used as parameter)

        2. Analyze the return reg (rax) to determine the return type (return or none-return):
           Get the function's ceiling block's output state, and query thre definition of the return reg. If the reg is
           defined inside the function, then the function has return value

        3. Analyze the caller saved regs ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11', 'rax'), and determine
           whether they are defined inside the functions

        Note that is method should be used in a *reversed-topological* sorted order, which is trying to ensure that
        function could be analyzed, without handling local calls to other functions which are also not analyzed yet.

        :return:
        """
        cc = DEFAULT_CC.get(self.project.arch.name, None)(self.project.arch)
        ceiling_addr = CFGAnalysis.function_floor_ceiling_block(self.project, self._subject.content)[-1]
        try:
            output_state: ValueSetState = self._output_node_map[self._node_key(ceiling_addr)]
        except KeyError:
            # the case that cailing block, which is nop block, has been refined
            ceiling_addr = sorted(self._output_node_map.keys())[-1]
            output_state: ValueSetState = self._output_node_map[self._node_key(ceiling_addr)]

        parameter_atoms = [Register(self.project.arch.registers[reg_name][0], self.project.arch.registers[reg_name][1])
                           for reg_name in cc.ARG_REGS]
        caller_save_atoms = [Register(self.project.arch.registers[reg_name][0],
                                         self.project.arch.registers[reg_name][1]) for reg_name in cc.CALLER_SAVED_REGS]
        return_atom = Register(self.project.arch.registers[cc.RETURN_VAL.reg_name][0],
                               self.project.arch.registers[cc.RETURN_VAL.reg_name][1])

        parameter_regs, no_used_regs, no_defined_regs = defaultdict(), [], []
        return_val = True
        # 1. analyze the parameter registers
        # note that the output_state's use contains all the possible uses since the function start point
        for def_, uses in output_state.register_uses._uses_by_definition.items():
            if not def_.atom in parameter_atoms or def_.codeloc != ExternalCodeLocation():
                continue

            if len(uses):
                parameter_regs.setdefault(def_.atom, def_.atom.size * self.project.arch.byte_width)
                log.debug(f"External parameter register: {def_} --> {uses}")
                # 1.1 type recovery: determine an under_approximated used size
                for use in uses:
                    use: CodeLocation
                    insn_addr, node = use.ins_addr, self._subject.content.get_node(use.block_addr)
                    block = self.project.factory.block(node.addr, node.size)
                    # get imark
                    imrks = list(filter(lambda stmt: isinstance(stmt, pyvex.stmt.IMark) and stmt.addr == insn_addr,
                                        block.vex.statements))
                    if len(imrks) != 1:
                        log.error(f"Multiple instruction IMarks found: {imrks}.")
                        raise ValueError
                    idx, lens = block.vex.statements.index(imrks[0]), imrks[0].len
                    for stmt in block.vex.statements[idx+1: idx+1+lens]:
                        # search for the correct GET: () stmt
                        # in case that stmt is Exit or AbiHint, there is no attribute data
                        try:
                            data = stmt.data
                        except AttributeError:
                            continue
                        if not isinstance(data, pyvex.expr.Get):
                            continue
                        if data.offset != def_.atom.reg_offset:
                            continue
                        # get size
                        GET_size = data.result_size(block.vex.tyenv)
                        if GET_size < parameter_regs[def_.atom]:
                            parameter_regs[def_.atom] = GET_size
                        break

        # 2. analyze the return register
        try:
            v: MultiValues = output_state.register_definitions.load(return_atom.reg_offset, return_atom.size)
        except SimMemoryMissingError:
            # return register not defined and used, thus no return value
            return_val = False
            no_used_regs.append(return_atom)
            caller_save_atoms.remove(return_atom)
            v = None
        if v is not None:
            vs = v.values[0]
            for val in vs:
                definition = next(iter(output_state.extract_defs(val)))
                if definition.codeloc.block_addr in self._subject.content.block_addrs:
                    log.debug(f"Return register defined: {definition}")
                    return_val = True
                    break

        # if rsi, rdx, rcx in params without rdi, we complete that
                # determine para nums
        reg_offsets = list(map(lambda reg: reg.reg_offset, parameter_regs.keys()))
        if not reg_offsets:
            para_nums = 0
        else:
            min_para_id = min(reg_offsets)
            max_para_id = max(reg_offsets)
            max_reg = abstract_to_register(max_para_id, 8, self.project)
            min_reg = abstract_to_register(min_para_id, 8, self.project)

            if max_reg == "r8":
                para_nums = 5
            elif max_reg == "r9":
                para_nums = 6
            elif min_reg == "rcx":
                para_nums = 4
            elif min_reg == "rdx":
                para_nums = 3
            elif min_reg == "rsi":
                para_nums = 2
            elif min_reg == "rdi":
                para_nums = 1
            else:
                para_nums = 0
        return {"parameter_regs": parameter_regs, "parameter_nums": para_nums, "return_val": True}

    def callsite_registers_use_def(self, callsite_bb_addr: int):
        """
        Analyse the registers def-use at a callsite, specifically the parameter registers of x64 ABI for Linux.
        1. Analyze the parameter regs (rdi, rsi, rdx, rcx, r8, r9), to determine the parameters' number and type
        (TypeArmor):
           Get the function's ceiling block's output state, and query the definitions of those parameter regs,
           and determine any of them are: a) could be used by the external definition (definitely used as parameter)

        2. Analyze the return reg (rax) to determine the return type (return or none-return):
           Get the function's ceiling block's output state, and query thre definition of the return reg. If the reg is
           defined inside the function, then the function has return value

        3. Analyze the caller saved regs ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11', 'rax'), and determine
           whether they are defined inside the functions

        Note that is method should be used in a *reversed-topological* sorted order, which is trying to ensure that
        function could be analyzed, without handling local calls to other functions which are also not analyzed yet.
        # TODO(): if the parameter registers including six registers, should further analyze the stack to determine the
        #      TODO(): number of parameters (but it is enough for current usage)
        """
        log.info(f"Resolving registers at callsite block {hex(callsite_bb_addr)}")
        cc = DEFAULT_CC.get(self.project.arch.name, None)(self.project.arch)
        output_state: ValueSetState = self._output_node_map[self._node_key(callsite_bb_addr)]

        parameter_atoms = [Register(self.project.arch.registers[reg_name][0], self.project.arch.registers[reg_name][1])
                           for reg_name in cc.ARG_REGS]

        caller_save_atoms = [Register(self.project.arch.registers[reg_name][0],
                                      self.project.arch.registers[reg_name][1]) for reg_name in cc.CALLER_SAVED_REGS]
        return_atom = Register(self.project.arch.registers[cc.RETURN_VAL.reg_name][0],
                               self.project.arch.registers[cc.RETURN_VAL.reg_name][1])

        parameter_regs, no_used_regs, no_defined_regs = defaultdict(), [], []
        return_val = False
        # 1. analyze the parameter registers
        # for those defined parameter registers, we treat them as parameters
        for reg_atom in parameter_atoms:
            try:
                v: MultiValues = output_state.register_definitions.load(reg_atom.reg_offset, reg_atom.size)
                values = v.values[0]
            except SimMemoryMissingError:
                # atom register has never been defined before
                no_defined_regs.append(reg_atom)
                continue
            is_external_defined, max_size = True, 0

            for reg_val in values:
                if not len(reg_val.annotations):
                    continue
                # get definition of the value, and determine the location
                def_: Definition = next(iter(output_state.extract_defs(reg_val)))
                if isinstance(def_.codeloc, ExternalCodeLocation):
                    continue
                is_external_defined = False
                # determine the maximum size defined
                insn_addr, node = def_.codeloc.ins_addr, self._subject.content.get_node(def_.codeloc.block_addr)
                block = self.project.factory.block(node.addr, node.size)
                imrks = list(filter(lambda stmt: isinstance(stmt, pyvex.stmt.IMark) and stmt.addr == insn_addr,
                                    block.vex.statements))
                if len(imrks) != 1:
                    log.error(f"Multiple instruction IMarks found: {imrks}.")
                    raise ValueError
                idx, lens = block.vex.statements.index(imrks[0]), imrks[0].len
                for stmt in block.vex.statements[idx + 1: idx + 1 + lens]:
                    # search for the correct PUT: () stmt, e.g.: PUT(offset=64) = t1
                    if not isinstance(stmt, pyvex.stmt.Put):
                        continue
                    if stmt.offset != def_.atom.reg_offset:
                        continue
                    # put size
                    PUT_size = stmt.data.result_size(block.vex.tyenv)
                    if PUT_size >= max_size:
                        max_size = PUT_size
                    break

            if is_external_defined:
                no_defined_regs.append(reg_atom)
                continue

            parameter_regs[reg_atom] = max_size

        # 2. analyze the return register
        callsite_node = self._subject.content.get_node(callsite_bb_addr)
        callsite_block = self.project.factory.block(callsite_node.addr, callsite_node.size)
        callsite_insn = callsite_block.instruction_addrs[-1]

        ceiling_addr = CFGAnalysis.function_floor_ceiling_block(self.project, self._subject.content)[-1]
        output_state: ValueSetState = self._output_node_map[self._node_key(ceiling_addr)]

        for def_, uses in output_state.register_uses._uses_by_definition.items():
            if not def_.atom == return_atom or def_.codeloc.ins_addr == callsite_insn:
                continue
            if len(uses):
                return_val = True
                break

        # determine para nums
        reg_offsets = list(map(lambda reg: reg.reg_offset, parameter_regs.keys()))
        if not reg_offsets:
            para_nums = 0
        else:
            min_para_id = min(reg_offsets)
            max_para_id = max(reg_offsets)
            max_reg = abstract_to_register(max_para_id, 8, self.project)
            min_reg = abstract_to_register(min_para_id, 8, self.project)

            if max_reg == "r8":
                para_nums = 5
            elif max_reg == "r9":
                para_nums = 6
            elif min_reg == "rcx":
                para_nums = 4
            elif min_reg == "rdx":
                para_nums = 3
            elif min_reg == "rsi":
                para_nums = 2
            elif min_reg == "rdi":
                para_nums = 1
            else:
                para_nums = 0
        return {"parameter_regs": parameter_regs, "parameter_nums": para_nums, "return_val": True}
