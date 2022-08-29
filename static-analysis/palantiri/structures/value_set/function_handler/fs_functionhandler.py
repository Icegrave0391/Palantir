from typing import List, Optional, Set
# from memory_profiler import profile
import claripy
import pyvex.expr
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.code_location import CodeLocation
from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.atoms import Register

from palantiri.structures.value_set.vs_state import ValueSetState
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues
from palantiri.structures.hooks.function_wrappers import function_plt_wrappers, get_hooked_plt_function
from ..value_domains.abstract_region import AbstractRegion, AbstractType
from .vs_util import ValueSetUtil

from ....analyses.function_summary import FunctionSummary

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

ALLOC_MAX_SZ = 8192


class FSFunctionHandler(FunctionHandler):
    """
    NOTE: experimental class, currently unused 
    """
    def __init__(self):
        self._analysis: 'FunctionSummary' = None
        self.project: Project = None
        self.util: ValueSetUtil = None

    def hook(self, analysis: 'FunctionSummary'):
        self._analysis = analysis
        self.project = analysis.project
        self.util = ValueSetUtil(self.project, self._analysis.interface, canonical_size=self._analysis._canonical_size)
        return self

#
# Local function call handler
#

    def handle_local_function(self, state: ValueSetState, function_address: int, call_stack: List,
                              maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: 'DepGraph',
                              src_ins_addr: Optional[int]=None,
                              codeloc: Optional['CodeLocation']=None,
                              callersite_block_addr: Optional[int]=None):
        """
        The key to create an inter-procedural analysis is to perform value-set analysis recursively, for the callee
        function. After the finish of callee function's VSA, caller should merge the result and update its own VSA,
        which is described as a text-book forward data flow analysis.
        """
        local_function = self.project.kb.functions.function(addr=function_address)
        log.info(f"Function Summary handling {local_function.name}")

        # 0. hook specical functions (like xmalloc -> malloc)
        if local_function.name in function_plt_wrappers:
            n_local_function = get_hooked_plt_function(self.project, local_function)
            log.info(f"Function {local_function.name} is hooked as {n_local_function.name}...")
            local_function = n_local_function

        # 1. get caller's ValueSetState at its call-site
        caller_parent_state = state
        caller_parent_fs = self._analysis
        # 2. get the function's all exit points and types, to create observation points
        function_endpoints = local_function.endpoints_with_type

        # return points are the most intuitive locations which mark the end of a function
        # transition points, which play a role as "tail-call optimization" to mark the end of function
        # (see paperNDSS'21)
        ret_points, call_points, trans_points = function_endpoints["return"], function_endpoints["call"],\
                                                function_endpoints["transition"]
        # 3. execute function's for plt functions
        if local_function.is_plt:
            func_child_fs = FunctionSummary(local_function, pal_proj=self._analysis.pal_project,
                                            project=self.project,
                                            interface=state.analysis.interface,
                                            function_handler=FSFunctionHandler(),
                                            init_state=caller_parent_state,
                                            do_taint_summary=True)

            trans_point = next(iter(trans_points))
            func_child_state = func_child_fs._output_node_map[trans_point.addr]
            # # pass the callee's state to the parent caller
            caller_parent_state = func_child_state
            caller_parent_state.analysis = state.analysis
            return True, caller_parent_state, func_child_fs.visited_blocks, func_child_fs.dep_graph

        else:
            # use the already reverse-analyzed 'leaf' functions to forward update
            result_dict = self._analysis.interface.function_summary_dict.get(local_function, None)
            if result_dict is None:
                log.error(f"Failed to get callee function: {local_function.name}'s summary. "
                          f"Skipping the callee function...")
                return False, state, state.analysis.visited_blocks, state.analysis.dep_graph

            # update
            if local_function.name == "re_node_set_init_copy":
                print("dbg")
            log.info(f"Successfully got callee function: {local_function.name}'s summary. "
                     f"Updating the current function...")
            caller_parent_state = state
            updated_state = state.analysis.update_from_function_summary(state, result_dict, codeloc)
            # handle return val
            if updated_state.arch.call_pushes_ret is True:
                # pop return address if necessary
                sp: VSMultiValues = updated_state.register_definitions.load(updated_state.arch.sp_offset,
                                                                            size=updated_state.arch.bytes)
                assert len(sp.values[0]) == 1
                sp_v = sp.one_value()
                if sp_v is not None and not updated_state.is_top(sp_v):
                    sp_addr = sp_v - updated_state.arch.stack_change

                    # update abs_region annotaion
                    stack_off = updated_state.get_stack_offset(sp_addr)
                    abs_region = AbstractRegion(AbstractType.Stack, stack_off)
                    sp_addr = updated_state.annotate_with_abs_regions(sp_addr, {abs_region})

                    atom = Register(updated_state.arch.sp_offset, updated_state.arch.bytes)
                    tag = ReturnValueTag(
                        function=local_function.addr,
                        metadata={'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                    )
                    updated_state.kill_and_add_definition(atom, codeloc,
                                                       VSMultiValues(offset_to_values={0: {sp_addr}}),
                                                       tags={tag},
                                                       )

            return True, updated_state, updated_state.analysis.visited_blocks, updated_state.analysis.dep_graph

#
# External function handlers
#
    def handle_malloc(self, state: ValueSetState, codeloc: CodeLocation):
        """
        void * malloc(size_t size);
        """
        malloc = self.project.kb.functions["malloc"]
        arg_atoms: List[Register] = self.util.generate_arg_atoms(malloc.calling_convention)

        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        # 1. add use of those argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. allocate
        heapaddr, ret_val = self.util.allocate(state, codeloc, malloc, rdi_valset)
        # 3. ret value
        self.util.handle_return_val(malloc, state, codeloc, ret_val)
        # update times
        self._update_interface_function_times(malloc)
        return True, state

    def handle_realloc(self, state: ValueSetState, codeloc: CodeLocation):
        """
        void * realloc(void *ptr, size_t size);
        """
        # we treat realloc as same as malloc()
        realloc = self.project.kb.functions["realloc"]
        arg_atoms: List[Register] = self.util.generate_arg_atoms(realloc.calling_convention)
        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        rsi_valset, rsi_defs = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of arguments
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. allocate
        heapaddr, ret_val = self.util.allocate(state, codeloc, realloc, rsi_valset)
        # 3. handle ret value
        self.util.handle_return_val(realloc, state, codeloc, ret_val)
        # update times
        self._update_interface_function_times(realloc)
        return True, state

    def handle_calloc(self, state: ValueSetState, codeloc: CodeLocation):
        """void * calloc(size_t nmemb, size_t size);"""
        calloc = self.project.kb.functions["calloc"]
        arg_atoms: List[Register] = self.util.generate_arg_atoms(calloc.calling_convention)
        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        rsi_valset, rsi_defs = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of arguments
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. allocate
        heapaddr, ret_val = self.util.allocate(state, codeloc, calloc, rsi_valset, rdi_valset)
        # 3. handle ret value
        self.util.handle_return_val(calloc, state, codeloc, ret_val)
        # update times
        self._update_interface_function_times(calloc)
        return True, state

    def handle_free(self, state: ValueSetState, codeloc: CodeLocation):
        """
        void free(void * ptr);
        """
        free = self.project.kb.functions["free"]
        arg_atoms: List[Register] = self.util.generate_arg_atoms(free.calling_convention)
        # 1. add use
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. set rdi value as top
        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        rdi_freed_valset = VSMultiValues(offset_to_values={0: {claripy.BVS("TOP", 64, explicit_name=True)}})
        state.kill_and_add_definition(arg_atoms[0], codeloc, rdi_freed_valset)
        # 3. ret
        self.util.handle_return_val(free, state, codeloc, None, set_ret_val=False)
        # update items
        self._update_interface_function_times(free)
        return True, state

    def handle_memcpy(self, state: ValueSetState, codeloc: CodeLocation):
        """void * memcpy(void * dest, const void * src, size_t n);"""
        # FIXME: DBG
        memcpy = self.project.kb.functions["memcpy"]
        cc = memcpy.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        rsi_valset, rsi_defs = self.util.get_register_vs_and_def(arg_atoms[1], state)
        rdx_valset, rdx_defs = self.util.get_register_vs_and_def(arg_atoms[2], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. get src memory values
        src_vs = self.util.load_memory_regions(state, codeloc, rsi_valset, rdx_valset)
        # 2. store dst memory regions
        addrs = next(iter(rdi_valset.values.values()))
        size = self.util.canonical_size
        state.analysis._engine._store_core(addrs, size, src_vs, endness=state.arch.memory_endness)
        # 3. handle return value
        self.util.handle_return_val(memcpy, state, codeloc, rdi_valset)
        # update times
        self._update_interface_function_times(memcpy)
        return True, state

    def _add_regsiters_use(self, state: ValueSetState, codeloc: CodeLocation, args: List[Register]):
        for arg_atom in args:
            state.add_use(arg_atom, codeloc)

    def _update_interface_function_times(self, func):
        self._analysis.interface._plt_function_times_map[func] += 1

    def handle_external_function_fallback(self, state: ValueSetState, codeloc: CodeLocation, func_name: str):
        """
        a general handle for all external functions, which are not related to essential syscalls
        """
        log.debug(f"Using general external handler for function {func_name}...")
        func = self.project.kb.functions[func_name]
        arg_atoms = self.util.generate_arg_atoms(func.calling_convention)
        # 1. add use of args
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. handle return value
        self.util.handle_return_val(func, state, codeloc, values=None)
        # 3. update
        self._update_interface_function_times(func)
        return True, state

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
