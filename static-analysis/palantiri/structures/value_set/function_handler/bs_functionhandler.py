from telnetlib import IP
from typing import List, Optional, Set
# from memory_profiler import profile
import claripy
import pyvex.expr
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.code_location import CodeLocation
from angr import Project
from angr.knowledge_plugins.functions import Function
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Register

from palantiri.structures.value_set.vs_state import ValueSetState
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues
from ....analyses.binary_summary import BinarySummary
from .vs_util import ValueSetUtil

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

ALLOC_MAX_SZ = 8192


class BSFunctionHandler(FunctionHandler):

    def __init__(self):
        self._analysis: BinarySummary = None
        self.project: Project = None
        self.util: ValueSetUtil = None

    def hook(self, analysis: BinarySummary):
        self._analysis: BinarySummary = analysis
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
                              callersite_block_addr: Optional[int]=None,
                              **kwargs):
        """
        The key to create an inter-procedural analysis is to perform value-set analysis recursively, for the callee
        function. After the finish of callee function's VSA, caller should merge the result and update its own VSA,
        which is described as a text-book forward data flow analysis.
        """
        ijk_call = kwargs.pop("ijk_call", True)
        local_function = self.project.kb.functions.function(addr=function_address)
        log.info(f"Binary Summary handling {local_function.name}")

        # # 0. hook specical functions (like xmalloc -> malloc)
        # if local_function.name in function_plt_wrappers:
        #     n_local_function = get_hooked_plt_function(self.project, local_function)
        #     log.info(f"Function {local_function.name} is hooked as {n_local_function.name}...")
        #     local_function = n_local_function

        # 1. get caller's ValueSetState at its call-site
        caller_parent_state = state
        caller_parent_bs = self._analysis

        # determine the whether the callee should be terminated due to loop call
        call_stack = state.analysis._call_stack
        cfg = state.analysis.pal_project.cfg_util.cfg
        call_stack_functions = list(map(lambda cs: cfg.model.get_any_node(cs).function_address, call_stack))
        if function_address in call_stack_functions:
            log.info(f"Local function {local_function.name} is dismissed due to loop calls.")
            return False, caller_parent_state, visited_blocks, dep_graph
        # 2. get the function's all exit points and types, to create observation points
        function_endpoints = local_function.endpoints_with_type

        # return points are the most intuitive locations which mark the end of a function
        # transition points, which play a role as "tail-call optimization" to mark the end of function
        # (see paperNDSS'21)
        ret_points, call_points, trans_points = function_endpoints["return"], function_endpoints["call"],\
                                                function_endpoints["transition"]
        # 3. execute function's ValueSetAnalyses
        if ijk_call:
            child_call_stack = caller_parent_bs._call_stack + [callersite_block_addr]
        else:
            child_call_stack = caller_parent_bs._call_stack
        func_child_bs = BinarySummary(function=local_function, pal_proj=self._analysis.pal_project,
                                      project=self.project,
                                      func_graph=local_function.graph, track_tmps=caller_parent_bs._track_tmps,
                                      function_handler=BSFunctionHandler(),
                                      init_state=caller_parent_state,
                                      dep_graph=caller_parent_bs.dep_graph,
                                      canonical_size=caller_parent_bs._canonical_size,
                                      max_iterations=caller_parent_bs._max_iterations,
                                      call_stack=child_call_stack,
                                      do_taint_summary=state.taint_summary is not None,
                                      interface=state.analysis.interface,
                                      immediate_update=state.analysis._immediate_update,
                                      auto_save=state.analysis._auto_save,
                                      max_symbol_reference_depth=caller_parent_bs.max_symbol_reference_depth
                                      )
        # 4. merge the callee function's final value set state, with all exit points
        # 4.1 determine the callee function type: normal function | @plt function | hooked function
        if local_function.info.get("hook", None):
            # hooked function, get the summary
            func_child_state = func_child_bs.get_block_summary(local_function.addr)
        elif local_function.is_plt:
            # example @plt function printf:
            # 0x4010f0:	endbr64
            # 0x4010f4:	bnd jmp	qword ptr [rip + 0x2ed5]  <== the function's transition point
            # 4.1.1 merge @plt function exit: only need to take away the transition point
            assert len(trans_points) == 1
            assert len(ret_points) == 0
            assert len(call_points) == 0
            trans_point = next(iter(trans_points))
            func_child_state = func_child_bs.get_block_summary(trans_point.addr)
        else:
            # 4.1.2 merge local function's multiple exit points
            ret_points, tail_ret_points = list(ret_points), list(trans_points)
            # handle tail calls
            # Filter all non 'jmp' tail calls (filter tail calls with 'js' or 'jz'). The observation is that non 'jmp'
            # calls are likely to be to .cold.n functions
            tail_ret_points_not_cold = []
            for node in tail_ret_points:
                if not self._is_cold_jmpoutnode(node):
                    tail_ret_points_not_cold.append(node)

            # merge them together
            final_ret_points = ret_points + tail_ret_points_not_cold
            # merge
            # the case that function does have return points
            if len(final_ret_points):
                if len(final_ret_points) > 1:
                    ret_states = list(map(lambda x: func_child_bs.get_block_summary(x.addr), ret_points[:]))
                    tail_states = list(map(
                        lambda x: func_child_bs.get_block_summary(x.addr, after_call=True),
                        tail_ret_points_not_cold[:])
                    )
                    if len(ret_states):
                        func_child_state, _ = ret_states[0].merge(*(ret_states[1:] + tail_states), update_taint_summary=
                                                                  self._analysis._propagate_taint_summary)
                    else:
                        func_child_state, _ = tail_states[0].merge(*tail_states[1:],
                                                                   update_taint_summary=self._analysis._propagate_taint_summary)
                else:
                    if len(ret_points):
                        func_child_state = func_child_bs.get_block_summary(ret_points[0].addr)
                    else:
                        func_child_state = func_child_bs.get_block_summary(tail_ret_points_not_cold[0].addr,
                                                                           after_call=True)

            # the case that the function is end up with call
            elif len(call_points):
                # TODO(): refine this, we treat all paths end up with call are to abort the program
                call_points = list(call_points)
                func_child_state = caller_parent_state
                func_child_state.abort = True
            else:
                func_child_state = caller_parent_state
        # pass the callee's state to the parent caller
        caller_parent_state = func_child_state
        caller_parent_state.analysis = state.analysis

        c_visited_blocks = func_child_bs.visited_blocks
        c_dep_graph = func_child_bs.dep_graph
        func_child_bs._output_node_map = None
        func_child_bs._input_node_map = None
        func_child_bs._aftercalled_node_map = None
        delattr(func_child_bs, "_output_node_map")
        del func_child_bs
        return True, caller_parent_state, c_visited_blocks, c_dep_graph

    def handle_unknown_call(self, state: ValueSetState, src_codeloc: CodeLocation, **kwargs):
        """
        Handle indirect call
        """
        ijk_call = kwargs.pop("ijk_call", True)
        caller_func = state.analysis._subject.content
        callsite = src_codeloc.block_addr
        try:
            targets = state.analysis.interface.interproc_manager.handle_indirect_call(caller_func, callsite)
        except KeyError:
            targets = []

        if ijk_call:
            child_call_stack = state.analysis._call_stack + [callsite]
        else:
            child_call_stack = state.analysis._call_stack

        for target_name in targets:
            target_func = self.project.kb.functions[target_name]
            target_addr = target_func.addr
            # dismiss loop calls
            cfg = state.analysis.pal_project.cfg_util.cfg
            call_stack = state.analysis._call_stack
            call_stack_functions = list(map(lambda cs: cfg.model.get_any_node(cs).function_address, call_stack))
            if target_addr in call_stack_functions:
                log.info(f"Indirect resolved target: {target_func.name} dismissed due to loop calls.")

                state.analysis.interface.dump_pruned_function(child_call_stack, target_addr)

                continue
            sub_analyze = BinarySummary(
                function=target_func, pal_proj=state.analysis.pal_project, project=state.analysis.project,
                interface=state.analysis.interface, function_handler=BSFunctionHandler(),
                init_state=state, call_stack=child_call_stack,
                dep_graph=state.analysis.dep_graph, canonical_size=state.analysis._canonical_size,
                do_taint_summary=state.analysis._do_taint_summary,
                immediate_update=state.analysis._immediate_update,
                auto_save=state.analysis._auto_save,
                max_symbol_reference_depth=state.analysis.max_symbol_reference_depth
            )
            # FIXME: for sendmail, we now hardcode to save development costs
            # actually we need to merge all indirect result states
            # this if condition could be commented
            if target_name in ["sm_bfopen", "sm_stdread"]:
            # if self.project.filename.basename.find("sendmail") > 0:
                state = self.get_child_analysis_retstate(sub_analyze)
        return True, state

#
# Hooked special handlers
#
    def handle_xxx_palloc(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """
        void * ngx_palloc_xxx(ngx_poot_t * pool, size_t size, xxx);
        (ignore the pool and just allocate)
        """
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:2])
        heapaddr, ret_val = self.util.allocate(state, codeloc, original_function, size_vals=rsi_valset)
        self.util.handle_return_val(original_function, state, codeloc, ret_val)
        return True, state

    def handle_sm_malloc_tagged(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """
        void * sm_malloc_tagged(size_t size, char * tag, int num, int group);
        """
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:2])
        headaddr, ret_val = self.util.allocate(state, codeloc, original_function, size_vals=rdi_valset)
        self.util.handle_return_val(original_function, state, codeloc, ret_val)
        return True, state

    def handle_sm_malloc_tagged_x(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """
        void * sm_malloc_tagged_x(size_t size, char * tag, int num, int group);
        """
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:2])
        headaddr, ret_val = self.util.allocate(state, codeloc, original_function, size_vals=rdi_valset)
        self.util.handle_return_val(original_function, state, codeloc, ret_val)
        return True, state

    def handle_ngx_printf(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """ngx_sprintf(u_char *buf, const char *fmt, ...)"""
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:2])
        self.util.handle_return_val(original_function, state, codeloc, rdi_valset)
        return True, state

    def handle_ngx_calloc(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """
        void * ngx_calloc(size_t size, xxx)
        """
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:2])
        heapaddr, ret_val = self.util.allocate(state, codeloc, original_function, size_vals=rdi_valset, data_val=0)
        self.util.handle_return_val(original_function, state, codeloc, ret_val)
        return True, state

    def handle_apr_bucket_alloc(self, state: ValueSetState, codeloc: CodeLocation, original_function: Function):
        """APU_DECLARE_NONSTD(void *) apr_bucket_alloc(apr_size_t size, 
                                            apr_bucket_alloc_t *list)"""
        arg_atoms: List[Register] = self.util.generate_arg_atoms(original_function.calling_convention,
                                                                 force_generate_atoms=True)
        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        self._add_regsiters_use(state, codeloc, arg_atoms[:1])
        heapaddr, ret_val = self.util.allocate(state, codeloc, original_function, size_vals=rdi_valset, data_val=0)
        self.util.handle_return_val(original_function, state, codeloc, ret_val)
        return True, state

#
# External function handlers
#
    def handle_malloc(self, state: ValueSetState, codeloc: CodeLocation, **kwargs):
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

    def handle_realloc(self, state: ValueSetState, codeloc: CodeLocation, **kwargs):
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

    def handle_calloc(self, state: ValueSetState, codeloc: CodeLocation, **kwargs):
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
        # if self.project.filename.find("nginx") < 0:
        #     src_vs = self.util.load_memory_regions(state, codeloc, rsi_valset, size_vals=rdx_valset)
        #     # 2. handle memory region
        #     self.util.handle_memory_definition(state, codeloc, rdi_valset, memcpy, content_valset=src_vs,
        #                                        size_valset=rdx_valset)
        #     # 3. handle return value
        #     self.util.handle_return_val(memcpy, state, codeloc, rdi_valset)
        # else:
        #     pass
        if self.project.filename.find("sendmail") >= 0:
            last_callsite = state.analysis._call_stack[-1]
            last_funcaddr = state.analysis.pal_project.cfg_util.cfg.model.get_any_node(last_callsite).function_address
            if state.analysis.project.kb.functions[last_funcaddr].name == "sm_bfwrite":
                src_vs = self.util.load_memory_regions(state, codeloc, rsi_valset, size_vals=rdx_valset)
                self.util.handle_memory_definition(state, codeloc, rdi_valset, memcpy, content_valset=src_vs,\
                    size_valset=rdx_valset)
                
        self.util.handle_return_val(memcpy, state, codeloc, rdi_valset)
        return True, state

    def handle_fgets(self, state: ValueSetState, codeloc: CodeLocation):
        """
        char * fgets(char * buffer,tmp_to_file=False int size, FILE * stream)
        """
        fgets = self.project.kb.functions["fgets"]
        cc = fgets.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        # 1. add use of those argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. add memory definition
        self.util.handle_memory_definition(state, codeloc, rdi_valset, fgets, content_valset=None)
        # 3. handle return reg
        self.util.handle_return_val(fgets, state, codeloc, rdi_valset)
        # update times
        self._update_interface_function_times(fgets)
        return True, state

    def handle_fread(self, state: ValueSetState, codeloc: CodeLocation):
        """size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream);"""
        func = self.project.kb.functions["fread"]
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rdi_valset, rdi_defs = self.util.get_register_vs_and_def(arg_atoms[0], state)
        # 1. add use of those argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. add memory definition
        self.util.handle_memory_definition(state, codeloc, rdi_valset, func, content_valset=None)
        import IPython; IPython.embed()
        # 3. handle return reg
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    def handle_read(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t read(int fd, void * buf, size_t count)"""
        read = self.project.kb.functions["read"]
        cc = read.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        
        # 2. create memory def
        self.util.handle_memory_definition(state, codeloc, rsi_valset, read, content_valset=None)
        # 3. ret val
        self.util.handle_return_val(read, state, codeloc, values=None)
        # _insert_debugpoint(state, "apr_file_read", rsi_valset)
        # update times
        self._update_interface_function_times(read)
        return True, state

    def handle_pread64(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t pread(int fd, void *buf, size_t count, off_t offset);"""
        func = self.project.kb.functions['pread64']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # create memory def
        self.util.handle_memory_definition(state, codeloc, rsi_valset, func, content_valset=None)
        # ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        self._update_interface_function_times(func)
        return True, state

    def handle_readv(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t readv(int filedes, const struct iovec *iov, int iovcnt);"""
        func = self.project.kb.functions['readv']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory def
        iovec_base_valset = self.util.load_memory_regions(state, codeloc, rsi_valset,
                                                          VSMultiValues({0:{claripy.BVV(state.arch.bytes, state.arch.bits)}}))
        self.util.handle_memory_definition(state, codeloc, iovec_base_valset, func, content_valset=None)
        # 3. ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    def handle_gnutls_record_recv(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t gnutls_record_recv(gnutls_session_t session, void * data, size_t sizeofdata);"""
        func = self.project.kb.functions['gnutls_record_recv']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc, force_generate_atoms=True)

        rsi_valset, rsi_defs = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory def
        self.util.handle_memory_definition(state, codeloc, rsi_valset, func, content_valset=None)
        # _insert_debugpoint(state, "wgnutls_read_timeout", rsi_valset) # 0x4366cc -> 436640
        # 3. ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    def handle_recv(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t recv(int sockfd, void *buf, size_t len, int flags);"""
        func = self.project.kb.functions['recv']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rsi_valset, rsi_defs = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory def
        self.util.handle_memory_definition(state, codeloc, rsi_valset, func, content_valset=None)
        # _insert_debugpoint(state, "Curl_recv_plain", rsi_valset)
        # 3. ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    def handle_abort(self, state: ValueSetState, codeloc: CodeLocation):
        """
        Mark the state to abort
        """
        abort = self.project.kb.functions["abort"]
        state.abort = True
        self.util.handle_return_val(abort, state, codeloc, values=None)
        return True, state

    def handle_connect(self, state: ValueSetState, codeloc: CodeLocation):
        """
        Mark the state to activate
        """
        connect = self.project.kb.functions["connect"]
        cc = connect.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 3. ret val
        self.util.handle_return_val(connect, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(connect)
        state.activate = True
        return True, state

    def handle_fputs(self, state: ValueSetState, codeloc: CodeLocation):
        log.info("ffffffffff")
        """int fputs(const char *str, FILE *stream)"""
        fputs = self.project.kb.functions["fputs"]
        cc = fputs.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory use
        self.util.handle_memory_use_for_syscall(state, codeloc, rdi_valset, fputs)
        # 3. ret val
        self.util.handle_return_val(fputs, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(fputs)
        return True, state

    def handle_write(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t write(int fd, const void *buf, size_t count);"""
        func = self.project.kb.functions['write']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)
        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory use
        # _insert_debugpoint(state, "write_data.part.0", rsi_valset)
        self.util.handle_memory_use_for_syscall(state, codeloc, rsi_valset, func)
        # 3. ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    def handle_fwrite(self, state: ValueSetState, codeloc: CodeLocation):
        """
        size_t fwrite(void * buffer, size_t size, size_t count, FILE * stream);
        """
        fwrite = self.project.kb.functions['fwrite']
        cc = fwrite.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)

        rdi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[0], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory use
        self.util.handle_memory_use_for_syscall(state, codeloc, rdi_valset, fwrite)
        # _insert_debugpoint(state, "tool_write_cb", rdi_valset)
        import IPython; IPython.embed()
        # 3. ret val
        self.util.handle_return_val(fwrite, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(fwrite)
        return True, state

    def handle_writev(self, state: ValueSetState, codeloc: CodeLocation):
        """ssize_t writev(int filedes, const struct iovec *iov, int iovcnt);"""
        func = self.project.kb.functions['writev']
        cc = func.calling_convention
        arg_atoms: List[Register] = self.util.generate_arg_atoms(cc)
        rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
        # 1. add use of argument registers
        self._add_regsiters_use(state, codeloc, arg_atoms)
        # 2. create memory use
        iov_base_valset = self.util.load_memory_regions(state, codeloc, region_vals=rsi_valset, size_vals=
                                                        VSMultiValues(offset_to_values={0: {claripy.BVV(8, state.arch.bits)}}))
        self.util.handle_memory_use_for_syscall(state, codeloc, iov_base_valset, func)
        # 3. ret val
        self.util.handle_return_val(func, state, codeloc, values=None)
        # update times
        self._update_interface_function_times(func)
        return True, state

    # def handle_apr_socket_sendv(self, state: ValueSetState, codeloc: CodeLocation):
    #     """apr_status_t	apr_socket_sendv (apr_socket_t *sock, const struct iovec *vec, apr_int32_t nvec, apr_size_t *len)"""
    #     func = self.project.kb.functions["apr_socket_sendv"]
    #     cc = func.calling_convention
    #     arg_atoms: List[Register] = self.util.generate_arg_atoms(cc, force_generate_atoms=True)
    #     rsi_valset, _ = self.util.get_register_vs_and_def(arg_atoms[1], state)
    #     # 1. add use of argument registers
    #     self._add_regsiters_use(state, codeloc, arg_atoms)
    #     # 2. create memory use
    #     iov_base_valset = self.util.load_memory_regions(state, codeloc, region_vals=rsi_valset, size_vals=
    #     VSMultiValues(offset_to_values={0: {claripy.BVV(8, state.arch.bits)}}))
    #     self.util.handle_memory_use_for_syscall(state, codeloc, iov_base_valset, func)
    #     # 3. ret val
    #     self.util.handle_return_val(func, state, codeloc, values=None)
    #     return True, state

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
        # determine the target 
        tar_func_addr = block.vex.next.con.value
        try:
            tar_func = self.project.kb.functions[tar_func_addr]
        except KeyError:
            # in case the function does not exists, just treat as cold function
            return True
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
    
    def get_child_analysis_retstate(self, func_child_bs: BinarySummary):
        """
        # TODO(): now this method is only used for updating indirect caller's result from
        # TODO(): the child analysis of its resolved callee
        """
        local_function = func_child_bs._subject.content

        function_endpoints = local_function.endpoints_with_type

        # return points are the most intuitive locations which mark the end of a function
        # transition points, which play a role as "tail-call optimization" to mark the end of function
        # (see paperNDSS'21)
        ret_points, call_points, trans_points = function_endpoints["return"], function_endpoints["call"],\
                                                function_endpoints["transition"]
        # if local_function.info.get("hook", None):
        #     # hooked function, get the summary
        #     func_child_state = func_child_bs.get_block_summary(local_function.addr)
        # elif local_function.is_plt:
        #     # example @plt function printf:
        #     # 0x4010f0:	endbr64
        #     # 0x4010f4:	bnd jmp	qword ptr [rip + 0x2ed5]  <== the function's transition point
        #     # 4.1.1 merge @plt function exit: only need to take away the transition point
        #     assert len(trans_points) == 1
        #     assert len(ret_points) == 0
        #     assert len(call_points) == 0
        #     trans_point = next(iter(trans_points))
        #     func_child_state = func_child_bs.get_block_summary(trans_point.addr)
        if local_function.is_plt or local_function.info.get("hook", None):
            raise TypeError(f"{local_function.name} is not a valid indirect callee for now.")
        else:
            # 4.1.2 merge local function's multiple exit points
            ret_points, tail_ret_points = list(ret_points), list(trans_points)
            # handle tail calls
            # Filter all non 'jmp' tail calls (filter tail calls with 'js' or 'jz'). The observation is that non 'jmp'
            # calls are likely to be to .cold.n functions
            tail_ret_points_not_cold = []
            for node in tail_ret_points:
                if not self._is_cold_jmpoutnode(node):
                    tail_ret_points_not_cold.append(node)

            # merge them together
            final_ret_points = ret_points + tail_ret_points_not_cold
            # merge
            # the case that function does have return points
            if len(final_ret_points):
                if len(final_ret_points) > 1:
                    ret_states = list(map(lambda x: func_child_bs.get_block_summary(x.addr), ret_points[:]))
                    tail_states = list(map(
                        lambda x: func_child_bs.get_block_summary(x.addr, after_call=True),
                        tail_ret_points_not_cold[:])
                    )
                    if len(ret_states):
                        func_child_state, _ = ret_states[0].merge(*(ret_states[1:] + tail_states), update_taint_summary=
                                                                  self._analysis._propagate_taint_summary)
                    else:
                        func_child_state, _ = tail_states[0].merge(*tail_states[1:],
                                                                   update_taint_summary=self._analysis._propagate_taint_summary)
                else:
                    if len(ret_points):
                        func_child_state = func_child_bs.get_block_summary(ret_points[0].addr)
                    else:
                        func_child_state = func_child_bs.get_block_summary(tail_ret_points_not_cold[0].addr,
                                                                           after_call=True)

            # the case that the function is end up with call
            elif len(call_points):
                # TODO(): refine this, we treat all paths end up with call are to abort the program
                call_points = list(call_points)
                func_child_state = None
                func_child_state.abort = True
            else:
                func_child_state = None
            return func_child_state
