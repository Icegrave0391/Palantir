from typing import Optional, TYPE_CHECKING, Union
import logging
import claripy
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues
from misc.debugger import debug_print_log

from palantiri.structures.value_set.vs_state import ValueSetState
from ..value_domains.abstract_region import AbstractRegion, AbstractType

from angr.errors import SimEngineError
import archinfo
from capstone import *
from angr.utils.constants import DEFAULT_STATEMENT
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.engines.light import SpOffset
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg, SimCC


from palantiri.structures.value_set.engine.vs_engine import SimEngineVSVEX

if TYPE_CHECKING:
    from angr.knowledge_plugins import FunctionManager
    from ....analyses.binary_summary import BinarySummary

l = logging.getLogger(name=__name__)

class SimEngineBSVEX(
    SimEngineVSVEX,
):  # pylint:disable=abstract-method
    """
    Implements the VEX execution engine for reaching definition analysis.
    """

    def __init__(self, project, call_stack, maximum_local_call_depth, functions=None,
                 function_handler=None):
        super().__init__(project, call_stack, maximum_local_call_depth, functions, function_handler)
        self.project = project
        self._call_stack = call_stack
        self._maximum_local_call_depth = maximum_local_call_depth
        self.functions: Optional['FunctionManager'] = functions
        self._function_handler = function_handler
        self._visited_blocks = None
        self._dep_graph = None

        self.state: ValueSetState

    def process(self, state, *args, **kwargs):
        self._dep_graph = kwargs.pop('dep_graph', None)
        self._visited_blocks = kwargs.pop('visited_blocks', None)

        self._state_initial_sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes).one_value()
        # we are using a completely different state. Therefore, we directly call our _process() method before
        # SimEngine becomes flexible enough.
        try:
            self._process(
                state,
                None,
                block=kwargs.pop('block', None),
            )
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e
            l.error(e)
        return self.state, self._visited_blocks, self._dep_graph

    def _process(self, state, successors, *args, block, whitelist=None, **kwargs):  # pylint:disable=arguments-differ

        # initialize local variables
        self.tmps = {}
        self.block = block
        self.state: ValueSetState = state

        if state is not None:
            self.arch: archinfo.Arch = state.arch
            self.state._block_addr = block.addr
            self.state._block_size = block.size

        self.tyenv = block.vex.tyenv

        self._process_block_start()
        # try to guess simplest block condition, like test rax, rax; jz xxxx
        self._block_test_condition_update()

        self._process_Stmt(whitelist=whitelist)

        self.stmt_idx = None
        self.ins_addr = None

    def _process_block_start(self):
        # FIXME: hard-code for sendmail 
        # to ensure the SM_FILE_T * is allocated
        if self.block.addr == 0x47b83a:
            _, heap_pointer_val = self._function_handler.util.allocate(
                self.state, self._codeloc(), self.state.analysis._subject.content, 
                size_vals=VSMultiValues(offset_to_values={0: {claripy.BVV(0x200, self.arch.bits)}})
                )
            rbx_offset, rbx_sz = self.arch.registers['rbx']
            rbx_atom = Register(rbx_offset, rbx_sz)
            self.state.kill_and_add_definition(rbx_atom, self._codeloc(), data=heap_pointer_val)
        pass

    # @profile(stream=open('/tmp/profile_processblkend.log', 'w+'))
    def _process_block_end(self):
        self.stmt_idx = DEFAULT_STATEMENT
        _analysis = self.state.analysis
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            addr = self._expr(self.block.vex.next)
            self._handle_function(addr, ijk_call=True)

        elif self.block.vex.jumpkind == "Ijk_Boring":
            # test if the target addr is a function or not
            addr = self._expr(self.block.vex.next)
            addr_v = addr.one_value()
            if addr_v is not None and addr_v.concrete:
                addr_int = addr_v._model_concrete.value
                if addr_int in self.functions:
                    # yes it's a jump to a function
                    # we only handle tail calls, rather than j to the .cold functions
                    # we treat conditional jumps such as jz js are to .cold functions
                    if self.block.capstone.insns[-1].mnemonic.find("jmp") >= 0:
                        self._handle_function(addr, ijk_call=False)
                else:
                    # jmp
                    # normalize splitted block
                    if not self.block.capstone.insns[-1].mnemonic.startswith("j"):
                        self.state._should_standardize = True
            else:
                # yes it's an indirect jump to a function
                # we only handle tail calls, rather than j to the .cold functions
                # we treat conditional jumps such as jz js are to .cold functions
                if self.block.capstone.insns[-1].mnemonic.find("jmp") >= 0:
                    self._handle_function(addr, ijk_call=False)
                pass

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: Optional[MultiValues], **kwargs):
        # TODO(): refine the logic at the BinarySummary, not here (de-correlate)
        func_addr_v = func_addr.one_value()
        analysis: 'BinarySummary' = self.state.analysis

        caller = analysis._subject.content
        # determine whether is a direct call
        try:
            callee = analysis.project.kb.functions[func_addr_v._model_concrete.value] # direct call
        except:
            callee = None  # indirect call
        if len(func_addr.values[0]) > 1:  # Also a non-deterministic indirect call
            callee = None

        ### (x) update states for non plt functions callees (both direct and indirect), before actually handle the target
        # fixed: update for both non plt callees and plt callees

        if callee is None or (not caller.is_plt and not analysis.interface.function_summary_dict)\
                or (not caller.is_plt and callee not in analysis.interface.function_summary_dict):
            analysis._update_output_state(self.block.addr, self.state, aftercalled=False)

        # handle function
        skip_cc = self._handle_function_core(func_addr, **kwargs)
        if not skip_cc:
            self._handle_function_cc(func_addr, **kwargs)

    def _handle_function_core(self, func_addr: Optional[MultiValues],
                              **kwargs) -> bool:  # pylint:disable=unused-argument

        if self._call_stack is not None and len(self._call_stack) + 1 > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return False

        if func_addr is None or not len(func_addr.values[0]):
            l.warning('Invalid type %s for IP.', type(func_addr).__name__)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(
                    self.state,
                    src_codeloc=self._codeloc(),
                    **kwargs
                )
                state: ValueSetState
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return False

        func_addr_v = func_addr.one_value()

        if func_addr_v is None or self.state.is_top(func_addr_v):
            # probably an indirect call
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                _, state = getattr(self._function_handler, handler_name)(self.state, src_codeloc=self._codeloc(),
                                                                         **kwargs)
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return False

        if not func_addr_v.concrete or func_addr_v._model_concrete.value not in self.project.kb.functions.keys():
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state,
                                                                                    src_codeloc=self._codeloc(),
                                                                                    **kwargs)
                state: ValueSetState
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
            return False

        #
        # Direct calls
        #
        func_addr_int: int = func_addr_v._model_concrete.value
        func = self.project.kb.functions[func_addr_int]

        # use inter-proc adaptor to guide inter-procedural analysis
        caller, callee = self.state.analysis._subject.content, func
        call_context = tuple(self.state.analysis._call_stack + [self.block.addr])

        if not self.state.analysis.interface.interproc_manager.handle_inter_procedure(caller, callee, call_context,
                                                                                      self.state):
            return False

        # determine whether should activate loop revisit mode
        elif callee in self.state.analysis.interface.interproc_manager.sysread_slice_functions and \
                self.state.analysis.interface.loop_revisit_mode:
            if self.state.analysis._subject.content.name == "main" and self.block.addr != 0x4045ed:
                pass
            # get the activate node
            else:
                self.state.analysis.revisit_activate_node = self.state.analysis._subject.get_function_node(self.block.addr)

        # direct calls
        ext_func_name = None
        if not self.project.loader.main_object.contains_addr(func_addr_int):
            is_internal = False
            symbol = self.project.loader.find_symbol(func_addr_int)
            if symbol is not None:
                ext_func_name = symbol.name
        else:
            is_internal = True

        executed_rda = False
        if ext_func_name is not None:
            handler_name = 'handle_%s' % ext_func_name
            if hasattr(self._function_handler, handler_name):
                codeloc = CodeLocation(func_addr_int, 0, None, func_addr_int, context=self._context)
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state, codeloc)
                self.state = state
            else:
                l.warning('Please implement the external function handler for %s() with your own logic.',
                          ext_func_name)
                handler_name = 'handle_external_function_fallback'
                if hasattr(self._function_handler, handler_name):
                    executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc(),
                                                                                        ext_func_name)
                    self.state = state
        elif is_internal is True:
            handler_name = 'handle_local_function'
            if hasattr(self._function_handler, handler_name):
                codeloc = CodeLocation(func_addr_int, 0, None, func_addr_int, context=self._context)
                executed_rda, state, visited_blocks, dep_graph = getattr(self._function_handler, handler_name)(
                    self.state,
                    func_addr_int,
                    self._call_stack,
                    self._maximum_local_call_depth,
                    self._visited_blocks,
                    self._dep_graph,
                    src_ins_addr=self.ins_addr,
                    codeloc=codeloc,
                    callersite_block_addr=self.block.addr,
                    **kwargs,
                )
                if executed_rda:
                    # update everything
                    self.state = state
                    self._visited_blocks = visited_blocks
                    self._dep_graph = dep_graph
            else:
                # l.warning('Please implement the local function handler with your own logic.')
                pass
        else:
            l.warning('Could not find function name for external function at address %#x.', func_addr_int)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state,
                                                                                    src_codeloc=self._codeloc(),
                                                                                    **kwargs)
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
        skip_cc = executed_rda

        return skip_cc

    def _handle_function_cc(self, func_addr: Optional[MultiValues], **kwargs):
        ijk_call = kwargs.pop("ijk_call", True)

        if ijk_call:
            child_func_callstack = self.state.analysis._call_stack + [self.block.addr]
        else:
            child_func_callstack = self.state.analysis._call_stack

        _cc = None
        func_addr_int: Optional[Union[int, Undefined]] = None
        if func_addr is not None and self.functions is not None:
            func_addr_v = func_addr.one_value()
            if func_addr_v is not None and func_addr_v.concrete:
                try:
                    func_addr_int = func_addr_v._model_concrete.value
                    if self.functions.contains_addr(func_addr_int):
                        _cc = self.functions[func_addr_int].calling_convention
                        l.info(f"Using general cc handler to handle skipped function: {self.functions[func_addr_int].name}")
                except AttributeError:
                    _cc = None

        # dump as pruned function (only pruned direct call target will be dumped)
        if func_addr_int and len(func_addr.values[0]) == 1:
            self.state.analysis.interface.dump_pruned_function(child_func_callstack, func_addr_int)

        cc: SimCC = _cc or DEFAULT_CC.get(self.arch.name, None)(self.arch)

        # follow the calling convention and:
        # - add uses for arguments
        # - kill return value registers
        # - caller-saving registers
        if cc.args:
            code_loc = self._codeloc()
            for arg in cc.args:
                if isinstance(arg, SimRegArg):
                    reg_offset, reg_size = self.arch.registers[arg.reg_name]
                    atom = Register(reg_offset, reg_size)
                elif isinstance(arg, SimStackArg):
                    atom = MemoryLocation(SpOffset(self.arch.bits,
                                                   arg.stack_offset),
                                          arg.size * self.arch.byte_width)
                else:
                    raise TypeError("Unsupported argument type %s" % type(arg))
                self.state.add_use(atom, code_loc)
                self._tag_definitions_of_atom(atom, func_addr_int)

        if cc.RETURN_VAL is not None:
            if isinstance(cc.RETURN_VAL, SimRegArg):
                reg_offset, reg_size = self.arch.registers[cc.RETURN_VAL.reg_name]
                atom = Register(reg_offset, reg_size)
                tag = ReturnValueTag(
                    function=func_addr_int if isinstance(func_addr_int, int) else None,
                    metadata={'tagged_by': '_handle_function_cc'}
                )
                self.state.kill_and_add_definition(
                    atom,
                    self._codeloc(),
                    MultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}),
                    tags={tag},
                )

        if cc.CALLER_SAVED_REGS is not None:
            pass

        if self.arch.call_pushes_ret is True:
            # pop return address if necessary
            sp: MultiValues = self.state.register_definitions.load(self.arch.sp_offset, size=self.arch.bytes)
            # todo(): 
            # assert len(sp.values[0]) == 1
            if len(sp.values[0]) != 1: 
                debug_print_log(self.state.analysis.pal_project, message=\
                    f"Multiple SP values at _handle_function_cc for target func addr:{func_addr}.",
                    logger=l, min_vlevel=1)
            sp_v = sp.one_value()
            if sp_v is not None and not self.state.is_top(sp_v):
                sp_addr = sp_v - self.arch.stack_change

                # update abs_region annotaion
                stack_off = self.state.get_stack_offset(sp_addr)
                abs_region = AbstractRegion(AbstractType.Stack, stack_off)
                sp_addr = self.state.annotate_with_abs_regions(sp_addr, {abs_region})

                atom = Register(self.arch.sp_offset, self.arch.bytes)
                tag = ReturnValueTag(
                    function=func_addr_int,
                    metadata={'tagged_by': '_handle_function_cc'}
                )
                self.state.kill_and_add_definition(atom, self._codeloc(),
                                                   MultiValues(offset_to_values={0: {sp_addr}}),
                                                   tags={tag},
                                                   )

    #
    # condition
    #
    def _block_test_condition_update(self):
        insn_list = self.block.capstone.insns
        if len(insn_list) < 2:
            return
        cond_insn = insn_list[-2].insn
        if cond_insn.mnemonic != "test" or cond_insn.operands[0].type != CS_OP_REG or\
                cond_insn.operands[1].type != CS_OP_REG:
            return

        # test reg, reg;  get reg name
        reg_name = cond_insn.reg_name(cond_insn.operands[0].reg)
        reg_name_list = [reg_name]
        j_insn = insn_list[-1].insn

        to_addr = None
        if j_insn.mnemonic in ["je", "jz"]:
            if j_insn.operands[0].type == CS_OP_IMM:
                to_addr = j_insn.operands[0].imm
        else:
            to_addr = self.block.addr + self.block.size

        #
        if len(insn_list) >= 3:
            insn_before_test = insn_list[-3].insn
            if insn_before_test.mnemonic == "mov" and \
                insn_before_test.operands[0].type == CS_OP_REG and insn_before_test.operands[1].type == CS_OP_REG and \
                insn_before_test.reg_name( insn_before_test.operands[1].reg) == reg_name:
                reg_name_list.append( insn_before_test.reg_name(insn_before_test.operands[0].reg))

        self.state.analysis.block_testcond_constraint[(self.block.addr, tuple(reg_name_list))] = to_addr
