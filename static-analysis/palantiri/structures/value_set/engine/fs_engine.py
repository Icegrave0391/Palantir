
from itertools import chain
from typing import Optional, Iterable, Set, Union, TYPE_CHECKING, Tuple, Any
import logging
import re

import pyvex
import claripy

from misc.debugger import dbgLog
from palantiri.structures.value_set.vs_state import ValueSetState
from ...value_set.simmemory.vs_multivalues import VSMultiValues
from ...value_set import update_vals_taint_from_defs
from ...utils import get_taint_tags, update_vals_with_taint_tags, resize_bvs, simplify_ast
from ...value_set import simplify_vs, DEFAULT_ALLOCA_SZ, update_regions_with_offset_and_op
from ...value_set import abstract_to_register
from ..value_domains.abstract_region import AbstractRegion, AbstractType, AbsRegionAnnotation
from ..taint import TaintType
from ..value_domains.taint_logic import TaintTag

import archinfo
from angr.analyses.reaching_definitions import engine_vex
from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from angr.engines.vex.claripy.datalayer import value as claripy_value
from angr.engines.vex.claripy.irop import operations as vex_operations
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg, SimCC
from angr.utils.constants import DEFAULT_STATEMENT
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, ReturnValueTag, Tag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

from palantiri.structures.value_set.engine.vs_engine import SimEngineVSVEX

if TYPE_CHECKING:
    from angr.knowledge_plugins import FunctionManager
    from ....analyses.function_summary import FunctionSummary

l = logging.getLogger(name=__name__)

class SimEngineFSVEX(
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

        self._process_Stmt(whitelist=whitelist)

        self.stmt_idx = None
        self.ins_addr = None

    # @profile(stream=open('/tmp/profile_processblkend.log', 'w+'))
    def _process_block_end(self):
        self.stmt_idx = DEFAULT_STATEMENT
        _analysis = self.state.analysis
        if self.block.vex.jumpkind == "Ijk_Call":
            # it has to be a function
            addr = self._expr(self.block.vex.next)
            self._handle_function(addr)

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
                        self._handle_function(addr)
                else:
                    # jmp
                    # normalize splitted block
                    if not self.block.capstone.insns[-1].mnemonic.startswith("j"):
                        self.state._should_standardize = True
            else:
                # we only handle tail calls, rather than j to the .cold functions
                # we treat conditional jumps such as jz js are to .cold functions
                if self.block.capstone.insns[-1].mnemonic.find("jmp") >= 0:
                    self._handle_function(addr)
                pass

    #
    # VEX expression handlers
    #
    def _handle_Get(self, expr: pyvex.IRExpr.Get) -> VSMultiValues:

        reg_offset: int = expr.offset
        bits: int = expr.result_size(self.tyenv)
        size: int = bits // self.arch.byte_width

        reg_atom = Register(reg_offset, size)
        try:
            values: VSMultiValues = self.state.register_definitions.load(reg_offset, size=size)
            values = self._annotate_values_with_taint(values, TaintType.REG, reg_offset, size)
        except SimMemoryMissingError:
            # sign a symbolic value for the atom
            top = self.state.top(size * self.arch.byte_width, reg_atom)
            # annotate it (with definition and symregion)
            top = self.state.annotate_with_def(top, Definition(reg_atom, ExternalCodeLocation()))
            reg_name = abstract_to_register(reg_atom.reg_offset, reg_atom.size, self.project)
            abs_region = AbstractRegion(AbstractType.Symbolic, 0, reg_name)
            top = self.state.annotate_with_abs_regions(top, {abs_region})
            values = VSMultiValues({0: {top}})
            values = self._annotate_values_with_taint(values, TaintType.REG, reg_offset, size)
            # FunctionSummary: we do not write it back to registers
        self.state.add_use(reg_atom, self._codeloc())
        return values

    def _load_core(self, addrs: Iterable[claripy.ast.Base], size: int, endness: str) -> VSMultiValues:
        """
        In function summary, when there is a Memory load miss, we just return top value and do not write back to the
        memory.
        """
        result: Optional[VSMultiValues] = None
        for addr in addrs:
            # handle symbolic region, now we treat both symbolic normal address and symbolic stack address as
            # symbolic. i.e. both [rax + d] and [stack_base + rax + d] ...
            addr_regions = self.state.extract_abs_regions(addr)

            if not addr_regions:  # Abs region cannot be determined by value, load symbolic...
                if addr.op == "BVV":
                    l.info(f"LoadMem address invalid (ignored), ins_addr = {hex(self.ins_addr)}, invalid_addr: {addr}")
                else:
                    l.info(f"LoadMem address invalid (ignored), ins_addr = {hex(self.ins_addr)}, invalid_addr: {addr}")
                continue

            for load_region in addr_regions:
                l.debug(f'LoadMem. ins_addr = {hex(self.ins_addr)}, sym_var: {addr}, AbsRegion: {load_region}.')

                if load_region.type == AbstractType.Stack: # load from stack
                    stack_offset = load_region.offset
                    if stack_offset is not None:
                        memory_location = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size, endness=endness)
                        # concrete stack offset e.g. stack_base + 0x20, load data from StackDefinitions
                        stack_addr = self.state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                        try:
                            vs: VSMultiValues = self.state.stack_definitions.load(stack_addr, size=size,
                                                                                  endness=endness)
                            vs = self._simplify_valueset(vs)
                            # annotate the value with taint tags
                            vs = self._annotate_values_with_taint(vs, TaintType.STACK, stack_offset, size)
                        except SimMemoryMissingError:
                            # FunctionSummary: just return top, and do not write back
                            sym_cont = self.state.top(bits=size * self.arch.byte_width)
                            # annotation
                            symbol_content = self.state.annotate_with_def(sym_cont, Definition(memory_location,
                                                                                               self._codeloc()))
                            vs = VSMultiValues({0: {symbol_content}})
                            vs = self._annotate_values_with_taint(vs, TaintType.STACK, stack_offset, size)
                        self.state.add_use(memory_location, self._codeloc())
                        result = result.merge(vs) if result is not None else vs

                elif load_region.type == AbstractType.Heap: # Load data from the heap
                    heap_offset = load_region.offset
                    memory_location = MemoryLocation(HeapAddress(heap_offset), size, endness=endness)
                    try:
                        vs: VSMultiValues = self.state.heap_definitions.load(heap_offset, size=size, endness=endness)
                        vs = self._simplify_valueset(vs)
                        vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)
                    except SimMemoryMissingError:
                        sym_cont = self.state.top(bits=size * self.arch.byte_width)
                        # annotation
                        symbol_content = self.state.annotate_with_def(sym_cont, Definition(memory_location,
                                                                                           ExternalCodeLocation()))
                        vs = VSMultiValues({0: {symbol_content}})
                        vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)
                    vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)

                    memory_location = MemoryLocation(HeapAddress(heap_offset), size, endness=endness)
                    self.state.add_use(memory_location, self._codeloc())

                    result = result.merge(vs) if result is not None else vs

                elif load_region.type == AbstractType.Global: # Load data from global
                    addr_v = load_region.offset
                    # Load data from a global region
                    try:
                        vs: VSMultiValues = self.state.memory_definitions.load(addr_v, size=size, endness=endness)
                        vs = self._simplify_valueset(vs)
                        vs = self._annotate_values_with_taint(vs, TaintType.GLB, addr_v, size)
                    except SimMemoryMissingError:
                        # try to load it from the static memory backer
                        # TODO: Is this still required?
                        # TODO: Hanle the backend miss, we need a strategy
                        try:
                            vs = VSMultiValues(offset_to_values={0: {
                                claripy.BVV(
                                    self.project.loader.memory.unpack_word(addr_v, size=size),
                                    size * self.arch.byte_width
                                )}})
                            vs = self._annotate_valueset_with_proper_region(vs)
                            vs = self._annotate_values_with_taint(vs, TaintType.GLB, addr_v, size)
                        except KeyError:
                            vs = VSMultiValues(offset_to_values={0: {
                                self.state.top(size * self.project.arch.byte_width)
                            }})
                            vs = self._annotate_values_with_taint(vs, TaintType.GLB, addr_v, size)

                    result = result.merge(vs) if result is not None else vs
                    # FIXME: _add_memory_use() iterates over the same loop
                    memory_location = MemoryLocation(addr_v, size, endness=endness)
                    self.state.add_use(memory_location, self._codeloc())

                else:  # symbolic region
                    symaddr: str = load_region.symbol_address()
                    l.debug(f'LoadMem address symbolic, ins_addr = {hex(self.ins_addr)}, symvar: {addr}, symaddr: '
                            f'{symaddr}')
                    # load from the symbolic memory living definitions
                    try:
                        vs: VSMultiValues = self.state.symbolic_definitions.load(symaddr, size, endness)
                        vs = self._simplify_valueset(vs)
                        vs = self._annotate_values_with_taint(vs, TaintType.SYM, symaddr, size)
                    except SimMemoryMissingError:
                        sym_cont = self.state.top(bits=size * self.arch.byte_width)
                        # annotation
                        symaddr_bv = claripy.BVS(symaddr, self.arch.bits, explicit_name=True)
                        symaddr_bv = self.state.annotate_with_abs_regions(symaddr_bv, {load_region})
                        mem_atom = MemoryLocation(symaddr_bv, size)
                        sym_cont = self.state.annotate_with_def(sym_cont, Definition(mem_atom, self._codeloc()))
                        # annotate the value with taint tags
                        vs = VSMultiValues({0: {sym_cont}})
                        vs = self._annotate_values_with_taint(vs, TaintType.SYM, symaddr, size)
                    # get result
                    result = result.merge(vs) if result is not None else vs

        if result is None:
            result = VSMultiValues(offset_to_values={0: {self.state.top(size * self.arch.byte_width)}})
        return result

    def _handle_Put(self, stmt):
        super(SimEngineFSVEX, self)._handle_Put(stmt)
        # update side effect
        reg_offset: int = stmt.offset
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size)
        self.state.analysis.update_side_effect_set(
            self.state.analysis.reg_side_effect_set,
            reg.reg_offset,
            reg.size
        )

    def _store_core(self, addr: Iterable[Union[int,HeapAddress,SpOffset]], size: int, data: VSMultiValues,
                    data_old: Optional[VSMultiValues]=None, endness=None):
        if data_old is not None:
            data = data.merge(data_old)

        for a in addr:
            regions = self.state.extract_abs_regions(a)
            if not regions:
                l.debug(f'StoreMem address invalid (ignored), ins_addr = {hex(self.ins_addr)}, sym_var: {a}')
                # TODO: a policy to handle such invalid address
                continue

            for store_region in regions:
                l.debug(f'StoreMem, ins_addr = {hex(self.ins_addr)}, sym_val: {a}, region: {store_region}')
                if store_region.type == AbstractType.Global:
                    atom = MemoryLocation(store_region.offset, size)
                    taint_type, offset = TaintType.GLB, store_region.offset
                    tags: Optional[Set[Tag]] = None
                    # update side effect
                    self.state.analysis.update_side_effect_set(
                        self.state.analysis.global_side_effect_set,
                        store_region.offset,
                        size
                    )
                elif store_region.type == AbstractType.Stack:  # store to stack address
                    stack_offset = store_region.offset
                    taint_type, offset = TaintType.STACK, stack_offset
                    atom = MemoryLocation(SpOffset(self.arch.bits, stack_offset), size)
                    function_address = (
                        self.project.kb
                            .cfgs.get_most_accurate()
                            .get_all_nodes(self._codeloc().ins_addr, anyaddr=True)[0]
                            .function_address
                    )
                    tags = {LocalVariableTag(
                        function=function_address,
                        metadata={'tagged_by': 'SimEngineVS._store_core'}
                    )}
                    # update side effect
                    self.state.analysis.update_side_effect_set(
                        self.state.analysis.stack_side_effect_set,
                        stack_offset,
                        size
                    )

                elif store_region.type == AbstractType.Heap:   # store to heap address
                    heap_offset = store_region.offset
                    taint_type, offset = TaintType.HEAP, heap_offset
                    atom = MemoryLocation(HeapAddress(heap_offset), size)
                    tags = None
                    # update side effect
                    self.state.analysis.update_side_effect_set(
                        self.state.analysis.heap_side_effect_set,
                        heap_offset,
                        size
                    )
                else:  # store to symbolic address
                    store_size = size if size >= self.arch.bytes else self.arch.bytes # the unit size is 8-bytes
                    symaddr = store_region.symbol_address()
                    # create a symbol memory location atom to store
                    symaddr_bv = claripy.BVS(symaddr, self.arch.bits, explicit_name=True)
                    symaddr_bv = self.state.annotate_with_abs_regions(symaddr_bv, {store_region})
                    atom = MemoryLocation(symaddr_bv, store_size)
                    tags = None
                    taint_type, offset = TaintType.SYM, symaddr
                    # update side effect
                    self.state.analysis.sym_side_effect_set.add((symaddr, size))
                    self.state.analysis.update_side_effect_set(
                        self.state.analysis.sym_side_effect_set,
                        symaddr,
                        size
                    )
                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                taint_tags = get_taint_tags(self.state, [data])
                data = self._annotate_values_with_taint(data, taint_type, offset, size, store_taint_set=taint_tags)
                self.state.kill_and_add_definition(atom, self._codeloc(), data, tags=tags, endness=endness)

    def _handle_Conversion(self, expr):
        simop = vex_operations[expr.op]
        bits = int(simop.op_attrs['to_size'])
        arg_0 = self._expr(expr.args[0])

        from_signed = simop.op_attrs["from_signed"]
        # if there are multiple values with only one offset, we apply conversion to each one of them
        # otherwise, we return a TOP
        if len(arg_0.values) == 1:
            # extension, extract, or doing nothing
            # data = set()
            r = VSMultiValues()
            for v in next(iter(arg_0.values.values())):
                # in fs_engine, we reserve the symbol
                if self.state.is_symbolic(v):
                    nv = resize_bvs(v, to_size=bits)
                    r.add_value(offset=0, value=nv)
                    continue

                if bits > v.size():
                    # choose sign extend or zero extend from the source value
                    if from_signed == "S":
                        res_val = simplify_ast(v.sign_extend(bits - v.size()))
                    else:
                        res_val = simplify_ast(v.zero_extend(bits - v.size()))
                    res_val = self._annotate_value_with_proper_region(res_val)
                    r.add_value(offset=0, value=res_val)
                else:
                    # extract HI or LO bits from the source value
                    if simop.op_attrs["from_side"] and "HI" in simop.op_attrs["from_side"]:
                        res_val = simplify_ast(v[v.size() - 1:v.size() - bits])
                    else:
                        res_val = simplify_ast(v[bits - 1:0])
                    res_val = self._annotate_value_with_proper_region(res_val)
                    r.add_value(offset=0, value=res_val)
        else:
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, arg_0)
        # downsize the taint tags, for operations like 64to32
        # if bits < arg_0.one_value().size():
        #     for tag in taint_tags:
        #         tag.metadata["tagged_sz"] = bits // self.arch.byte_width

        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r
    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: Optional[VSMultiValues], **kwargs):
        # handle function
        skip_cc = self._handle_function_core(func_addr, **kwargs)
        if not skip_cc:
            self._handle_function_cc(func_addr)

    def _handle_function_core(self, func_addr: Optional[VSMultiValues],
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
                )
                state: ValueSetState
                self.state = state
            else:
                # l.warning('Please implement the unknown function handler with your own logic.')
                pass
            return False

        func_addr_v = func_addr.one_value()

        if func_addr_v is None or self.state.is_top(func_addr_v):
            # probably an indirect call
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                _, state = getattr(self._function_handler, handler_name)(self.state, src_codeloc=self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return False

        if not func_addr_v.concrete or func_addr_v._model_concrete.value not in self.project.kb.functions.keys():
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state,
                                                                                    src_codeloc=self._codeloc())
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
        if not self.state.analysis.interface.interproc_manager.handle_inter_procedure(caller, callee, None,
                                                                                      self.state):
            return False

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
                                                                                    src_codeloc=self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
        skip_cc = executed_rda

        return skip_cc

    def _handle_function_cc(self, func_addr: Optional[VSMultiValues]):
        _cc = None
        func_addr_int: Optional[Union[int, Undefined]] = None
        if func_addr is not None and self.functions is not None:
            func_addr_v = func_addr.one_value()
            if func_addr_v is not None and func_addr_v.concrete:
                try:
                    func_addr_int = func_addr_v._model_concrete.value
                    if self.functions.contains_addr(func_addr_int):
                        _cc = self.functions[func_addr_int].calling_convention
                        l.info(f"Function handler not implemented specified handler for {self.functions[func_addr_int].name}")
                except AttributeError:
                    _cc = None

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
                    metadata={'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                )
                self.state.kill_and_add_definition(
                    atom,
                    self._codeloc(),
                    VSMultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}),
                    tags={tag},
                )

        if cc.CALLER_SAVED_REGS is not None:
            # TODO() correct this !!!
            pass

        if self.arch.call_pushes_ret is True:
            # pop return address if necessary
            sp: VSMultiValues = self.state.register_definitions.load(self.arch.sp_offset, size=self.arch.bytes)
            assert len(sp.values[0]) == 1
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
                    metadata={'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                )
                self.state.kill_and_add_definition(atom, self._codeloc(),
                                                   VSMultiValues(offset_to_values={0: {sp_addr}}),
                                                   tags={tag},
                                                   )

    #
    # VEX statement handlers
    #