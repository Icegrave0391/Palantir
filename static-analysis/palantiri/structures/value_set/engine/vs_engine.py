
from itertools import chain
from typing import Optional, Iterable, Set, Union, TYPE_CHECKING
import logging
import re

import pyvex
from capstone import *
import claripy

from misc.debugger import debug_print_log
from palantiri.structures.value_set.vs_state import ValueSetState
from ...value_set.simmemory.vs_multivalues import VSMultiValues
from ...utils import get_taint_tags, update_vals_with_taint_tags, get_abs_regions, simplify_ast, \
    update_vals_with_sem_constraints, get_sem_constraints, get_values_under_constraints
from ...value_set import simplify_vs, DEFAULT_ALLOCA_SZ, update_regions_with_offset_and_op
from ...utils.symbol_utils import bv_to_str
from ...value_set import abstract_to_register
from ..value_domains.abstract_region import AbstractRegion, AbstractType, AbsRegionAnnotation
from ..value_domains.semantic_record import SemanticConstraint, ConstraintType
from ..taint import TaintType
from ..value_domains.taint_logic import TaintTag

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin, SpOffset
from angr.engines.vex.claripy.datalayer import value as claripy_value
from angr.engines.vex.claripy.irop import operations as vex_operations
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg, SimCC
from angr.utils.constants import DEFAULT_STATEMENT
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ParameterTag, ReturnValueTag, Tag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

if TYPE_CHECKING:
    from angr.knowledge_plugins import FunctionManager

l = logging.getLogger(name=__name__)
l.setLevel(logging.INFO)

#others
# APPROXIMATE_LIMIT = 10
# sendmail
APPROXIMATE_LIMIT = 70

class SimEngineVSVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):  # pylint:disable=abstract-method
    """
    Implements the VEX execution engine for reaching definition analysis.
    """

    def __init__(self, project, call_stack, maximum_local_call_depth, functions=None,
                 function_handler=None):
        super().__init__()
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
                    self._handle_function(addr)

    #
    # Private methods
    #

    @staticmethod
    def _external_codeloc():
        return ExternalCodeLocation()

    #
    # VEX statement handlers
    #

    def _handle_Stmt(self, stmt):
        super()._handle_Stmt(stmt)

    def _handle_WrTmp(self, stmt: pyvex.IRStmt.WrTmp):

        data: VSMultiValues = self._expr(stmt.data)

        tmp_atom = Tmp(stmt.tmp, self.tyenv.sizeof(stmt.tmp) // self.arch.byte_width)
        self.tmps[stmt.tmp] = data
        # tags = get_taint_tags(self.state, [data])
        self.state.kill_and_add_definition(tmp_atom,
                                           self._codeloc(),
                                           data,
                                           # tags=tags
                                           )

    def _handle_WrTmpData(self, tmp: int, data):
        super()._handle_WrTmpData(tmp, data)
        # tags = get_taint_tags(self.state, [data])
        self.state.kill_and_add_definition(Tmp(tmp, self.tyenv.sizeof(tmp)),
                                           self._codeloc(),
                                           self.tmps[tmp],
                                           # tags=tags
                                           )

    # e.g. PUT(rsp) = t2, t2 might include multiple values
    # do extra handles for rsp
    def _handle_Put(self, stmt):
        # TODO(): alloca() handler
        reg_offset: int = stmt.offset
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size)
        data = self._expr(stmt.data)
        # this is hook for rsp, to ensure its value won't be symbolic
        if reg_offset == self.arch.sp_offset:
            data = self._handle_put_sp(stmt, data)

        # special handling for references to heap or stack variables
        if len(data.values) == 1:
            for d in next(iter(data.values.values())):
                if self.state.is_heap_address(d):
                    heap_offset = self.state.get_heap_offset(d)
                    if heap_offset is not None:
                        self.state.add_use(MemoryLocation(HeapAddress(heap_offset), 1), self._codeloc())
                elif self.state.is_stack_address(d) and not self.state.is_symbolic(d):
                    stack_offset = self.state.get_stack_offset(d)
                    if stack_offset is not None:
                        self.state.add_use(MemoryLocation(SpOffset(self.arch.bits, stack_offset), 1), self._codeloc())

        tags = get_taint_tags(self.state, [data])
        # store those taint logic tags
        data = self._annotate_values_with_taint(data, TaintType.REG, reg_offset, size, store_taint_set=tags)
        self.state.kill_and_add_definition(reg, self._codeloc(), data)

    def _handle_put_sp(self, stmt, data: VSMultiValues):
        """
        When sp is corrupted by symbolic variables (it happens at __builtin_alloca()), we should assign a stable
        constant size rather than a symbolic size to rsp
        """
        tmp = stmt.data.tmp
        # We believe that the case of multiple SP is due to alloca() statement.
        # We track the alloca-ed stack pointer.
        multi_val_occurred = False
        if len(data.values[0]) != 1:
            l.warning(f"Multiple SP {data.values[0]} occurred.")
            multi_val_occurred = True

        sp_val = data.min_sp_value()
        if not self.state.is_symbolic(sp_val):
            if multi_val_occurred:
                return VSMultiValues(offset_to_values={0: {sp_val}})
            return data
        l.debug(f"Symbolic SP ({sp_val}) assignment occurred at {self._codeloc()}.")
        def get_tmp_definition_idx(tmp, stmt_idx):
            # 1. find the definition of binary operations for sp
            tmp_defined_idx = -1
            for i in range(stmt_idx, 0, -1):
                history_stmt = self.block.vex.statements[i]
                if isinstance(history_stmt, pyvex.stmt.WrTmp) and history_stmt.tmp == tmp:
                    tmp_defined_idx = i
                    return tmp_defined_idx
            if tmp_defined_idx == -1:
                return None
        # res_data = set()
        res_vs = VSMultiValues()

        tmp_defined_idx = get_tmp_definition_idx(tmp, self.stmt_idx)
        assert tmp_defined_idx is not None
        tmp_stmt: pyvex.stmt.WrTmp = self.block.vex.statements[tmp_defined_idx]
        if isinstance(tmp_stmt.data, pyvex.expr.Binop):
            #  t5 = GET(rsp), t4 = GET(rcx)
            #  t3 = Sub(t5, t4)
            #  PUT(rsp) = t3
            expr = tmp_stmt.data
            arg0, arg1 = expr.args
            tmp0, tmp1 = arg0.tmp, arg1.tmp
            tmp0_def_idx, tmp1_def_idx = get_tmp_definition_idx(tmp0, tmp_defined_idx),\
                                         get_tmp_definition_idx(tmp1, tmp_defined_idx)
            tmp0_stmt, tmp1_stmt = self.block.vex.statements[tmp0_def_idx], self.block.vex.statements[tmp1_def_idx]
            if isinstance(tmp0_stmt.data, pyvex.expr.Get) and isinstance(tmp1_stmt.data, pyvex.expr.Get):
                off0, off1 = tmp0_stmt.data.offset, tmp1_stmt.data.offset
                if off0 == self.arch.sp_offset:
                    origin_sp_val = self.tmps[tmp0].one_value()
                    if "Sub" in tmp_stmt.data.op:
                        # update analysis's alloca map
                        for sym in self.tmps[tmp1].values[0]:
                            self.state.analysis.set_alloca_map(sym, DEFAULT_ALLOCA_SZ)
                        # set SP value
                        sp_data = origin_sp_val - DEFAULT_ALLOCA_SZ
                        origin_regions = self.state.extract_abs_regions(origin_sp_val)
                        regions = update_regions_with_offset_and_op(origin_regions, DEFAULT_ALLOCA_SZ, "sub")
                        sp_data = self._annotate_value_with_proper_region(sp_data, regions)
                        res_vs.add_value(0, sp_data)
                    elif "Add" in tmp_stmt.data.op:
                        # lookup analysis's alloca map
                        raise NotImplementedError()
                else:
                    raise NotImplementedError()
            else:
                raise NotImplementedError()

            return res_vs


    # e.g. STle(t6) = t21, t6 and/or t21 might include multiple values
    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        if len(addr.values) == 1:
            addrs = next(iter(addr.values.values()))
            self._store_core(addrs, size, data, endness=stmt.endness)

    def _handle_StoreG(self, stmt: pyvex.IRStmt.StoreG):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)
        elif claripy.is_false(guard_v):
            pass
        else:
            # get current data
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data_old = self._load_core(addrs, size, stmt.endness)
                data = self._expr(stmt.data)

                self._store_core(addrs, size, data, data_old=data_old)

    def _store_core(self, addr: Iterable[Union[int,HeapAddress,SpOffset]], size: int, data: VSMultiValues,
                    data_old: Optional[VSMultiValues]=None, endness=None):
        if data_old is not None:
            data = data.merge(data_old)

        strong_update = False if len(get_abs_regions(self.state, addr)) > 1 else True
        load_store_pattern = self._is_insn_load_store_pattern()

        try:
            rw_upperbound = self.state.analysis.interface.mem_rw_upperbound
        except:
            rw_upperbound = APPROXIMATE_LIMIT
        for a in addr:
            regions = self.state.extract_abs_regions(a)
            if not regions:
                debug_print_log(self.state.analysis.pal_project, message=\
                                f'StoreMem address invalid (ignored), ins_addr = {hex(self.ins_addr)}, sym_var: {a}',
                                min_vlevel=2, logger=l, to_tmp_file=False)
                continue
            elif len(regions) > rw_upperbound:
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"StoreMem addresses dismissed (exceeded limit), ins_addr = {hex(self.ins_addr)}, sym_var: {a}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                continue
            for store_region in regions:
                debug_print_log(self.state.analysis.pal_project, message=\
                                f'StoreMem ({"strong" if strong_update else "weak"}), ins_addr = {hex(self.ins_addr)}, '
                                f'sym_val: {a}, region: {store_region}',
                                min_vlevel=2, logger=l, to_tmp_file=False)
                store_data = data if strong_update else \
                    data.merge(self._load_core([store_region.to_claripy_symvar()], size, endness))

                # patch: use constraint to mitigate false positive in Load-Store pattern
                if load_store_pattern:
                    store_data = get_values_under_constraints(self.state, store_data, SemanticConstraint(
                        ConstraintType.LoadFromRegion, store_region
                    ))

                if store_region.type == AbstractType.Global:
                    atom = MemoryLocation(store_region.offset, size)
                    taint_type, offset = TaintType.GLB, store_region.offset
                    tags: Optional[Set[Tag]] = None
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

                elif store_region.type == AbstractType.Heap:   # store to heap address
                    heap_offset = store_region.offset
                    taint_type, offset = TaintType.HEAP, heap_offset
                    atom = MemoryLocation(HeapAddress(heap_offset), size)
                    tags = None

                else:  # store to symbolic address
                    store_size = size if size >= self.arch.bytes else self.arch.bytes # the unit size is 8-bytes
                    symaddr = store_region.symbol_address()
                    # create a symbol memory location atom to store
                    symaddr_bv = claripy.BVS(symaddr, self.arch.bits, explicit_name=True)
                    symaddr_bv = self.state.annotate_with_abs_regions(symaddr_bv, {store_region})
                    atom = MemoryLocation(symaddr_bv, store_size)
                    tags = None
                    taint_type, offset = TaintType.SYM, symaddr

                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                taint_tags = get_taint_tags(self.state, [store_data])
                store_data = self._annotate_values_with_taint(store_data, taint_type, offset, size, store_taint_set=taint_tags)
                self.state.kill_and_add_definition(atom, self._codeloc(), store_data, tags=tags, endness=endness)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            # FIXME: full conversion support
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif claripy.is_false(guard_v):
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find('Ident') < 0:
                l.warning('Unsupported conversion %s in LoadG.', stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            alt_v = self._expr(stmt.alt)

            data = load_expr_v.merge(alt_v)
            self._handle_WrTmpData(stmt.dst, data)

    def _handle_Exit(self, stmt):
        _ = self._expr(stmt.guard)
        target = stmt.dst.value
        self.state.mark_guard(self._codeloc(), target)

    def _handle_IMark(self, stmt):
        pass

    def _handle_AbiHint(self, stmt):
        pass

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
                load_result = self._load_core(addrs, size, stmt.endness)
                self.tmps[stmt.result] = load_result
                self.state.kill_and_add_definition(Tmp(stmt.result,
                                                       self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                                   self._codeloc(),
                                                   load_result)
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            if len(addr.values) == 1:
                addrs = next(iter(addr.values.values()))
                size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

                self._store_core(addrs, size, storedata)
                self.tmps[stmt.result] = VSMultiValues(offset_to_values={0: {claripy.BVV(1, 1)}})
                self.state.kill_and_add_definition(Tmp(stmt.result,
                                                       self.tyenv.sizeof(stmt.result) // self.arch.byte_width),
                                                   self._codeloc(),
                                                   self.tmps[stmt.result])

    #
    # VEX expression handlers
    #

    def _expr(self, expr) -> VSMultiValues:
        data = super()._expr(expr)
        if data is None:
            bits = expr.result_size(self.tyenv)
            top = self.state.top(bits)
            data = VSMultiValues(offset_to_values={0: {top}})
        return data

    def _handle_RdTmp(self, expr: pyvex.IRExpr.RdTmp) -> Optional[VSMultiValues]:
        tmp: int = expr.tmp

        self.state.add_use(Tmp(tmp, expr.result_size(self.tyenv) // self.arch.byte_width), self._codeloc())

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    # e.g. t0 = GET:I64(rsp), rsp might be defined multiple times
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
            # write it to registers
            values = self._annotate_values_with_taint(values, TaintType.REG, reg_offset, size)
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), values)

        # annotate with constraint
        values = update_vals_with_sem_constraints(self.state, values, {SemanticConstraint(
            ConstraintType.GetFromReg, reg_atom
        )})

        current_defs: Optional[Iterable[Definition]] = None
        for vs in values.values.values():
            for v in vs:
                if current_defs is None:
                    current_defs = self.state.extract_defs(v)
                else:
                    current_defs = chain(current_defs, self.state.extract_defs(v))

        if current_defs is None:
            # no defs can be found. add a fake definition
            self.state.kill_and_add_definition(reg_atom, self._external_codeloc(), values)
        self.state.add_use(reg_atom, self._codeloc())
        return values

    # e.g. t27 = LDle:I64(t9), t9 might include multiple values
    # caution: Is also called from StoreG
    def _handle_Load(self, expr) -> VSMultiValues:
        addr = self._expr(expr.addr)
        bits = expr.result_size(self.tyenv)
        size = bits // self.arch.byte_width

        # convert addr from MultiValues to a list of valid addresses
        if len(addr.values) == 1:
            addrs = next(iter(addr.values.values()))
            return self._load_core(addrs, size, expr.endness)
        # TODO()? resolve such un-resolvable memory, maybe its not todo
        top = self.state.top(bits)
        # annotate it
        dummy_atom = MemoryLocation(0, size)
        top = self.state.annotate_with_def(top, Definition(dummy_atom, ExternalCodeLocation()))
        # add use
        self.state.add_use(dummy_atom, self._codeloc())
        return VSMultiValues(offset_to_values={0: {top}})

    def _load_core(self, addrs: Iterable[claripy.ast.Base], size: int, endness: str) -> VSMultiValues:

        result: Optional[VSMultiValues] = None

        try:
            rw_upperbound = self.state.analysis.interface.mem_rw_upperbound
        except:
            rw_upperbound = APPROXIMATE_LIMIT

        for addr in addrs:
            # handle symbolic region, now we treat both symbolic normal address and symbolic stack address as
            # symbolic. i.e. both [rax + d] and [stack_base + rax + d] ...
            addr_regions = self.state.extract_abs_regions(addr)

            if not addr_regions:  # Abs region cannot be determined by value, load symbolic...
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"LoadMem address invalid (ignored), ins_addr = {hex(self.ins_addr)}, invalid_addr: {addr}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                continue
            elif len(addr_regions) > rw_upperbound:
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"LoadMem address dismissed (exceed limit), ins_addr = {hex(self.ins_addr)}, invalid_addr: {addr}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                continue
            for load_region in addr_regions:
                debug_print_log(self.state.analysis.pal_project, message=\
                                f'LoadMem. ins_addr = {hex(self.ins_addr)}, sym_var: {addr}, AbsRegion: {load_region}.',
                                min_vlevel=2, logger=l, to_tmp_file=False)
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
                            # 2. assign a symbolic value
                            if load_region.offset > 0:
                                str_offset = " + " + hex(load_region.offset)
                            elif load_region.offset == 0:
                                str_offset = ""
                            else:
                                str_offset = " - " + hex(abs(load_region.offset))

                            sym_cont = self.state.top(bits=size * self.arch.byte_width,
                                                      assign_name="[stack" + str_offset + "]")
                            # annotation with def
                            symbol_content = self.state.annotate_with_def(sym_cont, Definition(memory_location,
                                                                                               self._codeloc()))
                            vs = VSMultiValues({0: {symbol_content}})
                            vs = self._annotate_values_with_taint(vs, TaintType.STACK, stack_offset, size)
                            # TODO: for param eval
                            vs = self._annotate_valueset_with_proper_region(vs)
                            # write back to memory (assign definition)
                            self.state.kill_and_add_definition(memory_location, self._codeloc(), vs, endness=endness)

                        self.state.add_use(memory_location, self._codeloc())
                        # annotate with constraints
                        vs = update_vals_with_sem_constraints(self.state, vs,
                                                              {SemanticConstraint(ConstraintType.LoadFromRegion, load_region)})
                        result = result.merge(vs) if result is not None else vs

                elif load_region.type == AbstractType.Heap: # Load data from the heap
                    heap_offset = load_region.offset
                    memory_location = MemoryLocation(HeapAddress(heap_offset), size, endness=endness)
                    try:
                        vs: VSMultiValues = self.state.heap_definitions.load(heap_offset, size=size, endness=endness)
                        vs = self._simplify_valueset(vs)
                        vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)
                    except SimMemoryMissingError:
                        if load_region.offset > 0:
                            str_offset = " + " + hex(load_region.offset)
                        elif load_region.offset == 0:
                            str_offset = ""
                        else:
                            str_offset = " - " + hex(abs(load_region.offset))
                        sym_cont = self.state.top(size * self.arch.byte_width,
                                                  assign_name="[heap" + str_offset+"]")
                        # annotation
                        symbol_content = self.state.annotate_with_def(sym_cont, Definition(memory_location,
                                                                                           ExternalCodeLocation()))
                        vs = VSMultiValues({0: {symbol_content}})
                        vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)
                        # TODO: for param eval
                        vs = self._annotate_valueset_with_proper_region(vs)
                        # write back to memory (assign definition)
                        self.state.kill_and_add_definition(memory_location, self._external_codeloc(), vs, endness=endness)
                    vs = self._annotate_values_with_taint(vs, TaintType.HEAP, heap_offset, size)

                    memory_location = MemoryLocation(HeapAddress(heap_offset), size, endness=endness)
                    self.state.add_use(memory_location, self._codeloc())
                    # annotate with constraints
                    vs = update_vals_with_sem_constraints(self.state, vs,
                                                          {SemanticConstraint(ConstraintType.LoadFromRegion,
                                                                              load_region)})
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
                                self.state.top(size * self.project.arch.byte_width, assign_name="[" + hex(addr_v) + "]")
                            }})
                            vs = self._annotate_values_with_taint(vs, TaintType.GLB, addr_v, size)\

                    # annotate with constraints
                    vs = update_vals_with_sem_constraints(self.state, vs,
                                                          {SemanticConstraint(ConstraintType.LoadFromRegion,
                                                                              load_region)})
                    result = result.merge(vs) if result is not None else vs
                    # FIXME: _add_memory_use() iterates over the same loop
                    memory_location = MemoryLocation(addr_v, size, endness=endness)
                    self.state.add_use(memory_location, self._codeloc())

                else:  # symbolic region
                    symaddr: str = load_region.symbol_address()
                    # load from the symbolic memory living definitions
                    try:
                        vs: VSMultiValues = self.state.symbolic_definitions.load(symaddr, size, endness)
                        vs = self._simplify_valueset(vs)
                        vs = self._annotate_values_with_taint(vs, TaintType.SYM, symaddr, size)
                    except SimMemoryMissingError:
                        # assign a symbolic memory content for this addr (base unit size is 64bits)
                        def_size = size if size >= self.arch.bytes else self.arch.bytes
                        symbol_content = self.state.symbolic_definitions.assign_symbolic(addr,
                                                                                         def_size * self.arch.byte_width,
                                                                                         force_top=False)
                        # annotation
                        symaddr_bv = claripy.BVS(symaddr, self.arch.bits, explicit_name=True)
                        symaddr_bv = self.state.annotate_with_abs_regions(symaddr_bv, {load_region})

                        mem_atom = MemoryLocation(symaddr_bv, def_size)
                        symbol_content = self.state.annotate_with_def(symbol_content, Definition(mem_atom,
                                                                                                 self._codeloc()))
                        # annotate the value with taint tags
                        vs = VSMultiValues({0: {symbol_content}})
                        vs = self._annotate_values_with_taint(vs, TaintType.SYM, symaddr, def_size)
                        # *annotate the value with its relevant abs region (double symbol reference)
                        cont_region = AbstractRegion(AbstractType.Symbolic, 0, symbolic_base=bv_to_str(symbol_content))
                        vs = self._annotate_valueset_with_proper_region(vs)
                        # write back to memory
                        self.state.kill_and_add_definition(mem_atom, self._codeloc(), vs, endness=endness)
                        # if the actual load size < unit size, then load again
                        if def_size > size:
                            vs = self.state.symbolic_definitions.load(symaddr, size, endness)
                            vs = simplify_vs(vs)
                            vs = self._annotate_values_with_taint(vs, TaintType.SYM, symaddr, size)
                    # annotate with constraints
                    vs = update_vals_with_sem_constraints(self.state, vs,
                                                          {SemanticConstraint(ConstraintType.LoadFromRegion,
                                                                              load_region)})
                    # get result
                    result = result.merge(vs) if result is not None else vs

        if result is None:
            result = VSMultiValues(offset_to_values={0: {self.state.top(size * self.arch.byte_width)}})
            # result = self._annotate_values_with_taint(result, TaintType.SYM, , size)
        return result

    # CAUTION: experimental
    def _handle_ITE(self, expr: pyvex.IRExpr.ITE):
        cond = self._expr(expr.cond)
        cond_v = cond.one_value()

        if claripy.is_true(cond_v):
            return self._expr(expr.iftrue)
        elif claripy.is_false(cond_v):
            return self._expr(expr.iffalse)
        else:
            iftrue = self._expr(expr.iftrue)
            iffalse = self._expr(expr.iffalse)
            data = iftrue.merge(iffalse)
            return data

    #
    # Unary operation handlers
    #

    def _handle_Const(self, expr) -> VSMultiValues:
        const_val = claripy_value(expr.con.type, expr.con.value)
        const_val = self._annotate_value_with_proper_region(const_val)
        return VSMultiValues(offset_to_values={0: { const_val }})

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
                if self.state.is_symbolic(v):
                    r.add_value(offset=0, value=self.state.top(bits))
                    continue
                try:
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
                except:
                    pass
        else:
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, arg_0)
        # downsize the taint tags, for operations like 64to32
        # if bits < arg_0.one_value().size():
        #     for tag in taint_tags:
        #         tag.metadata["tagged_sz"] = bits // self.arch.byte_width

        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_Not1(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        e0 = expr_0.one_value()

        if e0 is not None and not e0.symbolic:
            return VSMultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value != 1 else claripy.BVV(0, 1)
                }})

        return VSMultiValues(offset_to_values={0: {self.state.top(1)}})

    def _handle_Not(self, expr):
        arg0 = expr.args[0]
        expr_0 = self._expr(arg0)
        bits = expr.result_size(self.tyenv)

        res_data = set()
        for e0 in expr_0.values[0]:
            if e0 is not None:
                if not e0.concrete:
                    res_data.add(self.state.top(bits))
                else:
                    res_val = ~e0
                    res_val = self._annotate_value_with_proper_region(res_val)
                    res_data.add(res_val)  # pylint:disable=invalid-unary-operand-type

        if not len(res_data):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})
        else:
            r = VSMultiValues(offset_to_values={0: res_data})
        r = update_vals_with_taint_tags(self.state, r, get_taint_tags(self.state, expr_0))
        return r

    #
    # Binary operation handlers
    #

    def _handle_Binop(self, expr):
        handler = None
        if expr.op.startswith('Iop_And'):
            handler = '_handle_And'
        elif expr.op.startswith('Iop_Mod'):
            handler = '_handle_Mod'
        elif expr.op.startswith('Iop_Or'):
            handler = '_handle_Or'
        elif expr.op.startswith('Iop_Add'):
            handler = '_handle_Add'
        elif expr.op.startswith('Iop_Sub'):
            handler = '_handle_Sub'
        elif expr.op.startswith('Iop_Mul'):
            handler = "_handle_Mul"
        elif expr.op.startswith('Iop_DivMod'):
            handler = "_handle_DivMod"
        elif expr.op.startswith('Iop_Div'):
            handler = "_handle_Div"
        elif expr.op.startswith('Iop_Xor'):
            handler = '_handle_Xor'
        elif expr.op.startswith('Iop_Shl'):
            handler = '_handle_Shl'
        elif expr.op.startswith('Iop_Shr'):
            handler = '_handle_Shr'
        elif expr.op.startswith('Iop_Sal'):
            # intended use of SHL
            handler = '_handle_Shl'
        elif expr.op.startswith('Iop_Sar'):
            handler = '_handle_Sar'
        elif expr.op.startswith('Iop_CmpEQ'):
            handler = '_handle_CmpEQ'
        elif expr.op.startswith('Iop_CmpNE'):
            handler = '_handle_CmpNE'
        elif expr.op.startswith('Iop_CmpLT'):
            handler = '_handle_CmpLT'
        elif expr.op.startswith('Iop_CmpLE'):
            handler = '_handle_CmpLE'
        elif expr.op.startswith('Iop_CmpGE'):
            handler = '_handle_CmpGE'
        elif expr.op.startswith('Iop_CmpGT'):
            handler = '_handle_CmpGT'
        elif expr.op.startswith('Iop_CmpORD'):
            handler = '_handle_CmpORD'
        elif expr.op == 'Iop_32HLto64':
            handler = '_handle_32HLto64'
        elif expr.op == "Iop_64HLto128":
            handler = "_handle_64HLto128"
        elif expr.op.startswith('Const'):
            handler = '_handle_Const'

        vector_size, vector_count = None, None
        if handler is not None:
            # vector information
            m = re.match(r"Iop_[^\d]+(\d+)x(\d+)", expr.op)
            if m is not None:
                vector_size = int(m.group(1))
                vector_count = int(m.group(2))
                handler += "_v"

        if handler is not None and hasattr(self, handler):
            if vector_size is not None and vector_count is not None:
                return getattr(self, handler)(expr, vector_size, vector_count)
            return getattr(self, handler)(expr)
        else:
            self.l.error('Unsupported Binop %s.', expr.op)

        return None

    def _handle_Add(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        is_expr0_const = isinstance(expr.args[0], pyvex.expr.Const)
        is_expr1_const = isinstance(expr.args[1], pyvex.expr.Const)

        r = VSMultiValues()
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                expr0_regions = self.state.extract_abs_regions(expr0_v)
                expr1_regions = self.state.extract_abs_regions(expr1_v)
                res_val, res_regions = None, None
                # handle specific cases:
                # **case3: constant value (treat as addressing offset)
                if is_expr0_const:
                    res_val = simplify_ast(expr1_v + expr0_v)
                    # constant value is used as disp
                    if not expr0_regions:
                        res_regions = update_regions_with_offset_and_op(expr1_regions, offset=expr0_v, op=expr.op)
                    # the case that constant value is used as base address
                    else:
                        res_regions = expr0_regions
                elif is_expr1_const:
                    res_val = simplify_ast(expr0_v + expr1_v)
                    if not expr1_regions:
                        res_regions = update_regions_with_offset_and_op(expr0_regions, offset=expr1_v, op=expr.op)
                    else:
                        res_regions = expr1_regions
                # case2: top value
                elif self.state.is_top(expr0_v) or self.state.is_top(expr1_v):
                    res_val = self.state.top(bits)
                    # merge regions
                    res_regions = expr0_regions | expr1_regions
                # case1: two concrete values
                elif expr0_v.concrete and expr1_v.concrete:
                    res_val = expr0_v + expr1_v
                    res_regions = expr0_regions | expr1_regions
                else:
                    res_val = simplify_ast(expr0_v + expr1_v)
                    res_regions = expr0_regions | expr1_regions

                res_val = self._annotate_value_with_proper_region(res_val, res_regions)
                res_val = self.state.annotate_with_taint_tags(res_val, get_taint_tags(self.state, [expr0_v, expr1_v]))
                res_val = self.state.annotate_with_sem_constraints(res_val, get_sem_constraints(self.state,
                                                                                                [expr0_v, expr1_v]))
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"{hex(self.ins_addr)}: _handle_ADD({expr0_v}, {expr1_v}) res_val: {res_val}\n" + " "*100 +
                                f"                                                     res_region: {res_regions}",
                                min_vlevel=2, logger=l, to_tmp_file=False)

                r.add_value(offset=0, value=res_val)

        if not len(r.values):
            r.add_value(offset=0, value=self.state.top(bits))
            r = update_vals_with_taint_tags(self.state, r, get_taint_tags(self.state, [expr0, expr1]))
        return r

    def _handle_Sub(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        is_expr0_const = isinstance(expr.args[0], pyvex.expr.Const)
        is_expr1_const = isinstance(expr.args[1], pyvex.expr.Const)

        r = VSMultiValues()
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                expr0_regions = self.state.extract_abs_regions(expr0_v)
                expr1_regions = self.state.extract_abs_regions(expr1_v)
                res_val, res_regions = None, None
                # handle specific cases:
                # **case3: constant value expr0 - offset (treat as addressing offset)
                if is_expr1_const:
                    res_val = simplify_ast(expr0_v - expr1_v) if not self.state.is_top(expr0_v) \
                        else self.state.top(bits)
                    res_regions = update_regions_with_offset_and_op(expr0_regions, offset=expr1_v, op=expr.op)
                elif is_expr0_const:
                    res_val = simplify_ast(expr0_v - expr1_v) if not self.state.is_top(expr1_v) \
                        else self.state.top(bits)
                    res_regions = expr0_regions
                # case2: top value
                elif self.state.is_top(expr0_v) or self.state.is_top(expr1_v):
                    res_val = self.state.top(bits)
                    # determine result regions: pointer substract
                    if len(expr0_regions) == 1 and len(expr1_regions) == 1 and \
                            next(iter(expr0_regions)).type == next(iter(expr0_regions)).type:
                        res_regions = set()
                    else:
                        res_regions = expr0_regions
                # case1: two concrete values
                elif expr0_v.concrete and expr1_v.concrete:
                    res_val = expr0_v - expr1_v
                    if len(expr0_regions) == 1 and len(expr1_regions) == 1 and \
                            next(iter(expr0_regions)).type == next(iter(expr1_regions)).type:
                        res_regions = set()
                    else:
                        res_regions = expr0_regions
                else:
                    res_val = simplify_ast(expr0_v - expr1_v)
                    if len(expr0_regions) == 1 and len(expr1_regions) == 1 and \
                        next(iter(expr0_regions)).type == next(iter(expr1_regions)).type:
                        res_regions = set()
                    else:
                        res_regions = expr0_regions

                debug_print_log(self.state.analysis.pal_project, message=\
                                f"{hex(self.ins_addr)}: _handle_SUB({expr0_v}, {expr1_v}) res_val: {res_val}\n" + " "*100 +
                                f"                                                     res_region: {res_regions}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                res_val = self._annotate_value_with_proper_region(res_val, res_regions)
                res_val = self.state.annotate_with_taint_tags(res_val, get_taint_tags(self.state, [expr0_v, expr1_v]))
                res_val = self.state.annotate_with_sem_constraints(res_val, get_sem_constraints(self.state,
                                                                                                [expr0_v, expr1_v]))
                r.add_value(offset=0, value=res_val)
        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})
            r = update_vals_with_taint_tags(self.state, r, get_taint_tags(self.state, [expr0, expr1]))
        return r

    def _handle_Mul(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = VSMultiValues()
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                # handle specific cases:
                # case1: two concrete values
                if expr0_v.concrete and expr1_v.concrete:
                    res_val = expr0_v * expr1_v
                    res_regions = None
                # case2: top value
                elif self.state.is_top(expr0_v) or self.state.is_top(expr1_v):
                    res_val = self.state.top(bits)
                    # merge regions
                    res_regions = set()
                # concrete * symbolic
                elif ((self.state.is_symbolic(expr0_v) and expr1_v.concrete) or
                      (self.state.is_symbolic(expr1_v) and expr0_v.concrete)):
                    res_val = simplify_ast(expr0_v * expr1_v)
                    res_regions = set()
                else:
                    res_val = self.state.top(bits)
                    res_regions = set()

                res_val = self._annotate_value_with_proper_region(res_val, res_regions)
                res_val = self.state.annotate_with_taint_tags(res_val, get_taint_tags(self.state, [expr0_v, expr1_v]))
                res_val = self.state.annotate_with_sem_constraints(res_val, get_sem_constraints(self.state,
                                                                                                [expr0_v, expr1_v]))
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"{hex(self.ins_addr)}: _handle_MUL({expr0_v}, {expr1_v}) res_val: {res_val}\n" + " "*86 +
                                f"                                                     res_region: {res_regions}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                r.add_value(offset=0, value=res_val)

        if not len(r.values):
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})
        r = update_vals_with_taint_tags(self.state, r, get_taint_tags(self.state, [expr0, expr1]))
        return r

    def _handle_Div(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = VSMultiValues()
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                expr0_regions = self.state.extract_abs_regions(expr0_v)
                expr1_regions = self.state.extract_abs_regions(expr1_v)
                res_val, res_regions = None, None
                # handle specific cases:
                # case1: two concrete values
                if expr0_v.concrete and expr1_v.concrete:
                    if expr1_v._model_concrete.value == 0:
                        res_val = self.state.top(bits)    
                    else: 
                        res_val = expr0_v // expr1_v
                    res_regions = None
                # case2: top value
                elif self.state.is_top(expr0_v) or self.state.is_top(expr1_v):
                    res_val = self.state.top(bits)
                    # merge regions
                    res_regions = set()
                else:
                    res_val = self.state.top(bits)
                    res_regions = set()

                res_val = self._annotate_value_with_proper_region(res_val, res_regions)
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"{hex(self.ins_addr)}: _handle_DIV({expr0_v}, {expr1_v}) res_val: {res_val}\n" + " "*86 +
                                f"                                                     res_region: {res_regions}",
                                min_vlevel=2, logger=l, to_tmp_file=False)

                r.add_value(offset=0, value=res_val)

        if not len(r.values):
            r = MultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_DivMod(self, expr):
        bits = expr.result_size(self.tyenv)
        args, r = self._binop_get_args(expr)
        if args is None:
            return r
        expr0, expr1 = args
        r = VSMultiValues()
        signed = "U" in expr.op

        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                from_sz, to_sz = expr0_v.size(), expr1_v.size()
                if not (expr0_v.concrete and expr1_v.concrete):
                    res_data = self.state.top(bits)
                    res_regions = set()

                elif signed:
                    try:
                        quotient = (expr0_v.SDiv(claripy.SignExt(from_sz - to_sz, expr1_v)))
                        remainder = (expr0_v.SMod(claripy.SignExt(from_sz - to_sz, expr1_v)))
                    except:
                        quotient = claripy.BVS("TOP", to_sz, explicit_name=True)
                        remainder = quotient
                    res_data = claripy.Concat(
                            claripy.Extract(to_sz - 1, 0, remainder),
                            claripy.Extract(to_sz - 1, 0, quotient)
                        )
                    res_regions = set()
                else:
                    try:
                        quotient = (expr0_v // claripy.ZeroExt(from_sz - to_sz, expr1_v))
                        remainder = (expr0_v % claripy.ZeroExt(from_sz - to_sz, expr1_v))
                    except:
                        quotient = claripy.BVS("TOP", to_sz, explicit_name=True)
                        remainder = quotient
                    res_data = claripy.Concat(
                            claripy.Extract(to_sz - 1, 0, remainder),
                            claripy.Extract(to_sz - 1, 0, quotient)
                        )
                    res_regions = set()
                res_data = self._annotate_value_with_proper_region(res_data, regions=res_regions)
                debug_print_log(self.state.analysis.pal_project, message=\
                                f"{hex(self.ins_addr)}: _handle_DIVMOD({expr0_v}, {expr1_v}) res_val: {res_data}\n" + " "*86 +
                                f"                                                        res_region: {res_regions}",
                                min_vlevel=2, logger=l, to_tmp_file=False)
                r.add_value(offset=0, value=res_data)

        if not len(r.values):
            r = MultiValues(offset_to_values={0: self.state.top(bits)})
        taint_tags = get_taint_tags(self.state, [expr0, expr1])
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_And(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        and_mask = 2 ** bits - 1

        r = VSMultiValues()
        # iterate all the values and calculate the whole value set
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is not None and expr1_v is not None:
                    # concrete case
                    if expr0_v.concrete and expr1_v.concrete:
                        # r.add_value(offset=0, value=expr0_v & expr1_v)
                        res_data = expr0_v & expr1_v
                        res_regions = None
                    else:
                        expr0_regions = self.state.extract_abs_regions(expr0_v)
                        expr1_regions = self.state.extract_abs_regions(expr1_v)
                        # 1. special case a & 0 or  a & 0xf..ff
                        if expr0_v.concrete and expr0_v._model_concrete.value == and_mask:
                            res_data = expr1_v
                            res_regions = expr1_regions
                        elif expr1_v.concrete and expr1_v._model_concrete.value == and_mask:
                            res_data = expr0_v
                            res_regions = expr0_regions
                        elif ((expr0_v.concrete and expr0_v._model_concrete.value == 0) or
                              (expr1_v.concrete and expr1_v._model_concrete.value == 0)):
                            res_data = claripy.BVV(0, bits)
                            res_regions = set()
                        else:
                            res_data = self.state.top(bits)
                            res_regions = expr0_regions | expr1_regions

                    debug_print_log(self.state.analysis.pal_project, message=\
                                    f"{hex(self.ins_addr)}: _handle_AND({expr0_v}, {expr1_v}) res_val: {res_data}\n" + " "*86 +
                                    f"                                                     res_region: {res_regions}",
                                    min_vlevel=2, logger=l, to_tmp_file=False)
                
                    res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                    r.add_value(offset=0, value=res_data)
                else:
                    continue
        if not len(r.values):
            r = MultiValues(offset_to_values={0: self.state.top(bits)})
        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_Xor(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = VSMultiValues()
        # iterate all the values and calculate the whole value set
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is not None and expr1_v is not None:
                    # concrete case
                    if expr0_v.concrete and expr1_v.concrete:
                        res_data = expr0_v ^ expr1_v
                        res_regions = None
                    else:
                        # 1. special case x ^ x = 0 (already automatically handled by vex IR)
                        # 2. operate abstract domain region
                        expr0_regions = self.state.extract_abs_regions(expr0_v)
                        expr1_regions = self.state.extract_abs_regions(expr1_v)
                        res_data = self.state.top(bits)
                        res_regions = expr0_regions | expr1_regions
                    
                    debug_print_log(self.state.analysis.pal_project, message=\
                                    f"{hex(self.ins_addr)}: _handle_XOR({expr0_v}, {expr1_v}) res_val: {res_data}\n" + " "*86 +
                                    f"                                                     res_region: {res_regions}",
                                    min_vlevel=2, logger=l, to_tmp_file=False)
                    res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                    r.add_value(offset=0, value=res_data)
                else:
                    continue
        if not len(r.values):
            r = MultiValues(offset_to_values={0: self.state.top(bits)})
        # FIXME: consider clear taint tags
        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r


    def _handle_Or(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        or_mask = 2 ** bits - 1

        r = VSMultiValues()
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is not None and expr1_v is not None:
                    if expr0_v.concrete and expr1_v.concrete:
                        res_data = expr0_v | expr1_v
                        res_regions = None
                    else:
                        expr0_regions = self.state.extract_abs_regions(expr0_v)
                        expr1_regions = self.state.extract_abs_regions(expr1_v)
                        # 1. special case a | 0 or  a | 0xf..ff
                        if expr0_v.concrete and expr0_v._model_concrete.value == 0:
                            res_data = expr1_v
                            res_regions = expr1_regions
                        elif expr1_v.concrete and expr1_v._model_concrete.value == 0:
                            res_data = expr0_v
                            res_regions = expr0_regions
                        elif ((expr0_v.concrete and expr0_v._model_concrete.value == or_mask) or
                              (expr1_v.concrete and expr1_v._model_concrete.value == or_mask)):
                            res_data = claripy.BVV(2 ** bits - 1, bits)
                            res_regions = set()
                        else:
                            res_data = self.state.top(bits)
                            res_regions = expr0_regions | expr1_regions
                    
                    debug_print_log(self.state.analysis.pal_project, message=\
                                    f"{hex(self.ins_addr)}: _handle_OR({expr0_v}, {expr1_v}) res_val: {res_data}\n" + " "*86 +
                                    f"                                                    res_region: {res_regions}",
                                    min_vlevel=2, logger=l, to_tmp_file=False)
                                    
                    res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                    r.add_value(offset=0, value=res_data)

        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})
        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_Sar(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = MultiValues()
        def _shift_sar(e0, e1):
            # convert e1 to an integer to prevent claripy from complaining "args' lengths must all be equal"
            if e1.symbolic or e0.symbolic:
                return self.state.top(bits)
            e1 = e1._model_concrete.value

            if claripy.is_true(e0 >> (bits - 1) == 0):
                head = claripy.BVV(0, bits)
            else:
                head = ((1 << e1) - 1) << (bits - e1)
            return head | (e0 >> e1)

        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                res_data = _shift_sar(expr0_v, expr1_v)
                res_regions = set()
                res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                r.add_value(offset=0, value=res_data)

        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_Shr(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = VSMultiValues()

        def _shift_shr(e0, e1):
            if e1.symbolic or e0.symbolic:
                return self.state.top(bits)
            if e1.size() < e0.size():
                e1 = e1.sign_extend(e0.size()-e1.size())
            else:
                e0 = e0.sign_extend(e1.size()-e0.size())

            return claripy.LShR(e0, e1)

        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                res_data = _shift_shr(expr0_v, expr1_v)
                res_regions = set()
                res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                r.add_value(offset=0, value=res_data)

        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_Shl(self, expr):
        expr0, expr1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        bits = expr.result_size(self.tyenv)

        r = VSMultiValues()

        def _shift_shl(e0, e1):
            # convert e1 to an integer to prevent claripy from complaining "args' lengths must all be equal"
            if e1.symbolic or e0.symbolic:
                return self.state.top(bits)
            e1 = e1._model_concrete.value
            return e0 << e1

        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is None or expr1_v is None:
                    continue
                res_data = _shift_shl(expr0_v, expr1_v)
                res_regions = set()
                res_data = self._annotate_value_with_proper_region(res_data, res_regions)
                r.add_value(offset=0, value=res_data)

        if not len(r.values):
            r = VSMultiValues(offset_to_values={0: {self.state.top(bits)}})

        taint_tags = get_taint_tags(self.state, expr0)
        taint_tags.update(get_taint_tags(self.state, expr1))
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    # data extend operations
    def _handle_64HLto128(self, expr):
        expr_vs, r = self._binop_get_args(expr)

        expr0, expr1 = expr_vs
        bits = expr.result_size(self.tyenv)
        r = VSMultiValues()
        # iterate all the values and calculate the whole value set
        for expr0_v in expr0.values[0]:
            for expr1_v in expr1.values[0]:
                if expr0_v is not None and expr1_v is not None:
                    if expr0_v.concrete and expr1_v.concrete:
                        # bitwise-xor two single values together
                        # r = MultiValues(offset_to_values={0: {expr0_v ^ expr1_v}})
                        r.add_value(offset=0, value=expr0_v.concat(expr1_v))
                    else:
                        r.add_value(offset=0, value=expr0_v.concat(expr1_v))
                else:
                    continue
        if not len(r.values):
            r = MultiValues(offset_to_values={0: self.state.top(bits)})
        taint_tags = get_taint_tags(self.state, [expr0, expr1])
        r = update_vals_with_taint_tags(self.state, r, taint_tags)
        return r

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return VSMultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value == e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return VSMultiValues(offset_to_values={0: {claripy.BVV(1, 1)}})
            return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

        return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return VSMultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value != e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return VSMultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return VSMultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value < e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return VSMultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                return VSMultiValues(offset_to_values={0: {
                    claripy.BVV(1, 1) if e0._model_concrete.value <= e1._model_concrete.value else claripy.BVV(0, 1)
                }})
            elif e0 is e1:
                return VSMultiValues(offset_to_values={0: {claripy.BVV(0, 1)}})
        # return both {0, 1}
        # return MultiValues(offset_to_values={0: {self.state.top(1)}})
        return VSMultiValues(offset_to_values={0: {claripy.BVV(0, 1), claripy.BVV(1, 1)}})

    def _handle_CmpGT(self, expr):
        return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

    # ppc only
    def _handle_CmpORD(self, expr):
        arg0, arg1 = expr.args
        expr_0 = self._expr(arg0)
        expr_1 = self._expr(arg1)

        e0 = expr_0.one_value()
        e1 = expr_1.one_value()
        bits = expr.result_size(self.tyenv)

        if e0 is not None and e1 is not None:
            if not e0.symbolic and not e1.symbolic:
                if e0 < e1:
                    return VSMultiValues(offset_to_values={0: {claripy.BVV(0x8, bits)}})
                elif e0 > e1:
                    return VSMultiValues(offset_to_values={0: {claripy.BVV(0x4, bits)}})
                else:
                    return VSMultiValues(offset_to_values={0: {claripy.BVV(0x2, bits)}})
            elif e0 is e1:
                return VSMultiValues(offset_to_values={0: {claripy.BVV(0x2, bits)}})

        return VSMultiValues(offset_to_values={0: { self.state.top(1) }})

    def _handle_CCall(self, expr):
        bits = expr.result_size(self.tyenv)
        for arg_expr in expr.args:
            self._expr(arg_expr)
        # return VSMultiValues(offset_to_values={0: { self.state.top(bits) }})
        return VSMultiValues(offset_to_values={0: {claripy.BVV(0, bits)}})

    #
    # User defined high level statement handlers
    #

    def _handle_function(self, func_addr: Optional[VSMultiValues], **kwargs):
        skip_cc = self._handle_function_core(func_addr, **kwargs)
        if not skip_cc:
            self._handle_function_cc(func_addr)

    def _handle_function_core(self, func_addr: Optional[VSMultiValues], **kwargs) -> bool:  # pylint:disable=unused-argument

        if self._call_stack is not None and len(self._call_stack) + 1 > self._maximum_local_call_depth:
            l.warning('The analysis reached its maximum recursion depth.')
            return False

        if func_addr is None:
            l.warning('Invalid type %s for IP.', type(func_addr).__name__)
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(
                    self.state,
                    src_codeloc=self._codeloc(),
                )
                # state: ReachingDefinitionsState
                state: ValueSetState
                self.state = state
            else:
                # l.warning('Please implement the unknown function handler with your own logic.')
                pass
            return False

        func_addr_v = func_addr.one_value()
        if func_addr_v is None or self.state.is_top(func_addr_v):
            # probably an indirect call
            handler_name = 'handle_indirect_call'
            if hasattr(self._function_handler, handler_name):
                _, state = getattr(self._function_handler, handler_name)(self.state, src_codeloc=self._codeloc())
                self.state = state
            else:
                l.warning('Please implement the indirect function handler with your own logic.')
            return False

        if not func_addr_v.concrete:
            handler_name = 'handle_unknown_call'
            if hasattr(self._function_handler, handler_name):
                executed_rda, state = getattr(self._function_handler, handler_name)(self.state,
                                                                                    src_codeloc=self._codeloc())
                state: ReachingDefinitionsState
                self.state = state
            else:
                l.warning('Please implement the unknown function handler with your own logic.')
            return False

        func_addr_int: int = func_addr_v._model_concrete.value

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
                    executed_rda, state = getattr(self._function_handler, handler_name)(self.state, self._codeloc())
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
        func_addr_int: Optional[Union[int,Undefined]] = None
        if func_addr is not None and self.functions is not None:
            func_addr_v = func_addr.one_value()
            if func_addr_v is not None and not self.state.is_symbolic(func_addr_v):
                func_addr_int = func_addr_v._model_concrete.value
                if self.functions.contains_addr(func_addr_int):
                    _cc = self.functions[func_addr_int].calling_convention

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
                    function = func_addr_int if isinstance(func_addr_int, int) else None,
                    metadata = {'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
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
            # for reg in cc.CALLER_SAVED_REGS:
            #     reg_offset, reg_size = self.arch.registers[reg]
            #     atom = Register(reg_offset, reg_size)
            #     self.state.kill_and_add_definition(atom,
            #                                        self._codeloc(),
            #                                        MultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}),
            #                                        )

        if self.arch.call_pushes_ret is True:
            # pop return address if necessary
            sp: VSMultiValues = self.state.register_definitions.load(self.arch.sp_offset, size=self.arch.bytes)
            sp_v = sp.one_value()
            if sp_v is not None and not self.state.is_top(sp_v):
                sp_addr = sp_v - self.arch.stack_change
                sp_addr = self._annotate_value_with_proper_region(sp_addr)
                atom = Register(self.arch.sp_offset, self.arch.bytes)
                tag = ReturnValueTag(
                    function=func_addr_int,
                    metadata={'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
                )
                self.state.kill_and_add_definition(atom, self._codeloc(),
                                                   VSMultiValues(offset_to_values={0: {sp_addr}}),
                                                   tags={tag},
                                                   )

    def _tag_definitions_of_atom(self, atom: Atom, func_addr: int):
        definitions = self.state.get_definitions(atom)
        tag = ParameterTag(
            function = func_addr,
            metadata = {'tagged_by': 'SimEngineRDVEX._handle_function_cc'}
        )
        for definition in definitions:
            definition.tags |= {tag}

    def _annotate_values_with_taint(self, values: VSMultiValues, taint_type, offset, size,
                                    store_taint_set: Optional[Set[TaintTag]]=None) -> VSMultiValues:
        """
        :param taint_type:
        :param offset:
        :param size:
        :param store_taint_set: If none, then load the current taint from certain region, else store
        :return:
        """
        if not self.state.taint_summary:
            return values
        # load and annotate
        if store_taint_set is None:
            taint_set = self.state.taint_summary.load(taint_type, offset, size)
            values = update_vals_with_taint_tags(self.state, values, taint_set)
        else:
            # no need to update values again, since those tags are extracted from values
            # values = update_vals_with_taint_tags(self.state, values, store_taint_set)
            self.state.taint_summary.store(taint_type, offset, data=store_taint_set, size=size)
        return values

    def _determine_abstract_region(self, expr: claripy.ast.Base) -> Union[str, None]:
        """
        Determine whether the expr could represent an abstract region <stack, heap, global>
        """
        if self.state.is_stack_address(expr):
            return AbstractType.Stack
        elif self.state.is_heap_address(expr):
            return AbstractType.Heap
        elif expr.concrete:
            if expr._model_concrete.value in self.state.analysis.global_section_range:
                return AbstractType.Global
        else:
            expr_str = bv_to_str(expr)
            if expr_str.find("TOP") >= 0:
                return None
            return AbstractType.Symbolic

    def _annotate_value_with_proper_region(self, value: claripy.ast.Base, regions: Optional[Set[AbstractRegion]]=None)\
            -> claripy.ast.Base:
        """
        Set the value's abstract region domain knowledge
        :param regions: a set of region to set, if none, region will be determined by the value's type and value
        """
        if regions is None:
            abs_type = self._determine_abstract_region(value)
            # value could represent abstract region, just clear such knowledge
            if abs_type is None:
                # clear
                annotations_to_move = []
                for anno in value.annotations:
                    if isinstance(anno, AbsRegionAnnotation):
                        annotations_to_move.append(anno)
                if annotations_to_move:
                    value = value.remove_annotations(annotations_to_move)
                return value
            sym_base = None
            if abs_type == AbstractType.Stack:
                offset = self.state.get_stack_offset(value)
            elif abs_type == AbstractType.Heap:
                offset = self.state.get_heap_offset(value)
            elif abs_type == AbstractType.Global:
                offset = value._model_concrete.value
            else:
                offset = 0
                sym_base = bv_to_str(value)
            abs_region = AbstractRegion(abs_type, offset, symbolic_base=sym_base)
            set_regions = {abs_region}
        else:
            set_regions = regions
        return self.state.annotate_with_abs_regions(value, set_regions)

    def _annotate_valueset_with_proper_region(self, valueset: VSMultiValues):
        nvs = VSMultiValues()
        for offset, vs in valueset.values.items():
            for val in vs:
                val = self._annotate_value_with_proper_region(val)
                nvs.add_value(offset, val)
        return nvs

    def _simplify_valueset(self, valueset: VSMultiValues) -> VSMultiValues:
        """
        Simplify the value-set, and reserve each value's annotations.
        This method is used for _load_core(), to simplify value-set loaded.
        """
        nvs = VSMultiValues()
        for offset, vs in valueset.values.items():
            for val in vs:
                nval = simplify_ast(val)
                if nval.annotations:
                    annos_to_remove = nval.annotations
                    nval = nval.remove_annotations(annos_to_remove)
                nval = nval.append_annotations(val.annotations)

                nvs.add_value(offset, nval)
        return nvs

    def _is_insn_load_store_pattern(self):
        """
        add [rax + 1], rbx
        """
        insn = filter(lambda x: x.address == self.ins_addr, self.block.capstone.insns)
        insn = next(iter(insn)).insn
        if len(insn.operands) > 1 and insn.operands[0].type == CS_OP_MEM \
                and insn.mnemonic.find("mov") < 0\
                and insn.mnemonic.find("cmp") < 0:
            return True
        return False