from typing import List, Set, Optional, TYPE_CHECKING, Union, Iterable, Dict, Tuple
import logging

import claripy

log = logging.getLogger(__name__)

import angr

from angr.calling_conventions import SimCC, DEFAULT_CC
from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag, FunctionTag, Tag
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.engines.light import RegisterOffset, SpOffset
from angr.knowledge_plugins.key_definitions.live_definitions import DefinitionAnnotation
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.errors import SimMemoryMissingError

from ..vs_state import ValueSetState
from ...value_set.simmemory.vs_multivalues import VSMultiValues
from ...utils import get_taint_tags, update_vals_with_taint_tags
from ..value_domains.taint_logic import TaintTag
from ..value_domains.abstract_region import AbstractRegion, AbstractType
from ..taint import TaintType
from ....syscalls import plt_function_to_syscall
from ..taint.taint_summary import sysname_to_number
if TYPE_CHECKING:
    from ....analyses.binary_summary import BinarySummaryInterface

MAX_ALLOC_SIZE = 8192
DEFAULT_ALLOC_SIZE = 0x100  # default allocation size


class ValueSetUtil:
    def __init__(self, project: angr.Project, interface: 'BinarySummaryInterface', canonical_size=8):
        self.project = project
        self._heap_allocator: HeapAllocator = None
        self.canonical_size = canonical_size
        self.interface = interface

    def generate_arg_atoms(self, cc: Optional[SimCC], force_generate_atoms=False):
        if not cc and not force_generate_atoms:
            return []
        elif not cc and force_generate_atoms:
            arg_atoms = \
                [Register(self.project.arch.registers["rdi"][0], self.project.arch.registers['rdi'][1]),
                 Register(self.project.arch.registers['rsi'][0], self.project.arch.registers['rsi'][1]),
                 Register(self.project.arch.registers['rdx'][0], self.project.arch.registers['rdx'][1])]
            return arg_atoms
        try:
            args = cc.arg_locs()
        except (ValueError, TypeError):
            args = cc.args
        if not args and not force_generate_atoms:
            return []
        elif not args:
            arg_atoms = \
                [Register(self.project.arch.registers["rdi"][0], self.project.arch.registers['rdi'][1]),
                 Register(self.project.arch.registers['rsi'][0], self.project.arch.registers['rsi'][1]),
                 Register(self.project.arch.registers['rdx'][0], self.project.arch.registers['rdx'][1])]
            return arg_atoms

        arg_atoms: List[Register] = []
        for arg in args:
            arg_atoms.append(Atom.from_argument(arg, self.project.arch.registers))
        return arg_atoms

    def get_register_vs_and_def(self, reg_atom: Register, state: ValueSetState, codeloc: CodeLocation=None) \
            -> Tuple[VSMultiValues, Set[Definition]]:
        try:
            v: VSMultiValues = state.register_definitions.load(reg_atom.reg_offset, reg_atom.size)
            values = v.values[0]
        except:
            raise ValueError
        definitions: Set[Definition] = set()
        for val in values:
            definitions.update(map(lambda a: a.definition,
                                   filter(lambda x: isinstance(x, DefinitionAnnotation), val.annotations)
                                   ))
        return v, definitions

    def handle_memory_definition(self, state: ValueSetState, codeloc: CodeLocation, dst_valset: VSMultiValues,
                                 func: Function, content_valset: Optional[VSMultiValues]=None,
                                 size_valset: Optional[VSMultiValues]=None
                                 ):
        """
        Define a memory location, which represented by dst_valset.
        The value set of this region could either be None, in case of functions fget(), read() and so on, or be a
        content value set, in case of memcpy() and so on...
        """
        # TODO(): identify and differentiate the strong and weak update
        if size_valset and len(size_valset.values[0]) == 1 and size_valset.one_value().concrete:
            size = size_valset.one_value()._model_concrete.value
        else:
            size = self.canonical_size
        if content_valset is None:
            content_name = "read_content"
            data = VSMultiValues({0: {state.top(self.project.arch.bits, assign_name=content_name)}})
        else:
            data = content_valset
        # create proper regions
        for val in dst_valset.values[0]:
            memlocation: Optional[Atom] = None
            taint_type, offset = None, None

            regions = state.extract_abs_regions(val)
            # store a non-region (symbolic region)
            if not regions:
                ...
                continue

            for store_region in regions:
                # determine memory region first
                if store_region.type == AbstractType.Global:
                    memlocation = MemoryLocation(store_region.offset, size)
                    taint_type, offset, tp = TaintType.GLB, store_region.offset, "memory"
                    pass
                elif store_region.type == AbstractType.Stack:
                    taint_type, offset, tp = TaintType.STACK, store_region.offset, "stack"
                    memlocation = MemoryLocation(SpOffset(state.arch.bits, offset), size)
                elif store_region.type == AbstractType.Heap: # heap region
                    taint_type, offset, tp = TaintType.HEAP, store_region.offset, "heap"
                    memlocation = MemoryLocation(HeapAddress(offset), size)
                else:
                    taint_type, offset, tp = TaintType.SYM, store_region.symbol_address(), "symbol"
                    symaddr = claripy.BVS(offset, self.project.arch.bits, explicit_name=True)
                    symaddr = state.annotate_with_abs_regions(symaddr, {store_region})
                    memlocation = MemoryLocation(symaddr, size)
                # determine whether the content comes from syscall (external source like read file)
                if content_valset is None:
                    func_id = self.interface._plt_function_times_map[func]
                    tagged_name = plt_function_to_syscall(func.name)
                    load_syscall = True if tagged_name else False
                    if load_syscall:
                        tags = self._get_syscall_tags(state, syscall_number=sysname_to_number(tagged_name))
                    # this should not happen
                    else:
                        tags = {TaintTag(func.addr, metadata={"tagged_by": tagged_name + str(func_id),
                                                              "tagged_tp": tp,
                                                              "tagged_off": offset,
                                                              "tagged_sz": size})}
                        raise TypeError(f"Check READ_TAINT_FUNCS to ensure function {func.name} is added.")
                # load the content's taint
                else:
                    tags = get_taint_tags(state, data)
                # define the region (we should identify the strong and weak update)
                data = self._annotate_values_with_taint(state, data, taint_type, offset, size, store_taint_set=tags)

                try:
                    state.kill_and_add_definition(memlocation, codeloc, data, endness=state.arch.memory_endness)
                except OverflowError:
                    print("dbg")

    def handle_memory_use_for_syscall(self, state: ValueSetState, codeloc: CodeLocation, region_vals: VSMultiValues,
                                      func: Function, content_valset: Optional[VSMultiValues]=None):
        """
        Use a memory location, which represented by region_valset.
        The value set of this region is used for write(), fputs() and so on.
        """
        tags = set()
        for region_val in region_vals.values[0]:

            regions = state.extract_abs_regions(region_val)
            for region in regions:

                if region.type == AbstractType.Global:
                    taint_type, taint_offset = TaintType.GLB, region.offset
                elif region.type == AbstractType.Stack:
                    taint_type, taint_offset = TaintType.STACK, region.offset
                elif region.type == AbstractType.Heap:
                    taint_type, taint_offset = TaintType.HEAP, region.offset
                else:
                    taint_type, taint_offset = TaintType.SYM, region.symbol_address()

                tags.update(state.taint_summary.load(taint_type, taint_offset, self.canonical_size,
                                                     adjust_stack=False))
        # taint syscall region
        tagged_syscall = plt_function_to_syscall(func.name)
        off = sysname_to_number(tagged_syscall)
        if not tagged_syscall or not off:
            raise NotImplementedError(f"{func.name} is not modeled to syscall correctly.")
        state.taint_summary.store(TaintType.SYSCALL, off, tags)

    def handle_return_val(self, func: Function, state: ValueSetState, codeloc: CodeLocation,
                          values: Optional[VSMultiValues], set_ret_val=True, create_symbol=False):
        self._manipulate_return_sp(state, codeloc, func)
        if func.calling_convention:
            ret_arg = func.calling_convention.return_val
            if ret_arg is None or not set_ret_val:
                # none return value
                return
        else:
            ret_arg = angr.calling_conventions.SimRegArg("rax", state.arch.bytes)
        ret_reg = Atom.from_argument(ret_arg, self.project.arch.registers)
        tags = {ReturnValueTag(func.addr, metadata={"tagged_by": func.name})}
        if values is None:  # create a TOP value and assign to rax
            if create_symbol:
               # assign unique return value
                ret_id = self.interface._plt_function_times_map[func]
                values = VSMultiValues(offset_to_values={0: {state.top(self.project.arch.bits,
                                                                     assign_name=func.name + str(ret_id))
                                                           }})
            else:
                values = VSMultiValues(offset_to_values={0: {state.top(self.project.arch.bits)}})
                # clear taint for return reg
                self._annotate_values_with_taint(state, values, TaintType.REG, ret_reg.reg_offset, ret_reg.size,
                                                 store_taint_set=set())
        else:   # assign return value to rax
            ret_val_taints = get_taint_tags(state, values)
            self._annotate_values_with_taint(state, values, TaintType.REG, ret_reg.reg_offset, ret_reg.size,
                                             store_taint_set=ret_val_taints)
            pass
        try:
            self.state.analysis.update_side_effect_set(
                self.state.analysis.reg_side_effect_set,
                ret_reg.reg_offset,
                ret_reg.size
            )
        except:
            pass
        state.kill_and_add_definition(ret_reg, codeloc, data=values, tags=tags)

    def allocate(self, state: ValueSetState, codeloc: CodeLocation, func: Function,
                 size_vals: Optional[VSMultiValues]=None,
                 items_vals: Optional[VSMultiValues]=None,
                 data_val: Optional[int]=None) -> Tuple[HeapAddress, VSMultiValues]:
        """
        Simulate library functions which allocate heap regions, i.e. malloc(), calloc()...
        Allocate is size-insensitive. We only allocate the canonical size for each chunk
        """
        if size_vals and len(size_vals.values[0]) == 1 and size_vals.one_value().concrete:
            size = size_vals.one_value()._model_concrete.value
        else:
            size = DEFAULT_ALLOC_SIZE

        if items_vals and len(items_vals.values[0]) == 1 and items_vals.one_value().concrete:
            items = items_vals.one_value()._model_concrete.value
        else:
            items = 1
        # size, items = self.canonical_size, 1  # default
        size *= items
        # FIXME:DBG
        if size == 0x10000:
            size = 0x100
        if size >= 0x100000000000000:
            size = 0x100
        if size < 1:
            size = 0x1
        heapaddr: HeapAddress = state.heap_allocator.allocate(size)
        # FIXME: DEBUG
        if heapaddr.value == 0xcdc or heapaddr == 0xd2c:
            print('dbg')
        log.debug(f"Allocated {hex(size)} bytes at heap addr {heapaddr} successfully.")
        memlocation = MemoryLocation(heapaddr, size)

        # annotate ret_value with its abstract heap region
        heap_region = AbstractRegion(AbstractType.Heap, heapaddr.value)
        heap_val = state.annotate_with_abs_regions(state.heap_address(heapaddr.value), {heap_region})

        heap_pointer_val = VSMultiValues({0: {heap_val}})
        tags = {FunctionTag(function=func.addr, metadata={"tagged_by": func.name})}
        # if there is no initialized value, we do not initialize the content of heap
        if data_val:
            data = VSMultiValues(offset_to_values={0: {claripy.BVV(data_val, size * self.project.arch.bytes)}})
            state.kill_and_add_definition(memlocation, codeloc, data=data, tags=tags, endness=state.arch.memory_endness)
        return heapaddr, heap_pointer_val

    def load_memory_regions(self, state: ValueSetState, codeloc, region_vals: VSMultiValues,
                            size_vals: Optional[VSMultiValues]=None) -> VSMultiValues:
        """
        Load values from proper memory region (represented by region_vs)
        """
        # choose size. For now, we choose canonical size.
        if len(size_vals.values[0]) == 1 and size_vals.one_value().concrete:
            size = size_vals.one_value()._model_concrete.value
        else:
            size = self.canonical_size
        return state.analysis._engine._load_core(region_vals.values[0], size, state.arch.memory_endness)

    def _manipulate_return_sp(self, state: ValueSetState, codeloc, func: Optional[Function]):
        if not self.project.arch.call_pushes_ret:
            return
        try:
            offset, size = self.project.arch.registers["rsp"]
            v: VSMultiValues = state.register_definitions.load(offset, size)
            values = v.values[0]
        except SimMemoryMissingError:
            # should not reach here
            raise SimMemoryMissingError

        if len(values) == 0:
            raise ValueError("No definition of SP found.")
        if len(values) > 1:
            log.critical(
                f'Invalid number of values for stack pointer at function {func.name if func else "?"} return. '
                f'Stack is probably unbalanced. This indicates '
                'serious problems with function handlers. Stack pointer values include: %s.', values)
        sp_v = v.one_value()
        if sp_v is not None and not state.is_top(sp_v):
            sp_addr = sp_v - self.project.arch.stack_change

            # update abs_region annotaion
            stack_off = state.get_stack_offset(sp_addr)
            abs_region = AbstractRegion(AbstractType.Stack, stack_off)
            sp_addr = state.annotate_with_abs_regions(sp_addr, {abs_region})

            atom = Register(self.project.arch.sp_offset, self.project.arch.bytes)
            tag = ReturnValueTag(
                function=func.addr if func else 0,
                metadata={'tagged_by': func.name if func else "?"}
            )
            state.kill_and_add_definition(atom, codeloc,
                                          VSMultiValues(offset_to_values={0: {sp_addr}}),
                                          tags={tag},
                                          )

    def _annotate_values_with_taint(self, state, values: VSMultiValues, taint_type, offset, size,
                                    store_taint_set: Optional[Set[TaintTag]]=None) -> VSMultiValues:
        """

        :param taint_type:
        :param offset: the offset of region
        :param size:
        :param store_taint_set: If none, then load the current taint from certain region, else store
        :return:
        """
        if not state.taint_summary:
            return values
        # load and annotate
        if store_taint_set is None:
            taint_set = state.taint_summary.load(taint_type, offset, size)
            values = update_vals_with_taint_tags(state, values, taint_set)
        else:
            values = update_vals_with_taint_tags(state, values, store_taint_set)
            state.taint_summary.store(taint_type, offset, data=store_taint_set, size=size)
        return values

    def _get_syscall_tags(self, state: ValueSetState, syscall_number) -> Set[TaintTag]:
        if not state.taint_summary or syscall_number is None:
            return set()
        return state.taint_summary.load(TaintType.SYSCALL, syscall_number)