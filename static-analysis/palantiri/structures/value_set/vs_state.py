from typing import Dict, List, Tuple, Optional, Set, TYPE_CHECKING, Iterable, Union
from . import abstract_to_register
from .value_domains.abstract_region import AbstractRegion, AbstractType
from .value_domains.semantic_record import SemanticConstraint, ConstraintType

from ..key_definitions import GENERAL_REGS_NO_STACKS_x64
from palantiri.singletons.global_symdict import global_symmem_dict
from palantiri.structures.value_set.vs_subject import VSSubject
import weakref

import claripy
import archinfo
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.analyses.calling_convention import SimCC
from angr.knowledge_plugins.key_definitions.tag import ParameterTag, InitialValueTag
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register
from .value_domains.taint_logic import TaintTag
from angr.analyses.reaching_definitions.subject import SubjectType
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.code_location import CodeLocation
from angr.calling_conventions import DEFAULT_CC
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

import logging
l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

from .vs_livedefinitions import VSLiveDefinitions
from .taint import TaintSummary
if TYPE_CHECKING:
    from ...analyses.binary_summary import BinarySummary
    from palantiri.cfg.cfgtest import *
    from palantiri.pal_project import PalProject

class ValueSetState(ReachingDefinitionsState):
    """
    FunctionSummaryState is a lightweight representation scheme for angr.ReachingDefinitionState,
    which contains the representation of use-def and value-set analysis for a certain program state.
    """

    __slots__ = ('arch', '_subject', '_track_tmps', 'analysis', 'current_codeloc', 'codeloc_uses', 'live_definitions',
                 'all_definitions', '_canonical_size', 'heap_allocator', '_do_taint_summary', "_stack_change_offset",
                 '_block_addr', '_block_size', '_should_standardize', 'abort', 'taint_summary', '__weakref__', '_addr',
                 'activate')

    def __init__(self, arch: archinfo.Arch, subject: VSSubject, track_tmps: bool = False,
                 analysis: Optional['BinarySummary']=None, rtoc_value=None,
                 live_definitions: Optional[VSLiveDefinitions] = None, canonical_size: int = 8,
                 heap_allocator: HeapAllocator = None, do_taint_summary=None, taint_summary=None,
                 abort=False, activate=False
                 ):
        # super(ValueSetState, self).__init__(arch, subject, track_tmps, None, rtoc_value,
        #                                            live_definitions, canonical_size, heap_allocator, None)
        # handy short-hands
        self.arch = arch
        self._subject = subject
        self._track_tmps = track_tmps
        self.analysis = analysis
        self._canonical_size: int = canonical_size
        self._environment = None
        self._do_taint_summary = do_taint_summary

        self._stack_change_offset = None
        self._block_addr = None     # represent the block address in binary summary
        self._block_size = None     # represent the block size in binary summary
        self._should_standardize = False

        # be marked when abort() is called
        self.abort = abort
        #
        self.activate = activate

        if live_definitions is None:
            # the first time this state is created. initialize it
            try:
                vs_upperbound = self.analysis.interface.valueset_upperbound
            except:
                vs_upperbound = 15
            self.live_definitions = VSLiveDefinitions(self.arch, track_tmps=self._track_tmps,
                                                      canonical_size=canonical_size, project=self.analysis.project,
                                                      valueset_upperbound=vs_upperbound)
            self._set_initialization_values(subject, rtoc_value)
        else:
            # this state is a copy from a previous state. skip the initialization
            self.live_definitions = live_definitions

        self.live_definitions.set_state(self)

        self.all_definitions: Set[Definition] = set()

        self.heap_allocator = heap_allocator or HeapAllocator(canonical_size)

        self.taint_summary = taint_summary
        if do_taint_summary and self.taint_summary is None:
            # do taint summary, initalize the original taint summary state
            self.taint_summary = TaintSummary(self.analysis.project, self.analysis)

        self.current_codeloc: Optional[CodeLocation] = None
        self.codeloc_uses: Set[Definition] = set()
        self.analysis = analysis

    def annotate_with_taint_tags(self, symvar: claripy.ast.Base, taint_tags: Set[TaintTag]):
        return self.live_definitions.annotate_with_taint_tags(symvar, taint_tags)

    def extract_taint_tags(self, symvar: claripy.ast.Base):
        return self.live_definitions.extract_taint_tags(symvar)

    def annotate_with_abs_regions(self, symvar: claripy.ast.Base, regions: Set[AbstractRegion]):
        return self.live_definitions.annotate_with_abs_regions(symvar, regions)

    def extract_abs_regions(self, symvar: claripy.ast.Base):
        return self.live_definitions.extract_abs_regions(symvar)

    def annotate_with_sem_constraints(self, symvar: claripy.ast.Base, constraints: Set[SemanticConstraint]):
        return self.live_definitions.annotate_with_sem_constraints(symvar, constraints)

    def extract_sem_constraints(self, symvar: claripy.ast.Base):
        return self.live_definitions.extract_sem_constraints(symvar)

    @property
    def symbolic_definitions(self):
        return self.live_definitions.symbolic_definitions

    def top(self, bits: int, atom: Optional[Atom]=None, assign_name=None):
        return self.live_definitions.get_top(bits, atom, assign_name)

    def is_top(self, *args):
        return self.live_definitions.is_top(*args)

    def is_symbolic(self, *args):
        return self.live_definitions.is_symbolic(*args)

    # @staticmethod
    def is_heap_address(self, addr: claripy.ast.Base) -> bool:
        return self.live_definitions.is_heap_address(addr)

    def is_stack_address(self, addr: claripy.ast.Base) -> bool:
        return self.live_definitions.is_stack_address(addr)

    def get_stack_offset(self, addr: claripy.ast.Base) -> Optional[Union[int, claripy.ast.Base]]:
        return self.live_definitions.get_stack_offset(addr)

    def copy(self, copy_taint_summary=False) -> 'ValueSetState':
        rd = ValueSetState(
            self.arch,
            self._subject,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            live_definitions=self.live_definitions.copy(),
            canonical_size=self._canonical_size,
            heap_allocator=self.heap_allocator,
            do_taint_summary=self._do_taint_summary,
            taint_summary=self.taint_summary.copy() if copy_taint_summary and self.taint_summary else None,
            abort=self.abort,
            activate=self.activate
        )
        return rd

    def merge(self, *others, update_taint_summary=False) -> Tuple['ValueSetState', bool]:
        state = self.copy(copy_taint_summary=update_taint_summary)
        # # do not merge abort states
        # others: Iterable['ValueSetState'] = list(filter(lambda s: s.abort is False, others))
        state.live_definitions, merged = state.live_definitions.merge(*[other.live_definitions for other in others])
        state.activate = state.activate | any(other.activate for other in others)
        if update_taint_summary and state.taint_summary is not None:
            state.taint_summary = state.taint_summary.merge(*[other.taint_summary for other in others])
        return state, merged

    def standardize(self, *others) -> 'ValueSetState':
        """
        Standardize is like to "merge" several consequential state into one (its block size, stake_change_offset, and
        taint summary). It's to recover the normalized control flow block to codeblock for function.
        """
        if not len(others):
            return self

        for o in others:
            self._block_size += o._block_size

        self.taint_summary = self.taint_summary.standardize(*[other.taint_summary for other in others])
        self.live_definitions = others[-1].live_definitions

        self._should_standardize = False
        return self

    def __getstate__(self):
        s = {slot: getattr(self, slot) for slot in self.__slots__ if slot not in \
             ("analysis", "__weakref__", "_addr")}
        return s

    def __setstate__(self, state):
        for slot in state:
            setattr(self, slot, state[slot])

    def _get_weakref(self):
        return weakref.proxy(self)

    def _set_initialization_values(self, subject: Subject, rtoc_value: Optional[int]=None):
        assert subject.type == SubjectType.Function
        # use default cc to set function
        self._initialize_function(
            subject.cc or DEFAULT_CC.get(self.arch.name, None)(self.arch),
            subject.content.addr,
            rtoc_value,
        )
        return self

    def _initialize_parameter_registers(self, reg_name: str):
        """
        Initialize parameter registers (rdi, rsi, rdx, rcx, r8, r9)
        """
        reg_offset = self.arch.registers[reg_name][0]
        reg_atom = Register(reg_offset, self.arch.bytes)
        reg_def = Definition(reg_atom, ExternalCodeLocation(), tags={ParameterTag(metadata={"tagged_by": reg_name})})
        reg_val = self.annotate_with_def(self.top(self.arch.bits, atom=reg_atom), reg_def)
        # initialize the abstract region for reg val ( symbolic address )
        reg_region = AbstractRegion(AbstractType.Symbolic, 0, symbolic_base=reg_name)
        reg_val = self.annotate_with_abs_regions(reg_val, {reg_region})
        # store
        self.register_definitions.store(reg_offset, reg_val)

    def _initialize_function(self, cc: SimCC, func_addr: int, rtoc_value: Optional[int]=None):
        # initialize stack pointer
        sp_atom = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp_atom, ExternalCodeLocation(), tags={InitialValueTag()})
        sp_region = AbstractRegion(AbstractType.Stack, 0)
        sp = self.annotate_with_def(self._initial_stack_pointer(), sp_def)
        # initialize the abstract region for sp val
        sp = self.annotate_with_abs_regions(sp, {sp_region})
        self.register_definitions.store(self.arch.sp_offset, sp)
        # initialize the abstract region for parameter registers
        # if cc is not None:
        #     for arg_name in cc.ARG_REGS:
        #         self._initialize_parameter_registers(arg_name)
        for reg_name in GENERAL_REGS_NO_STACKS_x64:
            self._initialize_parameter_registers(reg_name)

    #
    # DEBUG functions
    #

    def _dbg_hook(self, addr):
        """ FIXME: delete"""
        self._addr = addr

    def _dbg(self):
        """ FIXME: delete"""
        from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
        from angr.errors import SimMemoryMissingError, SimMemoryError
        print(f"===CHECK Register_Definitions for state {hex(self._addr)}===")
        # register check
        for i in [16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136]:
            reg_name = abstract_to_register(i, 8, self.analysis.project)
            try:
                v: MultiValues = self.register_definitions.load(i, size=8)
                vs = v.values[0]
                for val in vs:
                    if isinstance(val, claripy.ast.Base):
                        defs = list(self.extract_defs(val))
                        if len(defs):
                            def_ = defs[0]
                        else:
                            def_ = "external def"
                    else:
                        def_ = "int val, cannot get definition by annotation"
                    print(f"{reg_name}: {val}, by definition: {def_}")
            except SimMemoryMissingError:
                print(f"{reg_name}: is not defined and used.")
                continue
        print(f"===CHECK SymbolicMemory_Definitions for state {hex(self._addr)}===")
        # symbolic memory check
        mem = self.symbolic_definitions._memory
        for addr, v in mem.items():
            v: MultiValues
            vs = v.values[0]
            for val in vs:
                if isinstance(val, claripy.ast.Base):
                    defs = list(self.extract_defs(val))
                    if len(defs):
                        def_ = defs[0]
                    else:
                        def_ = "external def"
                else:
                    def_ = "int val, cannot get definition by annotation"
                print(f"{addr}({global_symmem_dict.global_symmem_dict[addr]}): {val}, by definition: {def_}")

    def _dbg_print_stack(self, offset, sz=8):
        assert isinstance(offset, int)
        stack_addr = self.live_definitions.stack_offset_to_stack_addr(offset)
        from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
        try:
            v: MultiValues = self.stack_definitions.load(stack_addr, sz)
        except:
            print(f"[state {hex(self._addr)}] stack offset {hex(offset)} is not defined.")
            return
        vs = v.values[0]
        for v in vs:
            defs = list(self.extract_defs(v))
            if len(defs):
                def_ = defs[0]
            else:
                def_ = "external def"
            print(f"[state {hex(self._addr)}] stack offset {hex(offset)}: {v}, with def: {def_}")