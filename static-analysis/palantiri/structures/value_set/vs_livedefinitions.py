from typing import Optional, Iterable, Dict, Set, Tuple, Union, TYPE_CHECKING
import logging
import time
from misc.debugger import dbgLog
from . import abstract_to_register
from .simmemory.vs_mvmemory import VSMultiValuedMemory
from .simmemory.vs_multivalues import VSMultiValues
from .vs_symbolicmemory import SymbolicMemory

import claripy
import archinfo

from collections import defaultdict

from angr.errors import SimMemoryMissingError, SimMemoryError
from angr.engines.light import SpOffset
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, MemoryLocation, Tmp
from angr.knowledge_plugins.key_definitions.definition import Definition, Tag
from .value_domains.taint_logic import TaintTag
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.uses import Uses

from .value_domains.taint_logic import TaintTagAnnotation
from .value_domains.abstract_region import AbstractRegion, AbsRegionAnnotation
from .value_domains.semantic_record import SemanticConstraint, SemConstraintAnnotation

if TYPE_CHECKING:
    pass

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


class VSLiveDefinitions(LiveDefinitions):

    INITIAL_SP_32BIT = 0x7fff0000
    INITIAL_SP_64BIT = 0x7fffffff0000
    _tops = {}

    __slots__ = ('project', 'state', 'arch', 'track_tmps', 'register_definitions',
                 'stack_definitions', 'heap_definitions',
                 'memory_definitions', 'symbolic_definitions', 'tmps', 'register_uses', 'stack_uses', 'heap_uses',
                 'memory_uses', 'symbolic_uses', 'uses_by_codeloc', 'tmp_uses', '_canonical_size', 
                 'valueset_upperbound')

    def __init__(self, arch: archinfo.Arch, track_tmps: bool=False, canonical_size=8,
                 register_definitions=None,
                 stack_definitions=None,
                 memory_definitions=None,
                 heap_definitions=None,
                 symbolic_definitions=None,
                 project=None,
                 state=None,
                 valueset_upperbound=15,
                 ):
        self.project = project
        self.arch = arch
        self.track_tmps = track_tmps
        self._canonical_size: int = canonical_size  # TODO: Drop canonical_size
        self.state = state if state is not None else None
        self.valueset_upperbound = valueset_upperbound
        self.register_definitions = VSMultiValuedMemory(memory_id="reg",
                                                      top_func=self.top,
                                                      skip_missing_values_during_merging=True,
                                                      page_kwargs={'mo_cmp': self._mo_cmp},
                                                      element_limit=valueset_upperbound) \
            if register_definitions is None else register_definitions
        self.stack_definitions = VSMultiValuedMemory(memory_id="stack",
                                                   top_func=self.top,
                                                   skip_missing_values_during_merging=True,
                                                   page_kwargs={'mo_cmp': self._mo_cmp},
                                                   element_limit=valueset_upperbound) \
            if stack_definitions is None else stack_definitions
        self.memory_definitions = VSMultiValuedMemory(memory_id="mem",
                                                    top_func=self.top,
                                                    skip_missing_values_during_merging=True,
                                                    page_kwargs={'mo_cmp': self._mo_cmp},
                                                    element_limit=valueset_upperbound) \
            if memory_definitions is None else memory_definitions
        self.heap_definitions = VSMultiValuedMemory(memory_id="mem",
                                                  top_func=self.top,
                                                  skip_missing_values_during_merging=True,
                                                  page_kwargs={'mo_cmp': self._mo_cmp},
                                                  element_limit=valueset_upperbound) \
            if heap_definitions is None else heap_definitions
        # create symbolic representation for symbolic variables, i.e. representation for [rax], [rsp + rax]
        # when such base_addr_register or index_addr_register is symbolic (not defined)
        self.symbolic_definitions = SymbolicMemory(memory_id="sym",
                                                   top_func=self.top,
                                                   skip_missing_values_during_merging=None,
                                                   page_kwargs=None) \
            if symbolic_definitions is None else symbolic_definitions

        self.tmps: Dict[int, Set[Definition]] = {}

        # set state
        self.register_definitions.set_state(self)
        self.stack_definitions.set_state(self)
        self.memory_definitions.set_state(self)
        self.heap_definitions.set_state(self)
        self.symbolic_definitions.set_state(self)

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.heap_uses = Uses()
        self.memory_uses = Uses()
        self.symbolic_uses = Uses()
        self.uses_by_codeloc: Dict[CodeLocation, Set[Definition]] = defaultdict(set)
        self.tmp_uses: Dict[int, Set[CodeLocation]] = defaultdict(set)

    def set_state(self, state):
        """
        Sets a new state (for example, if the state has been branched)
        """
        self.state = state._get_weakref()

    @staticmethod
    def annotate_with_taint_tags(symvar: claripy.ast.Base, tags: Set[TaintTag]):
        # strip existing taint tag annotations
        annotations_to_remove = [ ]
        for anno in symvar.annotations:
            if isinstance(anno, TaintTagAnnotation):
                annotations_to_remove.append(anno)
        if annotations_to_remove:
            # l.debug(f"[DEBUG] remove annos: {annotations_to_remove}")
            symvar = symvar.remove_annotations(annotations_to_remove)
            # l.debug(f"[DEBUG] after remove, res annos: {VSLiveDefinitions.extract_taint_tags(symvar)}")
        # annotate with the new definition annotation
        # l.debug(f"[DEBUG] annotate with tags: {tags}")
        nvar = symvar.annotate(TaintTagAnnotation(tags))
        # l.debug(f"[DEBUG] annotated nvar: {nvar}, taints: {VSLiveDefinitions.extract_taint_tags(nvar)}")
        return nvar

    @staticmethod
    def extract_taint_tags(symvar: claripy.ast.Base) -> Set[TaintTag]:
        tags = set()
        for anno in symvar.annotations:
            if isinstance(anno, TaintTagAnnotation):
                # l.debug(f"[DEBUG] found anno: {anno}")
                tags.update(anno.taint_tags)
        return tags

    @staticmethod
    def annotate_with_abs_regions(symvar: claripy.ast.Base, regions: Set[AbstractRegion]):
        """
        Annotate the value with its abstract region domain knowledge.
        """
        annotations_to_move = []
        for anno in symvar.annotations:
            if isinstance(anno, AbsRegionAnnotation):
                annotations_to_move.append(anno)
        if annotations_to_move:
            symvar = symvar.remove_annotations(annotations_to_move)
        return symvar.annotate(AbsRegionAnnotation(regions))

    @staticmethod
    def extract_abs_regions(symvar: claripy.ast.Base) -> Set[AbstractRegion]:
        regions = set()
        for anno in symvar.annotations:
            if isinstance(anno, AbsRegionAnnotation):
                regions.update(anno.abs_regions)
        return regions

    @staticmethod
    def annotate_with_sem_constraints(symvar: claripy.ast.Base, constrs: Set[SemanticConstraint]):
        annotations_to_move = []
        for anno in symvar.annotations:
            if isinstance(anno, SemConstraintAnnotation):
                annotations_to_move.append(anno)
        if annotations_to_move:
            symvar = symvar.remove_annotations(annotations_to_move)
        return symvar.annotate(SemConstraintAnnotation(constrs))

    @staticmethod
    def extract_sem_constraints(symvar: claripy.ast.Base) -> Set[SemanticConstraint]:
        constrs = set()
        for anno in symvar.annotations:
            if isinstance(anno, SemConstraintAnnotation):
                constrs.update(anno.sem_constraints)
        return constrs

    @staticmethod
    def is_symbolic(expr: claripy.ast.Base) -> bool:
        """
        Check if the given expression is a symbolic value.
        TODO()
        :param expr:    The given expression.
        :return:        True if the expression is symbolic, False otherwise.
        """
        if isinstance(expr, int):
            return False
        # 1. constant variable (BVV)
        if not expr.symbolic or expr.op == "BVV":
            return False
        # 2. certain operations mean symbolic: LShR
        if expr.op in ["LShR", "__lshift__", "Concat", "Extract"]:
            return True
        #
        if VSLiveDefinitions.is_heap_address(expr) or VSLiveDefinitions.is_stack_address(expr):
            return False
        return True

    @staticmethod
    def extract_sym_var(expr: claripy.ast.Base) -> claripy.ast.Base:
        """
        Extract the symbol from the symbolic variable / expression.
        Note: symbolic expression could only be like a1 * S + b1, where a1 and b1 are concrete values.
        """
        if not VSLiveDefinitions.is_symbolic(expr):
            l.error(f"expr {expr} is not symbolic, cannot extract symbol.")
            return None

        return next(iter(filter(lambda x: x != "stack_base" and x != "heap_base", expr.variables)))

    @staticmethod
    def is_stack_address(addr: claripy.ast.Base) -> bool:
        # we should only get concrete stack offset address
        # otherwise, the address should be considered as symbolic address, rather than stack offset
        stack_base = "stack_base"
        valid_operations = ["__add__", "__sub__", "BVS"]
        if stack_base not in addr.variables or addr.op not in valid_operations:
            return False

        if addr.op == "BVS":
            return True
        else:
            if len(addr.args) > 2:
                return False
            if addr.args[0].op == "BVS" and addr.args[0].args[0] == stack_base\
                    and addr.args[1].op == "BVV":
                return True
            else:
                return False
        # return "stack_base" in addr.variables and \
        #        addr.op not in ["Concat", "LShR", "__lshift__", "Extract", "ZeroExt", "SignExt"]

    @staticmethod
    def is_heap_address(addr: claripy.ast.Base) -> bool:
        heap_base = "heap_base"
        valid_operations = ["__add__", "__sub__", "BVS"]
        if heap_base not in addr.variables or addr.op not in valid_operations:
            return False
        if addr.op == "BVS":
            return True

        else:
            if len(addr.args) > 2:
                return False
            if addr.args[0].op == "BVS" and addr.args[0].args[0] == heap_base\
                    and addr.args[1].op == "BVV":
                return True
            else:
                return False

    @staticmethod
    def get_stack_offset(addr: claripy.ast.Base) -> Optional[Union[int, claripy.ast.Base]]:
        # TODO(): we should only get concrete stack offset address
        # TODO(): otherwise, the address should be considered as symbolic address, rather than stack offset
        if "stack_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            elif addr.op == "__add__":
                if len(addr.args) == 2 and addr.args[1].op == "BVV":
                    return addr.args[1]._model_concrete.value
                if len(addr.args) == 2 and addr.args[1].op == "BVS":
                    return addr.args[1]
                if len(addr.args) > 2:
                    ops = claripy.simplify(addr).split(addr.op)
                    new_ops = list(filter(lambda x: "stack_base" in x.variables, ops))
                    return sum(new_ops)

                if len(addr.args) == 1:
                    return 0

            elif addr.op == "__sub__" and len(addr.args) == 2 and addr.args[1].op == "BVV":
                return -addr.args[1]._model_concrete.value
            elif addr.op == "__sub__" and len(addr.args) == 2:
                return -addr.args[1]
            else:
                from ..utils import simplify_ast
                simplify_ast(addr)
                raise NotImplementedError(addr.op, addr)

        return None

    def get_top(self, bits: int, atom: Optional[Atom]=None, assign_name=None, forece_top=False):
        """
        Get a TOP value.
        :param bits:    Width of the TOP value (in bits).
        :param forece_top: If true, return TOP
        :return:        The symbol value.
        """
        if forece_top:
            return claripy.BVS("TOP", bits, explicit_name=True)
        if assign_name is not None:

            # TODO():eval param selection
            str_current_depth = assign_name.count("[")
            max_symbol_reference = self.state.analysis.max_symbol_reference_depth
            if str_current_depth and str_current_depth >= max_symbol_reference:
                return claripy.BVS("TOP", bits, explicit_name=True)

            r = claripy.BVS(assign_name, bits, explicit_name=True)
            return r

        if atom is None:
            if bits in VSLiveDefinitions._tops:
                return VSLiveDefinitions._tops[bits]
            r = claripy.BVS("TOP", bits, explicit_name=True)
            VSLiveDefinitions._tops[bits] = r

        else:
            if isinstance(atom, Register):
                reg_name = abstract_to_register(atom.reg_offset, atom.size, self.project)
                if reg_name in VSLiveDefinitions._tops:
                    return VSLiveDefinitions._tops[reg_name]
                r = claripy.BVS(reg_name, bits, explicit_name=True)
                VSLiveDefinitions._tops[reg_name] = r

            elif isinstance(atom, MemoryLocation):
                # concrete
                if isinstance(atom.addr, SpOffset) and not atom.addr.symbolic:
                    offset = atom.addr.offset
                    posi = "+" if offset > 0 else ""
                    r = claripy.BVS(f"[stack_base{posi}{hex(offset)}]", bits, explicit_name=True)
            else:
                raise NotImplementedError
        return r

    def kill_and_add_definition(self, atom: Atom, code_loc: CodeLocation, data: VSMultiValues,
                                dummy=False, tags: Set[Tag] = None, endness=None,
                                annotated=False) -> Optional[VSMultiValues]:
        if data is None:
            raise TypeError("kill_and_add_definition() does not take None as data.")

        if annotated:
            d = data
        else:
            definition: Definition = Definition(atom, code_loc, dummy=dummy, tags=tags)
            d = VSMultiValues()
            # annotate with definitions and taint tags
            for offset, vs in data.values.items():
                for v in vs:
                    d.add_value(offset, self.annotate_with_def(v, definition))

        # set_object() replaces kill (not implemented) and add (add) in one step
        if isinstance(atom, Register):
            try:
                self.register_definitions.store(atom.reg_offset, d, size=atom.size, endness=endness)
            except :
                l.warning("Failed to store register definition %s at %d.", d, atom.reg_offset, exc_info=True)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                # store the concrete stack memory
                if atom.addr.offset is not None:
                    stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                    self.stack_definitions.store(stack_addr, d, size=atom.size, endness=endness)
                # store the symbolic memory
                elif atom.addr.offset is not None and atom.symbolic:
                    raise RuntimeError("Should not reach here.")
                else:
                    l.warning("Skip stack storing since the stack offset is None.")
            elif isinstance(atom.addr, HeapAddress):
                try:
                    self.heap_definitions.store(atom.addr.value, d, size=atom.size, endness=endness)
                except SimMemoryError:
                    # Not enough data for store, it's due to mismatch of data size during symbolic assignment
                    # we enlarge the data size?
                    print('dbg')
            elif isinstance(atom.addr, int):
                self.memory_definitions.store(atom.addr, d, size=atom.size, endness=endness)
            # symbolic memory address
            elif isinstance(atom.addr, claripy.ast.Base):
                if atom.addr.concrete:
                    self.memory_definitions.store(atom.addr._model_concrete.value, d, size=atom.size, endness=endness)
                else:
                    # store to symbolic memory address
                    regions = self.extract_abs_regions(atom.addr)
                    for sym_region in regions:
                        symaddr = sym_region.symbol_address()
                        self.symbolic_definitions.store(symaddr, d, atom.size)
                    return None
            else:
                return None
        elif isinstance(atom, Tmp):
            if self.track_tmps:
                self.tmps[atom.tmp_idx] = {definition}
            else:
                self.tmps[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
                return None
        else:
            raise NotImplementedError()

        return d

    def add_use(self, atom: Atom, code_loc: CodeLocation) -> None:
        if isinstance(atom, Register):
            self._add_register_use(atom, code_loc)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset) and not atom.symbolic:
                self._add_stack_use(atom, code_loc)
            elif isinstance(atom.addr, HeapAddress):
                self._add_heap_use(atom, code_loc)
            elif isinstance(atom.addr, int):
                self._add_memory_use(atom, code_loc)
            else:
                # (x) ignore RegisterOffset
                # pass
                # TODO()
                self._add_symbolic_use(atom, code_loc)
        elif isinstance(atom, Tmp):
            self._add_tmp_use(atom, code_loc)
        else:
            raise TypeError("Unsupported atom type %s." % type(atom))

    def stack_addr_to_stack_offset(self, addr) -> int:
        if self.arch.bits == 32:
            base_v = self.INITIAL_SP_32BIT
            mask = 0xffff_ffff
        elif self.arch.bits == 64:
            base_v = self.INITIAL_SP_64BIT
            mask = 0xffff_ffff_ffff_ffff
        else:
            raise ValueError("Unsupported architecture word size %d" % self.arch.bits)
        return addr - base_v

    def get_definitions(self, atom: Atom) -> Iterable[Definition]:
        if isinstance(atom, Register):
            try:
                values: VSMultiValues = self.register_definitions.load(atom.reg_offset, size=atom.size)
            except SimMemoryMissingError:
                return
            for vs in values.values.values():
                for v in vs:
                    yield from self.extract_defs(v)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset) and not atom.symbolic:
                stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                try:
                    mv: VSMultiValues = self.stack_definitions.load(stack_addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in mv.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            elif isinstance(atom.addr, HeapAddress):
                try:
                    mv: VSMultiValues = self.heap_definitions.load(atom.addr.value, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in mv.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            elif isinstance(atom.addr, int):
                try:
                    values = self.memory_definitions.load(atom.addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in values.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            else:
                # symbolic
                # TODO(): FIXME DEBUG
                print("DEBUG GET Symbolic Definition.")
                sym_addr = None
                if isinstance(atom.addr, claripy.ast.Base):
                    sym_addr = atom.addr
                elif isinstance(atom.addr, SpOffset) and isinstance(atom.addr.offset, claripy.ast.Base):
                    sym_addr = atom.addr.offset
                else:
                    return
                try:
                    values = self.symbolic_definitions.load(sym_addr, atom.size)
                except SimMemoryMissingError:
                    return
                return
        elif isinstance(atom, Tmp):
            if atom.tmp_idx in self.tmps:
                for tmp in self.tmps[atom.tmp_idx]:
                    yield tmp
            else:
                return
        else:
            raise TypeError()

    def copy(self) -> 'VSLiveDefinitions':
        rd = VSLiveDefinitions(self.arch, track_tmps=self.track_tmps, canonical_size=self._canonical_size,
                               register_definitions=self.register_definitions.copy(),
                               stack_definitions=self.stack_definitions.copy(),
                               heap_definitions=self.heap_definitions.copy(),
                               memory_definitions=self.memory_definitions.copy(),
                               symbolic_definitions=self.symbolic_definitions.copy(),
                               project=self.project,
                               state=self.state,
                               valueset_upperbound=self.valueset_upperbound
                               )

        rd.tmps = self.tmps.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.heap_uses = self.heap_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()

        return rd

    def merge(self, *others) -> Tuple['VSLiveDefinitions', bool]:

        state = self.copy()
        t0 = time.time()
        merge_occurred = state.register_definitions.merge([ other.register_definitions for other in others ], None)
        t1 = time.time()
        dbgLog("Finally taken %.3f'ms to merge registers." % (1000*(t1-t0)))
        try:
            merge_occurred |= state.heap_definitions.merge([other.heap_definitions for other in others], None)
        except:
            # FIXME: debug
            state2 = self.copy()
            merge_occurred |= state2.heap_definitions.merge([other.heap_definitions for other in others], None)
        t2 = time.time()
        dbgLog("Finally taken %.3f'ms to merge heaps." % (1000*(t2-t1)))
        merge_occurred |= state.memory_definitions.merge([other.memory_definitions for other in others], None)
        t3 = time.time()
        dbgLog("Finally taken %.3f'ms to merge memories." % (1000 * (t3-t2)))
        merge_occurred |= state.stack_definitions.merge([other.stack_definitions for other in others], None)
        t4 = time.time()
        dbgLog("Finally taken %.3f'ms to merge stacks." % (1000 * (t4-t3)))
        merge_occurred |= state.symbolic_definitions.merge([other.symbolic_definitions for other in others], None)
        t5 = time.time()
        dbgLog("Finally taken %.3f'ms to merge symbolics." % (1000*(t5-t4)))


        for other in others:
            other: VSLiveDefinitions

            merge_occurred |= state.register_uses.merge(other.register_uses)
            merge_occurred |= state.stack_uses.merge(other.stack_uses)
            merge_occurred |= state.heap_uses.merge(other.heap_uses)
            merge_occurred |= state.memory_uses.merge(other.memory_uses)

        return state, merge_occurred

    def __getstate__(self):
        s = {slot: getattr(self, slot) for slot in self.__slots__ if slot not in ('project', )}
        return s

    def __setstate__(self, state):
        for slot in state:
            setattr(self, slot, state[slot])

    def _add_symbolic_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:
        self.symbolic_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_symbolic_use(self, atom: MemoryLocation, code_loc: CodeLocation) -> None:

        # get all current definitions
        current_defs: Iterable[Definition] = self.get_definitions(atom)

        for current_def in current_defs:
            self._add_symbolic_use_by_def(current_def, code_loc)