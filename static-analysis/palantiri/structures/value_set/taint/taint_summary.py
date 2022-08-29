from collections import defaultdict
from typing import Dict, Set, TYPE_CHECKING, Union, Iterable, Tuple
from functools import cmp_to_key
import claripy

from ..value_domains.taint_logic import TaintTag
from ...utils.symbol_utils import bv_to_str
from ...value_set import register_to_offset, abstract_to_register
from ...key_definitions import GENERAL_REGS_x64
from ....syscalls import syscall_analysis_table
from misc.debugger import dbgLog
if TYPE_CHECKING:
    from ....analyses.binary_summary import BinarySummary
from palantiri.cfg.cfgtest import *


class TaintType:
    REG = 1
    STACK = 2
    HEAP = 3
    GLB = 4
    SYM = 5
    SYSCALL = 6


LOOKUP_FMT = {
    TaintType.REG: "register",
    TaintType.STACK: "stack",
    TaintType.HEAP: "heap",
    TaintType.GLB: "memory",
    TaintType.SYM: "symbol",
    TaintType.SYSCALL: "syscall"
}


def sysname_to_number(sys_name):
    for k in syscall_analysis_table.keys():
        if sys_name == syscall_analysis_table[k]:
            return k
    return None


UNDEFINED_TAG = TaintTag(metadata={"tagged_by": "undefined",
                                   "tagged_tp": "undefined",
                                   "tagged_off": 0,
                                   "tagged_sz": 0}
                         )


def default_tag() -> Set:
    return {UNDEFINED_TAG}


class TaintSummary:
    # TODO(): Do not LOAD / STORE : rsp, rbp, non GRs
    def __init__(self, project: angr.Project, analysis: 'BinarySummary', default_tags=None):
        self.project = project
        self.analysis = analysis
        default_tg = default_tags if default_tags is not None else default_tag
        self.reg_taint_summary: Dict[int, Set[TaintTag]] = defaultdict(default_tg)
        self.mem_taint_summary: Dict[int, Set[TaintTag]] = defaultdict(default_tg)
        self.stack_taint_summary: Dict[int, Set[TaintTag]] = defaultdict(default_tg)
        self.heap_taint_summary: Dict[int, Set[TaintTag]] = defaultdict(default_tg)
        self.symbol_taint_summary: Dict[str, Set[TaintTag]] = defaultdict(default_tg)
        self.syscall_taint_summary: Dict[int, Set[TaintTag]] = defaultdict(default_tg)

        self._state_defined = {
            TaintType.REG: set(),
            TaintType.STACK: set(),
            TaintType.GLB: set(),
            TaintType.HEAP: set(),
            TaintType.SYM: set(),
            TaintType.SYSCALL: set()
        }

        self._state_used = {
            TaintType.REG: set(),
            TaintType.STACK: set(),
            TaintType.GLB: set(),
            TaintType.HEAP: set(),
            TaintType.SYM: set(),
            TaintType.SYSCALL: set()
        }

        self._type_map = {
            TaintType.REG: self.reg_taint_summary,
            TaintType.GLB: self.mem_taint_summary,
            TaintType.STACK: self.stack_taint_summary,
            TaintType.HEAP: self.heap_taint_summary,
            TaintType.SYM: self.symbol_taint_summary,
            TaintType.SYSCALL: self.syscall_taint_summary
        }

    def _adjust_stack_offset(self, offset):
        return offset - self.analysis._init_stack_offset

    def _initialize_initial_reg_taint(self):
        # initialize register taint summary
        for reg in GENERAL_REGS_x64:
            reg_offset = register_to_offset(reg, self.project)
            self.store(taint_type=TaintType.REG, offset=reg_offset, data={TaintTag(metadata={"tagged_by": reg})})

    def _offset_already_in_set(self, taint_def_or_use_set, offset):
        for off, sz in taint_def_or_use_set:
            if off == offset:
                return True
        return False

    def load(self, taint_type: int, offset: Union[int, claripy.ast.Base, str], size: int = 8, adjust_stack=True) \
            -> Set[TaintTag]:
        load_region = self._type_map[taint_type]
        tags = set()
        # adjust stack offset
        already_adjusted = False
        if (taint_type == TaintType.STACK and adjust_stack):
            offset = self._adjust_stack_offset(offset)
            already_adjusted = True

        if taint_type != TaintType.SYM and taint_type != TaintType.SYSCALL:

            if taint_type == TaintType.REG and offset >= 144:  # TODO(): refine this magic-number,skip all non GRs
                return tags

            for i in range(offset, offset + size):

                byte_tags = load_region[i]

                # do lazy initialize
                if UNDEFINED_TAG in byte_tags:
                    # try to find max undefined size

                    uninitialized_off = i
                    uninitialized_sz = 1
                    for x in range(i + 1, offset + size):
                        if UNDEFINED_TAG in load_region[x]:
                            uninitialized_sz += 1
                        else:
                            break

                    if taint_type == TaintType.STACK:
                        byte_tags = {TaintTag(metadata={"tagged_by": f"stack base{uninitialized_off}",
                                                        "tagged_tp": "stack",
                                                        "tagged_off": uninitialized_off,
                                                        "tagged_sz": uninitialized_sz,
                                                        }
                                              )}
                    elif taint_type == TaintType.REG:
                        if uninitialized_sz in range(4, 8):
                            uninitialized_off -= (8 - uninitialized_sz)
                            uninitialized_sz = 8
                        byte_tags = {TaintTag(metadata={"tagged_by": \
                                                            f"{abstract_to_register(uninitialized_off, uninitialized_sz, self.project)}",
                                                        "tagged_tp": "register",
                                                        "tagged_off": uninitialized_off,
                                                        "tagged_sz": uninitialized_sz,
                                                        }
                                              )}

                    elif taint_type == TaintType.GLB:
                        byte_tags = {TaintTag(metadata={"tagged_by": hex(uninitialized_off),
                                                        "tagged_tp": "memory",
                                                        "tagged_off": uninitialized_off,
                                                        "tagged_sz": uninitialized_sz,
                                                        }
                                              )}
                    elif taint_type == TaintType.HEAP:
                        byte_tags = {TaintTag(metadata={"tagged_by": f"heap base{uninitialized_off}",
                                                        "tagged_tp": "heap",
                                                        "tagged_off": uninitialized_off,
                                                        "tagged_sz": uninitialized_sz
                                                        }
                                              )}
                    self.store(taint_type, uninitialized_off, data=byte_tags, size=uninitialized_sz,
                               adjust_stack=False, set_state_defined=False)

                tags.update(byte_tags)

            if self._offset_already_in_set(self._state_used[taint_type], offset):
                for used_off, used_sz in self._state_used[taint_type]:
                    if used_off == offset and size > used_sz:
                        self._state_used[taint_type].remove((used_off, used_sz))
                        self._state_used[taint_type].add((offset, size))
            else:
                self._state_used[taint_type].add((offset, size))

        elif taint_type == TaintType.SYM:
            if isinstance(offset, claripy.ast.Base):
                offset = bv_to_str(offset)
            byte_tags = load_region[offset]
            if UNDEFINED_TAG in byte_tags:
                byte_tags = {TaintTag(metadata={"tagged_by": f"{offset}",
                                                "tagged_tp": "symbol",
                                                "tagged_off": offset,
                                                "tagged_sz": 1
                                                }
                                      )}
                self.store(TaintType.SYM, offset, data=byte_tags,
                           adjust_stack=False, set_state_defined=False)

            tags.update(byte_tags)
            self._state_used[TaintType.SYM].add((offset, 1))
        else:
            byte_tags = load_region[offset]
            if UNDEFINED_TAG in byte_tags:
                byte_tags = {TaintTag(metadata={"tagged_by": f"{syscall_analysis_table[offset]}",
                                                "tagged_tp": "syscall",
                                                "tagged_off": offset,
                                                "tagged_sz": 0
                                                }
                                      )}
                self.store(TaintType.SYSCALL, offset, data=byte_tags,
                           adjust_stack=False, set_state_defined=False)

            tags.update(byte_tags)
            self._state_used[TaintType.SYM].add((offset, 1))
        return tags

    def store(self, taint_type: int, offset: Union[int, claripy.ast.Base, str], data: Set[TaintTag], size: int = 8,
              adjust_stack=True, set_state_defined=True):
        store_region = self._type_map[taint_type]
        if taint_type == TaintType.STACK and adjust_stack:
            offset = self._adjust_stack_offset(offset)
        # # FIXME: DBG
        # for d in data:
        #     if isinstance(d, ParameterTag):
        #         log.debug("aaaa")
        if taint_type != TaintType.SYM and taint_type != TaintType.SYSCALL:
            # store at a continuous region
            for i in range(offset, offset + size):
                store_region[i] = data

            if set_state_defined:
                if self._offset_already_in_set(self._state_defined[taint_type], offset):
                    for defined_off, defined_sz in self._state_defined[taint_type]:
                        if defined_off == offset and size > defined_sz:
                            self._state_defined[taint_type].remove((defined_off, defined_sz))
                            self._state_defined[taint_type].add((offset, size))
                else:
                    self._state_defined[taint_type].add((offset, size))
        elif taint_type == TaintType.SYM:
            if isinstance(offset, claripy.ast.Base):
                offset = bv_to_str(offset)
            store_region[offset] = data
            if set_state_defined:
                self._state_defined[TaintType.SYM].add((offset, 1))
        else:
            store_region[offset] = data
            if set_state_defined:
                self._state_defined[TaintType.SYSCALL].add((offset, 0))

    def copy(self):
        ts: 'TaintSummary' = TaintSummary(self.project, self.analysis)
        for k, v in self.reg_taint_summary.items():
            ts.reg_taint_summary[k] = v
        for k, v in self.stack_taint_summary.items():
            ts.stack_taint_summary[k] = v
        for k, v in self.heap_taint_summary.items():
            ts.heap_taint_summary[k] = v
        for k, v in self.mem_taint_summary.items():
            ts.mem_taint_summary[k] = v
        for k, v in self.symbol_taint_summary.items():
            ts.symbol_taint_summary[k] = v
        for k, v in self.syscall_taint_summary.items():
            ts.syscall_taint_summary[k] = v

        ts._state_defined[TaintType.REG] = self._state_defined[TaintType.REG].copy()
        ts._state_defined[TaintType.STACK] = self._state_defined[TaintType.STACK].copy()
        ts._state_defined[TaintType.GLB] = self._state_defined[TaintType.GLB].copy()
        ts._state_defined[TaintType.HEAP] = self._state_defined[TaintType.HEAP].copy()
        ts._state_defined[TaintType.SYM] = self._state_defined[TaintType.SYM].copy()
        ts._state_defined[TaintType.SYSCALL] = self._state_defined[TaintType.SYSCALL].copy()

        ts._state_used[TaintType.REG] = self._state_used[TaintType.REG].copy()
        ts._state_used[TaintType.STACK] = self._state_used[TaintType.STACK].copy()
        ts._state_used[TaintType.GLB] = self._state_used[TaintType.GLB].copy()
        ts._state_used[TaintType.HEAP] = self._state_used[TaintType.HEAP].copy()
        ts._state_used[TaintType.SYM] = self._state_used[TaintType.SYM].copy()
        ts._state_used[TaintType.SYSCALL] = self._state_used[TaintType.SYSCALL].copy()
        return ts

    def _merge_taint_summary_map(self, *summary_maps: Dict):
        """
        Merge taint_summary_map
        """
        nmap = defaultdict(default_tag)
        key_set = set()
        for mp in summary_maps:
            key_set.update(mp.keys())
        for nk in key_set:
            vset: Set[TaintTag] = set()
            for mp in summary_maps:
                vset.update(mp[nk])
            try:
                vset.remove(UNDEFINED_TAG)
            except KeyError:
                pass
            nmap[nk] = vset
        return nmap

    def _merge_taint_defuse_set(self, *def_or_use_sets: Set[Tuple]) -> Set:
        res_set = set()
        for aset in def_or_use_sets:
            res_set.update(aset)

        def find_duplicate_key(tset: Iterable[Tuple]):
            seen = set()
            seen_add = seen.add
            # adds all elements it doesn't know yet to seen and all other to seen_twice
            seen_twice = set(x[0] for x in tset if x[0] in seen or seen_add(x[0]))
            # turn the set into a list (as requested)
            return list(seen_twice)

        dup_offs = find_duplicate_key(res_set)
        for dup_off in dup_offs:
            dup_elems = sorted(filter(lambda elem: elem[0] == dup_off, res_set),
                               key=cmp_to_key(lambda x, y: 1 if x[1] > y[1] else -1))
            elems_to_remove = dup_elems[:-1]
            res_set = res_set - set(elems_to_remove)

        return res_set

    def merge(self, *others) -> 'TaintSummary':
        state = self.copy()
        # merge taint tags
        to_merges = list(others) + [self]
        state.reg_taint_summary = self._merge_taint_summary_map(*[m.reg_taint_summary for m in to_merges])
        state.stack_taint_summary = self._merge_taint_summary_map(*[m.stack_taint_summary for m in to_merges])
        state.heap_taint_summary = self._merge_taint_summary_map(*[m.heap_taint_summary for m in to_merges])
        state.symbol_taint_summary = self._merge_taint_summary_map(*[m.symbol_taint_summary for m in to_merges])
        state.mem_taint_summary = self._merge_taint_summary_map(*[m.mem_taint_summary for m in to_merges])
        state.syscall_taint_summary = self._merge_taint_summary_map(*[m.syscall_taint_summary for m in to_merges])
        # merge used and defined
        for k, taint_type in TaintType.__dict__.items():
            if k.startswith("_"):
                continue
            state._state_used[taint_type] = self._merge_taint_defuse_set(
                *[m._state_used[taint_type] for m in to_merges]
            )
            state._state_defined[taint_type] = self._merge_taint_defuse_set(
                *[m._state_defined[taint_type] for m in to_merges]
            )
        return state

    def base_to_update_region_with_taints(self, taints: Set[TaintTag], taint_type: int, offset, size, adjust_stack=False):
        """
        Use self's taint summary as the base state, and do update on other's taint summary.
        To update a region (described by taint_type, offset, size)'s taints from the base state's taints.
        We do not directly update such region, instead, we treat the region to update as a transaction. We should
        only update when commit the transaction.
        e.g. base state, taint of heap 0: reg 72

            to update: type: xx, offset: xx, size: xx, taints: {heap 0}
            after update: type: xx, offset: xx, size: xx, taints: {reg 72}
        """
        new_taint_set = set()
        # 1. check the taints' dependency, from the current taints
        if len(taints) == 0:
            # in the case of updated taints is empty, it's a clear operation
            pass
        else:
            for taint in taints:
                # tagged by external functions, thus we treat it's a taint, not to look up and update
                if taint.function is not None:
                    new_taint_set.add(taint)
                    continue
                tainted_type = taint.metadata["tagged_tp"]
                tainted_off = taint.metadata["tagged_off"]
                if tainted_type == "register":
                    lookup_type = TaintType.REG
                    tainted_sz = taint.metadata["tagged_sz"]
                elif tainted_type == "memory":
                    lookup_type = TaintType.GLB
                    tainted_sz = taint.metadata["tagged_sz"]
                elif tainted_type == "stack":
                    lookup_type = TaintType.STACK
                    tainted_sz = taint.metadata["tagged_sz"]
                elif tainted_type == "heap":
                    lookup_type = TaintType.HEAP
                    tainted_sz = taint.metadata["tagged_sz"]
                elif tainted_type == "symbol":  # symbolic
                    lookup_type = TaintType.SYM
                    tainted_sz = 1
                else:  # syscall
                    lookup_type = TaintType.SYSCALL
                    tainted_sz = 1
                new_taint_set.update(self.load(lookup_type, tainted_off, tainted_sz, adjust_stack=adjust_stack))
        # do not store here, just mark as to_store
        # self.store(taint_type, offset, data=new_taint_set, size=size, adjust_stack=adjust_stack)
        to_update_transaction = {(taint_type, offset, size): new_taint_set}
        return new_taint_set, to_update_transaction

    def _commit_transaction(self, transaction_dict, adjust_stack=False, weak_update=False):
        for trans_key, data in transaction_dict.items():
            taint_type, offset, size = trans_key

            if weak_update:
                data: Set[TaintTag] = data | self.load(taint_type, offset, size, adjust_stack=adjust_stack)
            self.store(taint_type, offset, data=data, size=size, adjust_stack=adjust_stack)

    def standardize(self, *others):
        """
        Since standardize usually happens in a same function, due to the normalize of control flow,
        there is no need to adjust stack, as those stack base are identical.
        """
        taint_summary = self.copy()
        # if self.analysis._subject.content.name == "read_response_body":
        #     print('dbg')
        for other in others:
            other: TaintSummary
            to_update_transaction = {}
            # 1. update reg defined
            for reg_offset, reg_sz in other._state_defined[TaintType.REG]:
                updated_taints = other.load(TaintType.REG, reg_offset, reg_sz)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.REG,
                                                                               reg_offset, reg_sz, adjust_stack=False)
                to_update_transaction.update(to_update)
            # 2. update stack defined
            for stack_off, stack_sz in other._state_defined[TaintType.STACK]:
                updated_taints = other.load(TaintType.STACK, stack_off, stack_sz, adjust_stack=False)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.STACK,
                                                                               stack_off, stack_sz, adjust_stack=False)
                to_update_transaction.update(to_update)
            # 3. update heap defined
            for heap_off, heap_sz in other._state_defined[TaintType.HEAP]:
                updated_taints = other.load(TaintType.HEAP, heap_off, heap_sz)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.HEAP,
                                                                               heap_off, heap_sz)
                to_update_transaction.update(to_update)
            # 4. update memory defined
            for mem_off, mem_sz in other._state_defined[TaintType.GLB]:
                updated_taints = other.load(TaintType.GLB, mem_off, mem_sz)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.GLB,
                                                                               mem_off, mem_sz)
                to_update_transaction.update(to_update)
            # 5. update symbolic defined
            for sym_off, sym_sz in other._state_defined[TaintType.SYM]:
                updated_taints = other.load(TaintType.SYM, sym_off)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.SYM,
                                                                               sym_off, None)
                to_update_transaction.update(to_update)
            # 6. update syscall defined
            for sys_off, _ in other._state_defined[TaintType.SYSCALL]:
                updated_taints = other.load(TaintType.SYSCALL, sys_off)
                _, to_update = taint_summary.base_to_update_region_with_taints(updated_taints, TaintType.SYSCALL,
                                                                               sys_off, None)
                to_update_transaction.update(to_update)

            # FIXME: DEBUG
            # print(f"standard base: {taint_summary._dbg()}")
            # print(f"Standard other: {other._dbg()}")
            # commit transactions
            taint_summary._commit_transaction(to_update_transaction, adjust_stack=False)
            # print(f"after update: {taint_summary._dbg()}")
        return taint_summary

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k not in ("project", "analysis")}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.project = None
        self.analysis = None

    def _dbg(self):
        reg_defined = self._state_defined[TaintType.REG]
        stack_defined = self._state_defined[TaintType.STACK]
        heap_defined = self._state_defined[TaintType.HEAP]
        mem_defined = self._state_defined[TaintType.GLB]
        sym_defined = self._state_defined[TaintType.SYM]
        sys_defined = self._state_defined[TaintType.SYSCALL]

        print("=== TAINT SUMMARY, Registers ===")
        for reg_off, reg_size in reg_defined:
            if reg_off not in list(map(lambda x: register_to_offset(x, self.project), GENERAL_REGS_x64)):
                continue
            print(f"{abstract_to_register(reg_off, 8, self.project)}: {self.load(TaintType.REG, reg_off, reg_size)}")

        print("=== TAINT SUMMARY, Stacks ===")
        for stack_off, size in stack_defined:
            dem = "-" if stack_off < 0 else ""
            print(f"{dem}{hex(abs(stack_off))}: {self.load(TaintType.STACK, stack_off, size, adjust_stack=False)}")

        print("=== TAINT SUMMARY, Heaps ===")
        for heap_off, size in heap_defined:
            print(f"{hex(heap_off)}: {self.load(TaintType.HEAP, heap_off, size)}")

        print("=== TAINT SUMMARY, Memorys ===")
        for memoff, size in mem_defined:
            print(f"{hex(memoff)}: {self.load(TaintType.GLB, memoff, size)}")

        print("=== TAINT SUMMARY, Symbolics ===")
        for symoff, _ in sym_defined:
            print(f"{symoff}: {self.load(TaintType.SYM, symoff)}")

        print("=== TAINT SUMMARY, Syscalls ===")
        for sysoff, _ in sys_defined:
            print(f"{sysoff}: {self.load(TaintType.SYSCALL, sysoff)}")
