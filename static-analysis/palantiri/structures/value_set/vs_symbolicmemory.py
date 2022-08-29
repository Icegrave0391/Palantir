import claripy
from angr.errors import SimMemoryMissingError

from typing import Callable, Dict, Any, Union, Iterable
from palantiri.cfg.cfgtest import *
from ..utils import resize_bvs, simplify_ast
from palantiri.singletons.global_symdict import global_symmem_dict
from .simmemory.vs_multivalues import VSMultiValues

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def _get_addr_key(addr: Union[claripy.ast.Base, int, str]):
    """
    Turn the symbolic address into uuid key
    """
    if isinstance(addr, int):
        return addr
    return global_symmem_dict.symbol_to_uuid(addr)


class SymbolicMemory:

    def __init__(self, memory_id="sym", top_func=None, skip_missing_values_during_merging=False, page_kwargs=None):
        self.id = memory_id
        self._top_func: Callable = top_func
        # this dict is used to simulate symbolic memory addresses
        self._memory: Dict[int, Union[VSMultiValues, Any]] = {0: VSMultiValues(offset_to_values={0: {
            claripy.BVS("TOP", 64, explicit_name=True)}
        })}
        self._solver = claripy.Solver()

    def set_state(self, state):
        """
        Sets a new state (for example, if the state has been branched)
        """
        self.state = state._get_weakref()

    def load(self, addr: Union[claripy.ast.Base, int, str], size: int=None, endness=None, **kwargs):
        if size is None:
            raise TypeError("Must provide size to load")
        elif type(size) is int:
            out_size = size
        elif getattr(size, 'op', None) == 'BVV':
            out_size = size.args[0]
        else:
            raise Exception("Size must be concretely resolved by this point in the memory stack")

        k = _get_addr_key(addr)
        if k not in self._memory.keys():
            raise SimMemoryMissingError(addr, size, f"{addr} is not in SymbolicAddress")
        values: VSMultiValues = self._memory[k]
        # resize value
        d = VSMultiValues()
        for off, vs in values.values.items():
            for v in vs:
                if v.symbolic:
                    nv = resize_bvs(v, out_size * self.state.arch.byte_width)
                    nv = nv.append_annotations(v.annotations)
                    d.add_value(off, value=nv)
                elif v.size() > out_size * self.state.arch.byte_width:
                    nv = simplify_ast(v[out_size * self.state.arch.byte_width - 1: 0])
                    nv = nv.append_annotations(v.annotations)
                    d.add_value(off, value=nv)
                elif v.size() < out_size * self.state.arch.byte_width:
                    nv = simplify_ast(v.zero_extend(out_size * self.state.arch.byte_width - v.size()))
                    nv = nv.append_annotations(v.annotations)
                    d.add_value(off, value=nv)
                else:
                    d.add_value(off, v)
        return d

    def store(self, addr: Union[claripy.ast.Base, int, str], data, size: int=None, endness=None, **kwargs):
        max_size = len(data) // self.state.arch.byte_width
        if size is None:
            out_size = max_size
        elif type(size) is int:
            out_size = size
        elif getattr(size, 'op', None) == 'BVV':
            out_size = size.args[0]
        else:
            raise Exception("Size must be concretely resolved by this point in the memory stack")

        if out_size > max_size:
            # resize data
            d = VSMultiValues()
            for off, vs in data.values.items():
                for v in vs:
                    if v.size() < out_size * self.state.arch.byte_width:
                        if v.symbolic:
                            nv = resize_bvs(v, out_size * self.state.arch.byte_width)
                            nv = nv.append_annotations(v.annotations)
                        else:
                            nv = simplify_ast(v.zero_extend(out_size * self.state.arch.byte_width - v.size()))
                            nv = nv.append_annotations(v.annotations)
                        d.add_value(off, value=nv)
                    else:
                        d.add_value(off, v)
            data = d
        if out_size == 0:
            # skip zero-sized stores
            return
        k = _get_addr_key(addr)
        # we do not actually store a TOP memory
        if k == 0:
            return
        self._memory[k] = data

    def assign_symbolic(self, addr: Union[claripy.ast.Base, int], size, force_top=True) -> claripy.ast.Base:
        """
        :param force_top: If true, return a TOP value
        """
        if force_top:
            return claripy.BVS("TOP", size, explicit_name=True)
        str_addr = None
        if isinstance(addr, int):
            str_addr = hex(addr)
        else:
            str_addr = str(addr).strip("<BV" + str(addr.size())).strip(">").strip()

            str_current_depth = str_addr.count("[")
            max_symbol_reference = self.state.state.analysis.max_symbol_reference_depth
            if str_current_depth >= max_symbol_reference:
                return claripy.BVS("TOP", size, explicit_name=True)
        return claripy.BVS("["+str_addr+"]", size, explicit_name=True)

    def merge(self, others: Iterable['SymbolicMemory'], merge_conditions, common_ancestor=None) -> bool:
        merged = False
        for o in others:
            for addr, cont in o._memory.items():
                if addr not in self._memory.keys():
                    self._memory[addr] = cont
                    merged = True
                else:
                    if self._memory[addr] != cont:
                        merged = True
                        for offset, vs in cont.values.items():
                            for v in vs:
                                self._memory[addr].add_value(offset, v)
        return merged

    def copy(self) -> 'SymbolicMemory':
        symem = SymbolicMemory(self.id, self._top_func)
        # copy memory
        for addr, cont in self._memory.items():
            d = VSMultiValues()
            for offset, vs in cont.values.items():
                for v in vs:
                    d.add_value(offset, v)
            symem._memory[addr] = d
        return symem
