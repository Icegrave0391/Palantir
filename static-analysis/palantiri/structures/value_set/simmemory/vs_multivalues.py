from collections import Set
from typing import Callable, Iterable, Dict, Optional
from functools import cmp_to_key
import logging

import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class VSMultiValues(MultiValues):

    def __init__(self, offset_to_values=None):
        self.values: Dict[int, ASTSet[claripy.ast.Base]] = {}
        if offset_to_values is not None:
            for offset, val_set in offset_to_values.items():
                if isinstance(val_set, set):
                    self.values[offset] = ASTSet(val_set)
                elif isinstance(val_set, ASTSet):
                    self.values[offset] = val_set
                else:
                    raise TypeError("Each value in offset_to_values must be a set or a ASTSet!")

    def number_of_values(self):
        num = 0
        for off, vals in self.values.items():
            for val in vals:
                num += 1
        return num

    def extract_all_values(self):
        all_vals = set()
        for off, vals in self.values.items():
            all_vals.update(vals)
        return all_vals


    def add_value(self, offset, value) -> None:
        if offset not in self.values:
            self.values[offset] = ASTSet([])
        self.values[offset].add(value)

    def one_value(self) -> Optional[claripy.ast.Base]:
        if len(self.values) == 1 and len(self.values[0]) > 1:
            log.warning(f"Multiple values occured: {self.values[0]}, trying to get one value.")
            return next(iter(self.values[0]))
        if len(self.values) == 1 and len(self.values[0]) == 1:
            return next(iter(self.values[0]))
        return None

    def min_sp_value(self) -> Optional[claripy.ast.Base]:
        """
        Should only be used for getting min SP value
        """
        if len(self.values) == 1 and len(self.values[0]) == 1:
            return next(iter(self.values[0]))

        def extract_offset(a: claripy.ast.Base):
            if "sub" in a.op:
                return -a.args[1]._model_concrete.value
            elif "add" in a.op:
                return a.args[1]._model_concrete.value
            else:
                raise NotImplementedError

        def cmp_sp_val(a: claripy.ast.Base, b: claripy.ast.Base):
            # symbolic SP is the least value
            if len(a.args) > 2:
                return -1
            elif len(b.args) > 2:
                return 1
            # both concrete
            elif extract_offset(a) < extract_offset(b):
                return -1
            elif extract_offset(a) > extract_offset(b):
                return 1
            else:
                return 0

        values = sorted(list(self.values[0]), key=cmp_to_key(cmp_sp_val))
        log.debug(f"Try to get minimal SP value: {values[0]}")
        return values[0]

    def __len__(self) -> int:
        max_offset = max(self.values.keys())
        max_len = max(x.size() for x in self.values[max_offset])
        return max_offset * 8 + max_len  # FIXME: we are assuming byte_width of 8

    def merge(self, mv: 'VSMultiValues') -> 'VSMultiValues':
        new_mv = VSMultiValues(offset_to_values=self.values)
        assert len(new_mv.values.keys()) == 1
        assert len(mv.values.keys()) == 1

        for off, vs in mv.values.items():
            if off not in new_mv.values:
                new_mv.values[off] = vs
            else:
                new_mv.values[off] |= vs
        return new_mv

    def __repr__(self):
        if len(self.values):
            return f"<VSMultiValues {self.values[0]}>"
        return f"<VSMultiValues [Empty]>"

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiValues):
            return False
        if set(self.values.keys()) != set(other.values.keys()):
            return False
        for k in self.values.keys():
            if self.values[k] != other.values[k]:
                return False
        return True


def _build_variant(cls, opname):
    fn = getattr(cls, opname)
    # sanity check
    if not isinstance(fn, Callable):
        raise TypeError(f"{fn} must be function type.")

    def method(self, other, fn=fn):
        if not isinstance(other, Set):
            other = self._from_iterable(other)
        return fn(self, other)

    return method


class ASTSet(Set):
    """
    A set adapted for symbolic variables.
    Since claripy.ast.Base did not implement __bool__() function, the traditional way of adding symbolic value to
    set will fail when hash collusion occurs.
    The correct way to implement symbolic value set is to use claripy.ast.cache_key as unique keys (refer to angr's
    slack channel), thus we use key based set.
    """
    # named methods
    intersection = _build_variant(Set, '__and__')
    union = _build_variant(Set, '__or__')
    difference = _build_variant(Set, '__sub__')
    symmetric_difference = _build_variant(Set, '__xor__')
    issubset = _build_variant(Set, '__le__')
    issuperset = _build_variant(Set, '__ge__')
    _hash = _build_variant(Set, '_hash')

    def __init__(self, iterable: Iterable[claripy.ast.Base], key=lambda c: c.cache_key):
        self._items = dict((key(item), item) for item in iterable)
        self._key = key

    # Implementation of abstract methods from Set ABC
    def add(self, elem):
        """ Add an element to the set """
        k = self._key(elem)
        if k not in self._items:
            self._items[k] = elem

    def discard(self, elem):
        """ Remove an element """
        k = self._key(elem)
        try:
            del self._items[k]
        except KeyError:
            pass

    def clear(self):
        self._items.clear()

    def copy(self):
        return ASTSet(self._items.values(), key=self._key)

    def _from_iterable(self, iterable):
        return ASTSet(iterable, key=self._key)

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k != "_key"}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._key = lambda c: c.cache_key

    def __iter__(self):
        return iter(self._items.values())

    def __contains__(self, value):
        try:
            k = self._key(value)
        except KeyError:
            return False
        return k in self._items

    def __len__(self):
        return len(self._items)

    def __hash__(self):
        return self._hash(self._items.keys())

    def __repr__(self):
        return f"{list(self._items.values())}"
