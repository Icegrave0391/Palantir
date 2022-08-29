import claripy
from typing import Dict, Union

from palantiri.singletons.singleton_base import SingletonType
from palantiri.structures.utils.symbol_utils import bv_to_str


class SymbolMemDict(metaclass=SingletonType):

    def __init__(self):
        self.global_symmem_dict: Dict[int, str] = {0: "TOP"}
        self._symmem_uuid = 1

    def symbol_to_uuid(self, expr: Union[str, claripy.ast.Base]):
        """
        Assign a unique uuid for the symbolic memory entry address.
        :param expr: symbolic memory address
        :return it's uuid
        """
        expr_str = bv_to_str(expr) if isinstance(expr, claripy.ast.Base) else expr
        # first look up the global symbolic memory dict
        if expr_str in self.global_symmem_dict.values():
            return list(self.global_symmem_dict.keys())[list(self.global_symmem_dict.values()).index(expr_str)]
        # assign uuid and add to memory dict
        assign_uuid = self._symmem_uuid
        self.global_symmem_dict[assign_uuid] = expr_str
        self._symmem_uuid += 1
        return assign_uuid

    def setup_from_other(self, other: 'SymbolMemDict'):
        self.global_symmem_dict = other.global_symmem_dict
        self._symmem_uuid = other._symmem_uuid

    def reset(self):
        self.global_symmem_dict: Dict[int, str] = {0: "TOP"}
        self._symmem_uuid = 1


global_symmem_dict = SymbolMemDict()
