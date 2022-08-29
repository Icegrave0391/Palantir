import logging
import claripy
from claripy.annotation import Annotation
from typing import Optional

log = logging.getLogger(__name__)

log.setLevel(logging.DEBUG)
ARCH_BITS = 64


class AbstractType:
    Stack = "stack"
    Heap = "heap"
    Global = "global"
    Symbolic = "symbolic"


class AbstractRegion:
    """
    Abstract region is the domain knowledge of value used for memory addressing, and it could represent stack region,
    heap region and global region.
    """
    def __init__(self, region_type: str, region_offset: int, symbolic_base: Optional[str] = None):
        """
        :param region_type:   string of <stack, heap, global>
        :param region_offset:
        """
        self.type = region_type
        self.offset = region_offset
        self.symbolic_base = symbolic_base

    def symbol_address(self) -> str:
        """
        Convert the symbolic region to its address
        """
        if self.type != AbstractType.Symbolic:
            raise TypeError(f"{self} is not a symbolic region.")
        addr_repr = self.symbolic_base
        if self.offset > 0:
            addr_repr += f" + {hex(self.offset)}"
        elif self.offset == 0:
            pass
        else:
            addr_repr += f" - {hex(abs(self.offset))}"
        return addr_repr

    def to_claripy_symvar(self) -> claripy.ast.Base:
        """
        Convert the abstract region to a claripy's symbolic expression.
        The variable will be annotated with that abstract region.
        """
        if self.type == AbstractType.Global:
            symvar = claripy.BVV(self.offset, ARCH_BITS)
        elif self.type == AbstractType.Symbolic:
            symvar = claripy.BVS(self.symbolic_base, ARCH_BITS, explicit_name=True)
        else:
            symbase_name = "stack_base" if self.type == AbstractType.Stack else "heap_base"
            symvar = claripy.BVS(symbase_name, ARCH_BITS, explicit_name=True) + self.offset

        symvar = symvar.append_annotation(AbsRegionAnnotation({self}))
        return symvar

    def __hash__(self):
        return hash((self.type, self.offset, self.symbolic_base))

    def __eq__(self, other):
        if not isinstance(other, AbstractRegion):
            return False
        return self.type == other.type and self.offset == other.offset and self.symbolic_base == other.symbolic_base

    def __add__(self, other):
        if isinstance(other, int):
            # We don't support heap arith-operations, since each allocate size is the canonical size, and memcpy() is
            # also based on canonical size. Thus we should ensure the addressing for heap will constrained in its
            # boundary.
            # if self.type == AbstractType.Heap:
            #     return AbstractRegion(self.type, self.offset)
            if self.type == AbstractType.Symbolic:
                return AbstractRegion(self.type, self.offset + other, self.symbolic_base)
            else:
                return AbstractRegion(self.type, self.offset + other)
        else:
            raise TypeError(f"Operation type {type(other)} of abstractRegion is invalid. (Only support int operation.)")

    def __sub__(self, other):
        if isinstance(other, int):
            # if self.type == AbstractType.Heap:
            #     return AbstractRegion(self.type, self.offset)
            if self.type == AbstractType.Symbolic:
                return AbstractRegion(self.type, self.offset - other, self.symbolic_base)
            else:
                return AbstractRegion(self.type, self.offset - other)
        else:
            raise TypeError(f"Operation type {type(other)} of abstractRegion is invalid. (Only support int operation.)")

    def __repr__(self):
        if self.type != AbstractType.Symbolic:
            return f"<AbsRegion {self.type}: {hex(self.offset)}>"
        else:
            return f"<AbsRegion {self.type}: {self.symbol_address()}>"


class AbsRegionAnnotation(Annotation):

    __slots__ = ('abs_regions', )

    def __init__(self, regions):
        super().__init__()
        self.abs_regions = regions if regions is not None else set()

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __hash__(self):
        hashed = 0
        for region in self.abs_regions:
            hashed += hash(region)
        return hash((hashed, self.relocatable, self.eliminatable))

    def __eq__(self, other: 'AbsRegionAnnotation'):
        if not isinstance(other, AbsRegionAnnotation):
            return False
        return self.abs_regions == other.abs_regions \
            and self.relocatable == other.relocatable \
            and self.eliminatable == other.eliminatable

    def __repr__(self):
        return f"<AbsRegionAnno {self.abs_regions}>"