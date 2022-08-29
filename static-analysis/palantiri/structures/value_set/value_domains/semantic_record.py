import logging
from claripy.annotation import Annotation
from typing import Optional, Union
from angr.knowledge_plugins.key_definitions.atoms import Register
from .abstract_region import AbstractRegion
log = logging.getLogger(__name__)

log.setLevel(logging.DEBUG)
ARCH_BITS = 64


class ConstraintType:
    LoadFromRegion = "LoadFrom",
    GetFromReg = "GetFrom",


class SemanticConstraint:
    """
    Semantic Constraint is to increase the accuracy in performing the static analysis, and mitigate the false positive
    in taint propagation.
    # TODO(): now its only used for optimizing LOAD & STORE pattern, e.g. add [rax + 1], rbx
    # which in pseu-IR code is:
    # t1 <- Get[rax] + 1,  t2 <- Load[t1], t3 <- Get[rbx], Store[t1] <- t2 + t3 (false positive in value-set computation)
    """
    def __init__(self, constr_type, constr_value: Optional[Union[AbstractRegion, Register]]):
        if not isinstance(constr_value, AbstractRegion) and not isinstance(constr_value, Register):
            raise AssertionError(f"Wrong constraint value {constr_value} type.")
        self.constr_type = constr_type
        self.constr_value = constr_value

    def __hash__(self):
        return hash((self.constr_type, self.constr_value))

    def __eq__(self, other):
        if not isinstance(other, SemanticConstraint):
            return False
        return self.constr_type == other.constr_type and self.constr_value == other.constr_value

    def __repr__(self):
        return f"<SemanticConstraint {self.constr_type}: {self.constr_value}>"


class SemConstraintAnnotation(Annotation):
    __slots__ = ('sem_constraints', )

    def __init__(self, constraints):
        super().__init__()
        self.sem_constraints = constraints if constraints is not None else set()

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __hash__(self):
        hashed = 0
        for constr in self.sem_constraints:
            hashed += hash(constr)
        return hash((hashed, self.relocatable, self.eliminatable))

    def __eq__(self, other: 'SemConstraintAnnotation'):
        if not isinstance(other, SemConstraintAnnotation):
            return False
        return self.sem_constraints == other.sem_constraints \
            and self.relocatable == other.relocatable \
            and self.eliminatable == other.eliminatable

    def __repr__(self):
        return f"<SemConstraintAnno {self.sem_constraints}>"