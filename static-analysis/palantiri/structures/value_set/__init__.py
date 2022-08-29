import angr
import claripy
import logging
from claripy.simplifications import SimplificationManager
from .value_domains.taint_logic import TaintTag
from angr.knowledge_plugins.key_definitions.definition import Definition
from typing import Set, Iterable, Union, Optional

from .simmemory.vs_multivalues import VSMultiValues
from .value_domains.abstract_region import AbstractRegion
from ..utils import simplify_ast

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

SYM_MEM = "sym_mem"
SYMBOLIC_THRESHOLD = 50
DEFAULT_ALLOCA_SZ = 1024
simplify_manager = SimplificationManager()

SYMBOLICS = ['rax', 'eax', 'ax', 'al', 'ah',
             'rcx', 'ecx', 'cx', 'cl', 'ch',
             'rdx', 'edx', 'dx', 'dl', 'dh',
             'rbx', 'ebx', 'bx', 'bl', 'bh',
             'rsp', 'sp', 'esp',
             'rbp', 'bp', 'ebp', 'bpl', 'bph',
             'rsi', 'esi', 'si', 'sil', 'sih',
             'rdi', 'edi', 'di', 'dil', 'dih',
             'r8', 'r8d', 'r8w', 'r8b',
             'r9', 'r9d', 'r9w', 'r9b',
             'r10', 'r10d', 'r10w', 'r10b',
             'r11', 'r11d', 'r11w', 'r11b',
             'r12', 'r12d', 'r12w', 'r12b',
             'r13', 'r13d', 'r13w', 'r13b',
             'r14', 'r14d', 'r14w', 'r14b',
             'r15', 'r15d', 'r15w', 'r15b',
             ]


def register_to_offset(reg_name: str, project: angr.Project) -> int:
    try:
        offset, size = project.arch.registers[reg_name]
        return offset
    except KeyError:
        log.error(f"register {reg_name} is not a valid register name for the current arch.")
        raise KeyError()


def abstract_to_register(offset, size, project: angr.Project) -> str:
    # TODO() delete such heuristic
    if size in range(4, 8):
        offset = offset - (8 - size)
        size = 8

    for reg_name, abstract in project.arch.registers.items():
        off, sz = abstract
        if offset == off and size == sz:
            return reg_name

    return "??"
    raise ValueError(f"Abstract representation <offset {offset}, size {size}> is not a valid register.")


def simplify_vs(vs: VSMultiValues) -> VSMultiValues:
    nvs = VSMultiValues()
    for offset, d in vs.values.items():
        for v in d:
            origin_annos = v.annotations
            nv = simplify_ast(v)
            nv = nv.append_annotations(origin_annos)
            nvs.add_value(offset, value=nv)
    return nvs


def identical_ast(e1: claripy.ast.Base, e2: claripy.ast.Base) -> bool:
    """
    Determine whether or not two expressions are identical in **structural**.
    Since our VSA-expression result must be linear symbolic expression like a * v + b, where a and b are concrete value
    We only need to determine the structure.
    """
    e1s, e2s = claripy.simplify(e1), claripy.simplify(e2)
    if e1s.op != e2s.op or len(e1s.args) != len(e2s.args):
        # try to use z3 solver to solve that
        # if 0 in claripy.Solver().eval(e1s - e2s, 2):
        #     return True
        simplified = claripy.simplify(e1s - e2s)
        if simplified.op == "BVV" and simplified.args[0] == 0:
            return True
        return False
    e1s_sub, e2s_sub = e1s.split(e1s.op), e2s.split(e2s.op)
    e1s_subset, e2s_subset = set(e1s_sub), set(e2s_sub)
    if len(set(e1s_sub) - set(e2s_sub)) == 0:
        return True
    if len(e1s_sub) != len(e2s_sub):
        return False

    # recursively check
    diff_1, diff_2 = list(e1s_subset.difference(e2s_subset)), list(e2s_subset.difference(e1s_subset))
    if len(diff_1) != diff_2:
        return False
    idx1, idx2 = 0, 0
    while 1:
        if idx2 >= len(diff_2):
            return False

        if identical_ast(diff_1[idx1], diff_2[idx2]) is True:
            diff_1.pop(idx1)
            diff_2.pop(idx2)

            if len(diff_1) == 0 and len(diff_2) == 0:
                return True

            idx1, idx2, times = 0, 0, len(diff_2)
            continue

        idx2 += 1


def update_vals_taint_from_defs(state, values: 'VSMultiValues', definitions: Union[Definition, Iterable[Definition]]):
    # annotate with definitions and taint tags
    if isinstance(definitions, Definition):
        tags = definitions.tags
    else:
        tags = set()
        for definition in definitions:
            tags.update(definition.tags)

    taint_tags = set(filter(lambda x: isinstance(x, TaintTag), tags))

    if not len(taint_tags):
        return values

    d = VSMultiValues()
    for offset, vs in values.values.items():
        for v in vs:
            d.add_value(offset, state.annotate_with_taint_tags(v, taint_tags))
    return d


def update_regions_with_offset_and_op(regions: Set[AbstractRegion], offset: Union[int, claripy.ast.BV], op: str) \
        -> Set[Optional[AbstractRegion]]:
    if not regions:
        return set()

    def _MASK(x):
        return 2 ** x - 1

    if isinstance(offset, claripy.ast.BV):
        if not offset.concrete:
            raise TypeError(f"offset {offset} is not a constant value.")

        conc = offset._model_concrete.value
        sig_bit = conc >> (offset.size() - 1)
        if not sig_bit:
            # return conc
            # reserve its size in case of concat
            offset = conc
        else:
            offset = -((conc ^ _MASK(offset.size())) + 1)

    if op.lower().find("add") >= 0:
        res_regions = set(map(lambda x: x + offset, regions))
    elif op.lower().find("sub") >= 0:
        res_regions = set(map(lambda x: x - offset, regions))
    else:
        raise TypeError(f"Unsupported operation {op} on AbstractRegions.")
    return res_regions
