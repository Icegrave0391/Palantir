from typing import Union, Iterable, Set, TYPE_CHECKING, Optional

import claripy.ast
from angr.knowledge_plugins.key_definitions.tag import Tag
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from palantiri.structures.value_set.value_domains.taint_logic import TaintTag
from palantiri.structures.value_set.simmemory.vs_multivalues import VSMultiValues

from palantiri.structures.value_set.value_domains.abstract_region import AbstractRegion, AbsRegionAnnotation, \
    AbstractType
from palantiri.structures.value_set.value_domains.semantic_record import SemanticConstraint, ConstraintType
if TYPE_CHECKING:
    from palantiri.structures.value_set.vs_state import ValueSetState


def get_taint_tags(state, iter_values: Union[MultiValues, Iterable[MultiValues], Iterable[claripy.ast.Base]]) \
        -> Set[TaintTag]:
    if not state.taint_summary:
        return set()

    all_vals = set()
    all_tags: Set[Tag] = set()
    if isinstance(iter_values, MultiValues):
        all_vals.update(iter_values.values[0])
    elif len(iter_values):
        if isinstance(next(iter(iter_values)), MultiValues):
            for v in iter_values:
                all_vals.update(v.values[0])
        else:
            all_vals.update(iter_values)
    else:
        return set()
    # all_defs: Set[Definition] = set()
    for val in all_vals:
        try:
            all_tags.update(state.extract_taint_tags(val))
        except:
            print("???")
            
    taint_set = set(filter(lambda x: isinstance(x, TaintTag), all_tags))
    return taint_set


def get_abs_regions(state, iter_values: Union[MultiValues, Iterable[MultiValues], Iterable[claripy.ast.Base]]) \
        -> Set[AbstractRegion]:
    # 1. extract all expressions
    all_vals = set()
    if isinstance(iter_values, MultiValues):
        all_vals.update(iter_values.values[0])
    elif len(iter_values):
        if isinstance(next(iter(iter_values)), MultiValues):
            for v in iter_values:
                all_vals.update(v.values[0])
        else:
            all_vals.update(iter_values)
    else:
        return set()
    # extract regions
    all_regions: Set[AbstractRegion] = set()
    for val in all_vals:
        all_regions.update(state.extract_abs_regions(val))
    return all_regions


def get_sem_constraints(state: 'ValueSetState',
                        iter_values: Union[MultiValues, Iterable[MultiValues], Iterable[claripy.ast.Base]]) \
        -> Set[SemanticConstraint]:
    # 1. extract all expressions
    all_vals = set()
    if isinstance(iter_values, MultiValues):
        all_vals.update(iter_values.values[0])
    elif len(iter_values):
        if isinstance(next(iter(iter_values)), MultiValues):
            for v in iter_values:
                all_vals.update(v.values[0])
        else:
            all_vals.update(iter_values)
    else:
        return set()
    # extract constrs
    all_constrs: Set[SemanticConstraint] = set()
    for val in all_vals:
        all_constrs.update(state.extract_sem_constraints(val))
    return all_constrs


def _annotate_values_with_taint(state: 'ValueSetState', values: VSMultiValues, taint_type, offset, size,
                                store_taint_set: Optional[Set[TaintTag]]=None) -> VSMultiValues:
    """
    Update the valueset's taint tags from a state's taint region. If store_taint_set is set, then
    such such taint tag set will be stored to the state's relevant taint region.
    :param taint_type: (describe state's taint region)
    :param offset: (describe state's taint region)
    :param size:   (describe state's taint region)
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
        # no need to update values again, since those tags are extracted from values
        # values = update_vals_with_taint_tags(self.state, values, store_taint_set)
        state.taint_summary.store(taint_type, offset, data=store_taint_set, size=size)
    return values


def update_vals_with_taint_tags(state, values: 'VSMultiValues', taint_tags: Set[TaintTag]) -> 'VSMultiValues':
    """
    Simply update the valueset's taint tags with the provided taint tags
    """
    if not state.taint_summary or not len(taint_tags):
        return values

    d = VSMultiValues(offset_to_values=None)
    for offset, vs in values.values.items():
        for v in vs:
            nv = state.annotate_with_taint_tags(v, taint_tags)
            d.add_value(offset, nv)
    return d


def update_vals_with_abs_regions(state: 'ValueSetState', values: 'VSMultiValues', abs_regions: Set[AbstractRegion]) \
        -> 'VSMultiValues':
    d = VSMultiValues(offset_to_values=None)
    for offset, vs in values.values.items():
        for v in vs:
            nv = state.annotate_with_abs_regions(v, abs_regions)
            d.add_value(offset, nv)
    return d


def update_vals_with_sem_constraints(state: 'ValueSetState', values: 'VSMultiValues', constrs: Set[SemanticConstraint])\
        -> 'VSMultiValues':
    d = VSMultiValues(offset_to_values=None)
    for offset, vs in values.values.items():
        for v in vs:
            nv = state.annotate_with_sem_constraints(v, constrs)
            d.add_value(offset, nv)
    return d


def get_values_under_constraints(state: 'ValueSetState', values: 'VSMultiValues', constr: SemanticConstraint):
    nv = VSMultiValues()
    for offset, vs in values.values.items():
        for v in vs:
            if constr in state.extract_sem_constraints(v):
                nv.add_value(offset, v)
    if not len(nv.values):
        nv = values
    return nv
