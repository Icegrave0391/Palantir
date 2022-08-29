from typing import Iterable, Tuple, Any, List, Optional, Set, Union, Callable, Dict
import time

from .vs_multivalues import VSMultiValues
from ...utils.symbol_utils import bv_to_str
from ...utils.anno_utils import *
import claripy
from misc.debugger import dbgLog
from angr import SimMemoryError
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.storage.memory_mixins import MultiValuedMemory
from angr.storage.memory_mixins.paged_memory.pages import MVListPage
from angr.storage.memory_object import SimMemoryObject
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

import logging
l = logging.getLogger(__name__)
l.setLevel(logging.WARNING)


class VSMVListPage(MVListPage):

    @classmethod
    def _compose_objects(cls, objects: List[List[Tuple[int, Set[SimMemoryObject]]]], size, endness=None,
                         memory=None, **kwargs):
        c_objects: List[Tuple[int, Union[SimMemoryObject, Set[SimMemoryObject]]]] = []
        for objlist in objects:
            for element in objlist:
                if not c_objects or element[1] is not c_objects[-1][1]:
                    c_objects.append(element)

        mask = (1 << memory.state.arch.bits) - 1
        elements: List[Set[claripy.ast.Base]] = []
        for i, (a, objs) in enumerate(c_objects):
            chopped_set = set()
            if not type(objs) is set:
                objs = {objs}
            for o in objs:
                if o.includes(a):
                    chopped = o.bytes_at(
                        a,
                        ((c_objects[i + 1][0] - a) & mask) if i != len(c_objects) - 1 else (
                                    (c_objects[0][0] + size - a) & mask),
                        endness=endness
                    )
                    chopped_set.add(chopped)
            if chopped_set:
                elements.append(chopped_set)

        if len(elements) == 0:
            # nothing is read out
            return VSMultiValues(offset_to_values={0: {claripy.BVV(0, 0)}})

        if len(elements) == 1:
            return VSMultiValues(offset_to_values={0: elements[0]})

        if endness == 'Iend_LE':
            elements = list(reversed(elements))

        mv = VSMultiValues()
        offset = 0
        start_offset = 0
        prev_value = ...
        for i, value_set in enumerate(elements):
            if len(value_set) == 1:
                if prev_value is ...:
                    prev_value = next(iter(value_set))
                    start_offset = offset
                else:
                    prev_value = prev_value.concat(next(iter(value_set)))
            else:
                if prev_value is not ...:
                    mv.add_value(start_offset, prev_value)
                    prev_value = ...

                for value in value_set:
                    mv.add_value(offset, value)

            offset += next(iter(value_set)).size() // memory.state.arch.byte_width

        if prev_value is not ...:
            mv.add_value(start_offset, prev_value)
            prev_value = ...

        # we should concat all the possibilities of mv
        if len(mv.values) > 1:
            # to mitigate the potential high overhead concatenating all possibilities of values, we should avoid some
            # complexity cases
            if mv.number_of_values() > 10:
                all_vals = mv.extract_all_values()
                vs_state = memory.state.state
                all_taints = get_taint_tags(vs_state, all_vals)
                mv = VSMultiValues(offset_to_values={0: {
                    vs_state.top(vs_state.arch.bytes * size)
                }})
                mv = update_vals_with_taint_tags(vs_state, mv, all_taints)
                # TODO(): do we need to consider those values regions again?
                all_regions = get_abs_regions(vs_state, all_vals)
                mv = update_vals_with_abs_regions(vs_state, mv, all_regions)
            else:
                concated_values = set()
                for k in sorted(mv.values.keys()):
                    if not len(concated_values):
                        concated_values = mv.values[k]
                    else:
                        new_concated_valus = set()
                        upper_values = mv.values[k]
                        for uv in upper_values:
                            for cv in concated_values:
                                new_concated_valus.add(uv.concat(cv))
                        concated_values = new_concated_valus
                mv = VSMultiValues(offset_to_values={0: concated_values})
        return mv

    def __init__(self, memory=None, content=None, sinkhole=None, mo_cmp=None, **kwargs):
        super().__init__(memory, content, sinkhole, mo_cmp, **kwargs)

    def erase(self, addr, size=None, **kwargs) -> None:
        for off in range(size):
            self.content[addr + off] = None

    def merge(self, others: List['VSMVListPage'], merge_conditions, common_ancestor=None, page_addr: int = None,
              memory=None, changed_offsets: Optional[Set[int]] = None):

        if changed_offsets is None:
            changed_offsets = set()
            for other in others:
                changed_offsets |= self.changed_bytes(other, page_addr)

        all_pages: List['VSMVListPage'] = [self] + others
        if merge_conditions is None:
            merge_conditions = [None] * len(all_pages)

        merged_to = None
        merged_objects = set()
        merged_offsets = set()
        for b in sorted(changed_offsets):
            if merged_to is not None and not b >= merged_to:
                l.info("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_objects = []
            unconstrained_in = []

            # first get a list of all memory objects at that location, and
            # all memories that don't have those bytes
            for sm, fv in zip(all_pages, merge_conditions):
                if sm._contains(b, page_addr):
                    l.info("... present in %s", fv)
                    for mo in sm.content_gen(b):
                        if mo.includes(page_addr + b):
                            memory_objects.append((mo, fv))
                else:
                    l.info("... not present in %s", fv)
                    unconstrained_in.append((sm, fv))

            if not memory_objects:
                continue

            mos = set(mo for mo, _ in memory_objects)
            mo_bases = set(mo.base for mo, _ in memory_objects)
            mo_lengths = set(mo.length for mo, _ in memory_objects)
            endnesses = set(mo.endness for mo in mos)

            if not unconstrained_in and not (mos - merged_objects):
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in and len(endnesses) == 1:
                the_endness = next(iter(endnesses))
                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                mo_length = memory_objects[0][0].length
                size = mo_length - (page_addr + b - mo_base)
                merged_to = b + size

                merged_val = self._merge_values(to_merge, mo_length, memory=memory)
                if merged_val is None:
                    # merge_values() determines that we should not attempt to merge this value
                    continue

                # do the replacement
                # TODO: Implement in-place replacement instead of calling store()
                # new_object = self._replace_memory_object(our_mo, merged_val, page_addr, memory.page_size)

                first_value = True
                for v in merged_val:
                    self.store(b,
                               {SimMemoryObject(v, mo_base, endness=the_endness)},
                               size=size,
                               cooperate=True,
                               weak=not first_value,
                               )
                    first_value = False

                merged_offsets.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of
                # the size of all memory objects and unallocated spaces.
                # for the case
                # if memory.id == "reg":
                #     min_size = 8   # TODO: now hard-code here :), set the mimial size as the register size for x64
                # else:
                min_size = min([mo.length - (b + page_addr - mo.base) for mo, _ in memory_objects])
                for um, _ in unconstrained_in:
                    for i in range(0, min_size):
                        if um._contains(b + i, page_addr):
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = [(mo.bytes_at(page_addr + b, min_size), fv) for mo, fv in
                             memory_objects] if min_size != 0 else []
                if not memory.skip_missing_values_during_merging:
                    created = [
                        (self._default_value(None, min_size, name="merge_uc_%s_%x" % (uc.id, b), memory=memory),
                         fv) for
                        uc, fv in unconstrained_in
                    ]
                    to_merge = extracted + created
                else:
                    to_merge = extracted

                merged_val = self._merge_values(to_merge, min_size, memory=memory)
                if merged_val is None:
                    continue

                first_value = True
                for v in merged_val:
                    try:
                        self.store(b,
                                   {SimMemoryObject(v, page_addr + b, endness='Iend_BE')},
                                   size=min_size,
                                   endness='Iend_BE',
                                   cooperate=True,
                                   weak=not first_value,
                                   )  # do not convert endianness again
                    except:
                        print('dbg')
                    first_value = False
                merged_offsets.add(b)

        self.stored_offset |= merged_offsets
        return merged_offsets

    def changed_bytes(self, other: 'VSMVListPage', page_addr: int = None):

        candidates: Set[int] = set()
        if self.sinkhole is None:
            candidates |= self.stored_offset
        else:
            for i in range(len(self.content)):
                if self._contains(i, page_addr):
                    candidates.add(i)

        if other.sinkhole is None:
            candidates |= other.stored_offset
        else:
            for i in range(len(other.content)):
                if other._contains(i, page_addr):
                    candidates.add(i)

        byte_width = 8  # TODO: Introduce self.state if we want to use self.state.arch.byte_width
        differences: Set[int] = set()
        for c in candidates:
            if c > 4095:
                break
            s_contains = self._contains(c, page_addr)
            o_contains = other._contains(c, page_addr)
            if not s_contains and o_contains:
                differences.add(c)
            elif s_contains and not o_contains:
                differences.add(c)
            else:
                try:
                    if self.content[c] is None:
                        if self.sinkhole is not None:
                            self.content[c] = SimMemoryObject(self.sinkhole.bytes_at(page_addr + c, 1), page_addr + c,
                                                              byte_width=byte_width, endness='Iend_BE')
                    if other.content[c] is None:
                        if other.sinkhole is not None:
                            other.content[c] = SimMemoryObject(other.sinkhole.bytes_at(page_addr + c, 1), page_addr + c,
                                                               byte_width=byte_width, endness='Iend_BE')
                    if s_contains and self.content[c] != other.content[c]:
                        same = None
                        if self._mo_cmp is not None:
                            same = self._mo_cmp(self.content[c], other.content[c], page_addr + c, 1)
                        if same is None:
                            # Try to see if the bytes are equal
                            self_bytes = {mo.bytes_at(page_addr + c, 1) for mo in self.content_gen(c)}
                            other_bytes = {mo.bytes_at(page_addr + c, 1) for mo in other.content_gen(c)}
                            same = self_bytes == other_bytes

                        if same is False:
                            differences.add(c)
                    else:
                        # this means the byte is in neither memory
                        pass
                except:
                    print(f'{c}')
        l.debug(f"other: {other} pageno: {divmod(page_addr, 4096)[0]}, other at mem2: {other.content[3664]}, page addr: {hex(page_addr)}, candidates: {candidates}, changed_bytes: {differences}")
        return differences


class VSMultiValuedMemory(MultiValuedMemory):
    PAGE_TYPE = VSMVListPage
    @property
    def category(self):
        """
        Return the category of this SimMemory instance. It can be one of the three following categories: reg, mem,
        or file.
        """
        if self.id in ('reg', 'mem', "stack"):
            return self.id

        elif self.id.startswith('file'):
            return 'file'

        elif '_' in self.id:
            return self.id.split('_')[0]

        else:
            raise SimMemoryError('Unknown SimMemory category for memory_id "%s"' % self.id)
    
    def load(self, addr, size=None, **kwargs):
        endness = kwargs.pop("endness", None)
        endness = endness if endness else self.state.arch.memory_endness
        return super(VSMultiValuedMemory, self).load(addr, size=size, endness=endness, **kwargs)
    
    def store(self, addr, data, size=None, **kwargs):
        """
        set a threshold for maximum date storage
        :return:
        """
        if isinstance(data, VSMultiValues):
            values = data.values[0]
            # TODO(): remove hard code
            # merge to top
            if len(values) > 15:
                v = claripy.BVS("TOP", size=size * self.state.arch.byte_width, explicit_name=True)
                vs_state: 'ValueSetState' = self.state.state
                taint_tags = get_taint_tags(vs_state, values)
                abs_regions = get_abs_regions(vs_state, values)
                definitions = list(vs_state.extract_defs(next(iter(values))))

                if len(definitions):
                    v = vs_state.annotate_with_def(v, definitions[0])
                v = vs_state.annotate_with_abs_regions(v, abs_regions)
                v = vs_state.annotate_with_taint_tags(v, taint_tags)

                data = VSMultiValues(offset_to_values={0: {v}})
        endness = kwargs.pop("endness", None)
        endness = endness if endness else self.state.arch.memory_endness
        super().store(addr, data, size, endness=endness, **kwargs)

    def merge(self, others: Iterable['VSMultiValuedMemory'], merge_conditions, common_ancestor=None) -> bool:
        changed_pages_and_offsets: Dict[int,Optional[Set[int]]] = {}
        for o in others:
            for changed_page, changed_offsets in self.changed_pages(o).items():
                if changed_offsets is None:
                    changed_pages_and_offsets[changed_page] = None
                else:
                    # changed_offsets is a set of offsets (ints)
                    if changed_page not in changed_pages_and_offsets:
                        # update our dict
                        changed_pages_and_offsets[changed_page] = changed_offsets
                    else:
                        # changed_page in our dict
                        if changed_pages_and_offsets[changed_page] is None:
                            # in at least one `other` memory can we not determine the changed offsets
                            # do nothing
                            pass
                        else:
                            # union changed_offsets with known ones
                            changed_pages_and_offsets[changed_page] = \
                                changed_pages_and_offsets[changed_page].union(changed_offsets)

        if merge_conditions is None:
            merge_conditions = [None] * (len(list(others)) + 1)

        merged_bytes = set()
        for page_no in sorted(changed_pages_and_offsets.keys()):
            l.debug("... on page %x", page_no)

            page = self._get_page(page_no, True)
            other_pages = [ ]

            for o in others:
                if page_no in o._pages:
                    other_pages.append(o._get_page(page_no, False))

            page_addr = page_no * self.page_size
            changed_offsets = changed_pages_and_offsets[page_no]
            l.debug(f"VSMVMemory merge page: {page_no}, all changed: {changed_pages_and_offsets}")
            merged_offsets = page.merge(other_pages, merge_conditions, page_addr=page_addr, memory=self,
                                        changed_offsets=changed_offsets)
            for off in merged_offsets:
                merged_bytes.add(page_addr + off)

        return bool(merged_bytes)

    def changed_pages(self, other) -> Dict[int,Optional[Set[int]]]:
        my_pages = set(self._pages)
        other_pages = set(other._pages)
        intersection = my_pages.intersection(other_pages)
        difference = my_pages.symmetric_difference(other_pages)

        changes: Dict[int,Optional[Set[int]]] = dict((d, None) for d in difference)

        for pageno in intersection:
            my_page = self._pages[pageno]
            other_page = other._pages[pageno]

            # FIXME: fix angr's sinkhole
            if isinstance(my_page.sinkhole, set):
                my_page.sinkhole = next(iter(my_page.sinkhole))
            if isinstance(other_page.sinkhole, set):
                other_page.sinkhole = next(iter(other_page.sinkhole))

            if (my_page is None) ^ (other_page is None):
                changes[pageno] = None
            elif my_page is None:
                pass
            else:
                changed_offsets = my_page.changed_bytes(other_page, page_addr=pageno * self.page_size)
                if changed_offsets:
                    changes[pageno] = changed_offsets
        try:
            l.debug(f"o: {other}, o.mem2: {other._pages[1654].content[3664]}, changed: {changes}")
        except:
            l.debug(f"o: {other}, o.mem2: {None}, changed: {changes}")
        return changes

    def erase(self, addr, size=None, **kwargs) -> None:
        if type(size) is not int:
            raise TypeError("Need size to be resolved to an int by this point")

        if type(addr) is not int:
            raise TypeError("Need addr to be resolved to an int by this point")

        pageno, pageoff = self._divide_addr(addr)
        max_pageno = (1 << self.state.arch.bits) // self.page_size
        bytes_done = 0
        while bytes_done < size:
            page = self._get_page(pageno, True, **kwargs)
            sub_size = min(self.page_size - pageoff, size - bytes_done)
            page.erase(pageoff, sub_size, memory=self, **kwargs)
            bytes_done += sub_size
            pageno = (pageno + 1) % max_pageno
            pageoff = 0

    def _default_value(self, addr, size, **kwargs):
        # TODO: Make _default_value() a separate Mixin
        # "merge_uc_%s_%x" % (uc.id, b)
        if kwargs.get("name", "").startswith("merge_uc_"):
            # this is a hack. when this condition is satisfied, _default_value() is called inside Listpage.merge() to
            # create temporary values. we simply return a TOP value here.
            sym_name = kwargs.get("name", "")
            # self.state: ValueSetState
            if self.id == "reg":
                reg_offset = int(sym_name.strip("merge_uc_").split("_")[-1], 16)
                reg = Register(reg_offset, size)
                val = self.state.get_top(size * self.state.arch.byte_width, reg)
                return self.state.annotate_with_def(val, Definition(reg, ExternalCodeLocation()))
            elif self.id == "stack":
                stack_addr = int(sym_name.strip("merge_uc_stack_").split("_")[0]) * self.page_size
                stack_addr += int(sym_name.strip("merge_uc_stack_").split("_")[-1], 16)
                stack_offset = self.state.stack_addr_to_stack_offset(stack_addr)
                sp = MemoryLocation(SpOffset(self.state.arch.bits, stack_offset), size)
                val = self.state.get_top(size * self.state.arch.byte_width, sp)
                return self.state.annotate_with_def(val, Definition(sp, ExternalCodeLocation()))
            return self.state.top(size * self.state.arch.byte_width)

        # we never fill default values for non-existent loads
        kwargs['fill_missing'] = False
        return super()._default_value(addr, size, **kwargs)

    def _merge_values(self, values: Iterable[Tuple[Any, Any]], merged_size: int, **kwargs):
        """
        Occurs at merge happened, here we should discard all the "same" values. Although it's a set(),
        all the values are claripy.BVS, thus we treat identical AST as same values.
        # TODO(): merge the annotations (taint)
        """
        t1 = time.time()
        vs_state: ValueSetState = self.state.state
        values_set: Set[claripy.ast.Base] = set(v for v, _ in values)
        cpy_valset = values_set.copy()
        if self._phi_maker is not None:
            phi_var = self._phi_maker(values_set)
            if phi_var is not None:
                return {phi_var}
        #
        # discard same values
        unique_value_dict = {}
        duplicate_keys = set()
        for val in values_set:
            # unique key is its linear symbolic expression
            val: claripy.ast.Base
            unique_k = bv_to_str(val)
            # add to unique dict
            if unique_k not in unique_value_dict.keys():
                unique_value_dict[unique_k] = val
            # merge the annotations
            else:
                duplicate_keys.add(unique_k)

        # merge those duplicate keys annotations
        for dup_k in duplicate_keys:
            duplicate_vals = list(filter(lambda v: bv_to_str(v) == dup_k, values_set))
            duplicate_taint_tags = get_taint_tags(vs_state, duplicate_vals)
            duplicate_abs_regions = get_abs_regions(vs_state, duplicate_vals)
            v = unique_value_dict[dup_k]
            v = vs_state.annotate_with_taint_tags(v, duplicate_taint_tags)
            v = vs_state.annotate_with_abs_regions(v, duplicate_abs_regions)
            unique_value_dict[dup_k] = v

        new_set = set(unique_value_dict.values())
        t2 = time.time()
        dbgLog("Taking %.3f'ms to merge value set %r." % (1000 * (t2 - t1), cpy_valset))
        # try to merge it in the traditional way
        if len(new_set) > self._element_limit:
            merged_val = {self._top_func(merged_size * self.state.arch.byte_width)}
        else:
            merged_val = new_set
        return merged_val