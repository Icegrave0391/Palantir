from .function_summary import FunctionSummary
from angr import Project

import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

OP_BEFORE = 0
OP_AFTER = 1

# switch angr's archinfo to our protocal
# this class is unimportant to the static analysis 

class PAL_ISA:
    """
    PAL_ISA is the protocal of register definition for communication between Palantir's static-analysis and provenance-analysis.
    Based on the protocal, each register is (from angr.Project.arch.registers) translated to another unique ID.
    """
    @classmethod
    def register_to_id(cls, project: Project, offset, size):

        # TODO(): now hardcode some unused regsisters
        if offset == 56 and size < 4: # ebp
            size = 4

        reg_list = list(project.arch.registers.values())
        ordered_list = list(set(reg_list))
        ordered_list.sort(key=reg_list.index)
        try:
            idx = ordered_list.index((offset, size))
        except ValueError:
            idx = None
        return idx

    @classmethod
    def register_dep(cls, project: Project, reg_id):
        reg_list = list(project.arch.registers.values())
        ordered_list = list(set(reg_list))
        ordered_list.sort(key=reg_list.index)
        try:
            reg_off, reg_sz = ordered_list[reg_id]
        except IndexError:
            log.error(f"Invalid register id {reg_id}.")
            return None

        dep_list = [reg_id]
        while reg_sz // 2:
            reg_sz = reg_sz // 2
            dep_idx = PAL_ISA.register_to_id(project, reg_off, reg_sz)
            if dep_idx is not None:
                dep_list.append(dep_idx)

        if len(dep_list) > 1:
            next_idx = PAL_ISA.register_to_id(project, reg_off + 1, 1)
            if next_idx is not None:
                dep_list.append(next_idx)
        return dep_list