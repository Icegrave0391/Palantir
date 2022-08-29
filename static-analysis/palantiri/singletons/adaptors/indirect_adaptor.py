from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from misc.debugger import debug_print_log

from angr.knowledge_plugins.functions import Function
from typing import Optional, List
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class IndirectAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    The adaptor for handling indirect calls and jumps during binary analysis.
    """
    def __init__(self):
        super(IndirectAdaptor, self).__init__()

    def handle_indirect_call(self, caller: Function, callsite: int) -> List[Optional[str]]:
        caller_name = caller.name
        if caller_name in self.resolved_indirect_dict:
            if callsite in self.resolved_indirect_dict[caller_name]:
                
                calltarget_name_list = self.resolved_indirect_dict[caller_name][callsite]
                
                debug_print_log(self.pal_project, message=\
                    f"Indirect adaptor resolved indirect call targets for {caller.name}'s \
                      callsite {hex(callsite)}: {calltarget_name_list}",
                    logger=log, min_vlevel=1)

                return calltarget_name_list
        return list()


indirect_adaptor = IndirectAdaptor()