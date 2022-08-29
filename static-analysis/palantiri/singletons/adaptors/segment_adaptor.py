from palantiri.singletons.singleton_base import SingletonType
from palantiri.singletons.adaptors.adaptor_base import AdaptorBase
from palantiri.global_configs import *

from angr.knowledge_plugins.functions import Function
from typing import Tuple
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class SegmentAdaptor(AdaptorBase, metaclass=SingletonType):
    """
    Heuristic: To ensure each segment is only analyzed once.
    """
    def __init__(self):
        super(SegmentAdaptor, self).__init__()
        self.analyzed_segment_functions = []

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state):
        if caller.is_plt or callee.is_plt:
            return True

        if callee in self.rw_segment_functions:
            if callee not in self.analyzed_segment_functions:
                self.analyzed_segment_functions.append(callee)
                return True
            else:
                log.info(f"Segment Adaptor dismiss {caller.name} -> {callee.name} (callee segment already analyzed).")
                return False
        return True


segment_adaptor = SegmentAdaptor()