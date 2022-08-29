from typing import TYPE_CHECKING
from collections import deque

from palantiri.structures.value_set.vs_subject import VSSubject
from palantiri.cfg.callgraph import CGNode
import logging

from angr.project import Project
from angr.knowledge_plugins.functions import Function

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class ContextExplorer:
    """
    Explore all possible calling contexts and dump to db.
    """
    def __init__(self, pal_project: 'PalProject'):
        self.pal_project: 'PalProject' = pal_project
        self.project: Project = pal_project.angr_project
        self._current_call_stack = []

    @property
    def cfg(self):
        return self.pal_project.cfg_util.cfg

    @property
    def callgraph(self):
        return self.pal_project.callgraph

    def explore(self, start_function=None):
        """
        Explore the calling contexts from function 'main' in a worklist style
        """
        log.info(f"Starting to explore binary calling contexts...")
        if not start_function:
            start_function = self.project.kb.functions["main"]
        # initialize task queue
        task_queue = deque( [(start_function, cs) for cs in start_function.get_call_sites()] )
        task_function = start_function
        valid_context_num = 0
        # start analysis
        while task_queue:

            _, callsite = task_queue.popleft()
            target_addr = task_function.get_call_target(callsite)

            try:
                target_func = self.project.kb.functions[target_addr]
                u, v = CGNode(task_function.addr, task_function), CGNode(target_addr, target_func)
                if (u, v) not in self.callgraph.graph.edges:
                    log.warning(f"{task_function.name} -> {target_func.name} is contradict with CallGraph.")
            except:
                # did not get callee function, pass the analysis on this context
                continue
            target_subj = VSSubject(self.project, target_func)

            # update global context
            if not self._push_context(task_function, callsite):
                continue
            # dump to db
            self.pal_project.redis_kb.store_empty_context(callsites=self.call_stack,
                                                          nodes=target_subj.refined_func_graph.nodes)
            log.debug(f"Explored valid target_func: {target_func.name} under context: {self.context_repr()}")
            valid_context_num += 1
            # next-iteration explore
            next_callsites = target_func.get_call_sites()
            if not next_callsites:
                task_function = self._pop_context(task_queue)
                continue

            task_queue.extendleft( [(target_func, cs) for cs in next_callsites] )
            task_function = target_func

        log.info(f"Totally explored {valid_context_num} contexts.")

    @property
    def call_stack(self):
        return [cs for _, cs in self._current_call_stack]

    def context_repr(self):
        ctx_str = ""
        for _f, _ in self._current_call_stack:
            ctx_str = ctx_str + f"{_f.name} -> "
        return ctx_str

    def _push_context(self, func, callsite):
        # dismiss loop call or recursive calls
        if (func, callsite) in self._current_call_stack:
            return 0
        self._current_call_stack.append( (func, callsite) )
        return 1

    def _pop_context(self, queue: deque) -> Function:
        if not queue:
            self._current_call_stack.clear()

        queue_task_func = queue[0][0]

        while self._current_call_stack[-1][0] != queue_task_func:
            self._current_call_stack.pop()
        self._current_call_stack.pop()
        return queue_task_func






