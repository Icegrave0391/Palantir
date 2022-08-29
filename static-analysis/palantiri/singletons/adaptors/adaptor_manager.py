import networkx as nx
import logging
from typing import Tuple, Iterable, Optional, Dict, List, TYPE_CHECKING
from palantiri.global_configs import callgraph_whitelist_starts
from palantiri.global_configs import *
from palantiri.cfg.cfg_util import CFGAnalysis
from palantiri.cfg.callgraph import CallGraphAcyclic, CGNode

from misc.debugger import debug_print_log

import angr

from angr.knowledge_plugins.functions import Function

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# FIXME DEBUG
from misc.visualize import V


class AdaptorManager:
    """
    The manager for inter procedural adaptors.
    """
    def __init__(self):
        self.adaptors = []
        self.pal_project: Optional['PalProject'] = None
        self.project: Optional[angr.Project] = None
        self.callgraph: Optional[CallGraphAcyclic] = None
        self.pruned_callgraph: Optional[CallGraphAcyclic] = None

        self.syscall_slice_graph: Optional[CallGraphAcyclic] = None

        self._syscall_slice_functions = []
        self._sysread_slice_functions = []
        self._syswrite_slice_functions = []
        self.rw_segment_functions: Optional[List[Function]] = None    # each entry for read + write segment
        self.whole_segment_functions: Optional[List[Function]] = None # entries for all rw segments
        self.resolved_indirect_dict: Optional[Dict] = None
        self.resolve_indirect = False

    def register_adaptors(self, adaptors: Iterable):
        for adaptor in adaptors:
            self.adaptors.append(adaptor)

    def set_interface(self, interface):
        """
        Set up for the analysis interface
        :param interface:
        :return:
        """
        self.pal_project = interface._pal_project
        self.project = interface.project
        self.callgraph = interface.callgraph_acyclic
        # 1. complete call graph from indirect dict
        # try to search enforce indirect dict as resolved indirect dict
        enforce_dict = search_indirect_enforce_list(self.pal_project)
        if enforce_dict:
            self.resolved_indirect_dict = enforce_dict
            self._enrich_callgraph()
        # pre prune the call graph
        self.pruned_callgraph: CallGraphAcyclic = self._prune_callgraph()
        # 2. make syscall slice graph
        self._generate_syscall_slice_graph()
        # 3. generate read & write segments
        self._generate_rw_segments()
        if not interface.without_whole_segment:
            self.generate_whole_segment(self.rw_segment_functions)

    def setup_adaptors(self):
        for adaptor in self.adaptors:
            adaptor.set_from_manager(self)

    @property
    def syscall_slice_functions(self):
        if not self._syscall_slice_functions:
            if not self.syscall_slice_graph:
                log.warning(f"Should set interface first.")
                return []
            for node in self.syscall_slice_graph.nodes:
                self._syscall_slice_functions.append(node.func)
        return self._syscall_slice_functions

    @property
    def sysread_slice_functions(self):
        if not self._sysread_slice_functions:
            self._generate_sysread_slice_functions()
        return self._sysread_slice_functions

    @property
    def syswrite_slice_functions(self):
        if not self._syswrite_slice_functions:
            self._generate_syswrite_slice_functions()
        return self._syswrite_slice_functions

    @property
    def start_functions(self):
        if self.whole_segment_functions:
            return [next(iter(self.whole_segment_functions))]
        return self.rw_segment_functions

    def handle_inter_procedure(self, caller: Function, callee: Function, call_context: Tuple[int], caller_state) -> \
            bool:
        """
        Use the adaptors' handles to determine whether or not to handle inter procedure call
        """
        all_res = True

        # apply whitelist filter first 
        if callee.name in search_binary_function_whitelist(self.project):
            debug_print_log(self.pal_project, message=\
                            f"Function: {callee.name} is in whitelist.",
                            min_vlevel=1, logger=log)
            return True
        
        # apply the adaptors
        for adaptor in filter(lambda ada: ada.adaptor_activate, self.adaptors):
            adaptor_class = adaptor.__class__
            adaptor_base_class = adaptor_class.__base__
            if getattr(adaptor_class, "handle_inter_procedure") is getattr(adaptor_base_class, "handle_inter_procedure"):
                continue

            handler = getattr(adaptor, "handle_inter_procedure")
            res = handler(caller, callee, call_context, caller_state)
            # TODO(): remove sockforce_adaptor, since its only a heuristic for wget
            # if res and hasattr(adaptor, "force_guide_graph") and adaptor.adaptor_activate:
            #     return True
            all_res &= res
        return all_res

    def handle_indirect_call(self, caller: Function, callsite: int) -> List[Optional[str]]:
        """
        Use the adaptors' handlers to resolve indirect call targets
        """
        handled_targets = []
        for adaptor in self.adaptors:
            adaptor_class = adaptor.__class__
            adaptor_base_class = adaptor_class.__base__
            if getattr(adaptor_class, "handle_indirect_call") is getattr(adaptor_base_class, "handle_indirect_call"):
                continue
            handled_targets.extend(getattr(adaptor, "handle_indirect_call")(caller, callsite))
        return list(set(handled_targets))

    def update_resolved_dict(self, resolved_dict: Dict[int, Dict]):
        """
        Update the resolved indirect callsite-calltargets dict
        """
        # first try to use enforce dict
        enforce_dict = search_indirect_enforce_list(self.pal_project)
        if enforce_dict:
            self.resolved_indirect_dict = enforce_dict
            return

        # filter out the non-interesting callers from whitelist_graph
        func_to_remove = search_binary_indirect_blacklist(self.project)
        for fname in func_to_remove:
            try:
                func = self.project.kb.functions[fname]
                fnode = CGNode(func.addr, func)
                self.syscall_slice_graph.graph.remove_node(fnode)
            except:
                continue

        # filter out non-interesting callers
        remove_k = []
        all_blacklist_func_names = search_binary_all_blacklists(self.project)
        for caller_addr in resolved_dict.keys():
            if self.project.kb.functions[caller_addr].name in all_blacklist_func_names:
                remove_k.append(caller_addr)
        for k in remove_k:
            resolved_dict.pop(k)

        # filter out non-interesting resolved results from dict
        for caller_addr, callsite_and_tar_map in resolved_dict.items():
            for cs, targets in callsite_and_tar_map.items():
                target_to_remove = []
                targets: list
                for target in targets:
                    if self.project.kb.functions[target].name in all_blacklist_func_names:
                        target_to_remove.append(target)
                for tar in target_to_remove:
                    targets.remove(tar)

        # filter out rule-based blacklist indirect results from dict
        indirect_result_rules = search_binary_indirect_rule_blacklists(self.project)
        for caller_addr, callsite_and_tar_map in resolved_dict.items():
            for cs, targets in callsite_and_tar_map.items():
                target_to_remove = []
                targets: list
                for target in targets:
                    target_name = self.project.kb.functions[target].name
                    for rule in indirect_result_rules:
                        if target_name.find(rule) >= 0:
                            target_to_remove.append(target)
                            break
                for tar in target_to_remove:
                    targets.remove(tar)
        self.resolved_indirect_dict = resolved_dict

    def _enrich_callgraph(self):
        """
        Enrich the call graph with the resolved results of indirect calls
        """
        if not self.resolved_indirect_dict:
            return

        enrich_dump_path = os.path.join(self.pal_project.arg_info.binary_output_path,
                                        "callgraph_acyclic_enriched_model.dump")
        if os.path.exists(enrich_dump_path):
            self.callgraph = CallGraphAcyclic(self.pal_project, None, force_dump_path=enrich_dump_path)
            return

        for caller_name, vmap in self.resolved_indirect_dict.items():
            caller = self.project.kb.functions[caller_name]
            for callsite, calltargets in vmap.items():
                for tar_name in calltargets:
                    callee = self.project.kb.functions[tar_name]
                    self.callgraph.add_edge(CGNode(caller.addr, caller), CGNode(callee.addr, callee), callsite)
        # ensure the call graph is acyclic
        self.callgraph = CallGraphAcyclic(self.pal_project, self.callgraph.graph, force_dump_path=enrich_dump_path)

    def _prune_callgraph(self, prune_isolated=True) -> CallGraphAcyclic:
        """
        Prune un-interesting functions in call graph
        """
        # prune the insensitive functions from callgraph
        log.info(f"Pruning the callgraph for analysis of adaptor: {self}...")
        prune_graph = self.callgraph.graph.copy()
        
        # 1. prune binary blacklist
        func_to_remove = search_binary_function_blacklist(self.project)
        log.info(f"Round 0: Pruned blacklist functions: {func_to_remove}")
        for fname in func_to_remove:
            try:
                func = self.project.kb.functions[fname]
                fnode = CGNode(func.addr, func)
                prune_graph.remove_node(fnode)
            except:
                continue
        # 2. prune external rule based blacklist
        rules = search_binary_rule_blacklist(self.project)
        nodes_to_remove = list(filter(lambda n: any(n.func.name.find(rule) >= 0 for rule in rules),
                                      prune_graph.nodes))
        log.info(f"Round 0.1: Pruned rule based blacklist functions: {nodes_to_remove}")
        try:
            prune_graph.remove_nodes_from(nodes_to_remove)
        except:
            pass
        # 3. since we've already pruned the functions from the heuristic rules, we further prune out all those
        #    unreachable functions.
        if prune_isolated:
            prune_graph.remove_nodes_from(list(nx.isolates(prune_graph)))
            isolated_nodes = set(filter(lambda node: node.func.name not in callgraph_whitelist_starts
                                                     and not prune_graph.in_edges(node),
                                        prune_graph.nodes))
            _round = 1
            while isolated_nodes:
                prune_graph.remove_nodes_from(isolated_nodes)
                log.info(f"Round {_round}: Pruned isolated nodes: {isolated_nodes}...")
                isolated_nodes = set(filter(
                    lambda node: node.func.name not in callgraph_whitelist_starts and not prune_graph.in_edges(node),
                    prune_graph.nodes
                ))
                _round += 1
        
        return CallGraphAcyclic(self.pal_project, prune_graph, force_generate=True)

    def _generate_syscall_slice_graph(self):
        rw_transitive_closure = CFGAnalysis.syscall_function_whitelist(self.project, self.pruned_callgraph,
                                                                       self.pal_project._cfg_util.cfg,
                                                                       function_keys=["read", "write", "send", "recv"],
                                                                       add_indirect=False)
        self.syscall_slice_graph = CallGraphAcyclic(self.pal_project, graph=rw_transitive_closure, force_generate=True)

    def _generate_sysread_slice_functions(self):
        read_transitive_closure = CFGAnalysis.syscall_function_whitelist(self.project, self.pruned_callgraph,
                                                                         self.pal_project._cfg_util.cfg,
                                                                         function_keys=["read"],
                                                                         add_indirect=False)
        self._sysread_slice_functions = list(map(
            lambda n: n.func, read_transitive_closure.nodes
        ))

    def _generate_syswrite_slice_functions(self):
        write_transitive_closure = CFGAnalysis.syscall_function_whitelist(self.project, self.pruned_callgraph,
                                                                         self.pal_project._cfg_util.cfg,
                                                                         function_keys=["write"],
                                                                         add_indirect=False)
        self._syswrite_slice_functions = list(map(
            lambda n: n.func, write_transitive_closure.nodes
        ))

    def _generate_rw_segments(self):
        rw_g = CFGAnalysis.key_dataflow_transitive_closure(self.project, self.pruned_callgraph, self.pal_project.cfg)
        leave_nodes = []
        for node in rw_g.nodes:
            if not len(rw_g.out_edges(node)):
                leave_nodes.append(node)
        self.rw_segment_functions = list(map(lambda n: n.func, leave_nodes))

    def generate_whole_segment(self, rw_seg_functions: List[Function]):
        if not rw_seg_functions:
            return None

        trans_closures = []
        for func in rw_seg_functions:
            trans_closures.append(self.pruned_callgraph.transitive_closure(func))

        whole_trans_closure = nx.DiGraph()

        total_nodes = set()
        common_nodes = set()

        for trans_c in trans_closures:
            whole_trans_closure.add_edges_from(trans_c.edges)
            total_nodes.update(trans_c.nodes)
            common_nodes = common_nodes.union(trans_c.nodes) if not len(common_nodes) else \
                common_nodes.intersection(trans_c.nodes)

        nodes_to_remove = total_nodes - common_nodes
        whole_trans_closure.remove_nodes_from(nodes_to_remove)

        dbg_draw = V(self.project, self.pal_project.arg_info)
        dbg_draw.draw_transitive_graph(whole_trans_closure, "whole_segment_transclosure")
        self.whole_segment_functions = [
            n.func for n in whole_trans_closure.nodes if not len(whole_trans_closure.out_edges(n))
        ]
        if self.whole_segment_functions:
            fname = self.whole_segment_functions[0].name
            log.info(f"Analysis Manager determined the whole segment start: {fname}")
        else:
            flist = list(map(lambda f: f.name, self.rw_segment_functions))
            log.info(f"Analysis Manager determined the segments to start: {flist}")
        return

    def __getstate__(self):
        s = {k: v for k, v in self.__dict__.items() if k not in ("pal_project",)}
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)