from typing import List, Optional
import networkx as nx
import logging

from angr.knowledge_plugins.functions.function import Function
from palantiri.arginfo import ArgInfo


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def dbgLog(msg, slience=True):
    if slience:
        return
    log.debug(msg)


def _dbg_vals(state, vs):
    for v in vs.values[0]:
        print(f"===val: {v},\nregions: {state.extract_abs_regions(v)},\ntaints: {state.extract_taint_tags(v)},\n"
              f"constrs: {state.extract_sem_constraints(v)}.")


def debug_print_log(pal_proj, message: str, logger: Optional[logging.Logger]=None, min_vlevel=0, to_tmp_file=True):
    a: ArgInfo = pal_proj.arg_info
    logger = logger if logger is not None else log
    message = logger.name + " | " + message
    # write to debug file
    if to_tmp_file:
        with open(a.dbg_file_path, "a+") as f:
            f.write(message + "\n")
    # log print
    if a.args.verbose >= min_vlevel:
        logger.info(message)


def dbg_context(p, cfg, call_stack):
    names = []
    for callsite in call_stack:
        faddr = cfg.model.get_any_node(callsite).function_address
        names.append(p.kb.functions[faddr].name)
    print(names)


def dbg_generate_subgraph(func_name: str, transitive_graph: nx.DiGraph):
    """
    generate sub graph starting from the function node
    """
    fnode = None
    for node in transitive_graph.nodes:
        if node.func.name == func_name:
            fnode = node
            break
    if not fnode:
        print(f"function {func_name} not exists, generation stop.")
        return None
    
    sub_graph = nx.DiGraph()
    node_queue = [fnode]
    while node_queue:
        in_node = node_queue.pop()
        for _, out_node in transitive_graph.out_edges(in_node):
            sub_graph.add_edge(in_node, out_node)
            node_queue.append(out_node)
    
    print(f"Generation done, sub graph contains {len(sub_graph.nodes)} nodes.")
    return sub_graph


def dbg_generate_subtransitive(func_list: List[Function], transitive_graph: nx.DiGraph):
    print(f"Debug generate subgraph for function list: {list(map(lambda f: f.name, func_list))}.")
    sub_graph = nx.DiGraph()

    node_queue = []
    for func in func_list:
        node_queue.append(next(iter(filter(lambda n: n.func.name == func.name, 
                                          transitive_graph.nodes))))
    
    while node_queue:
        in_node = node_queue.pop()
        for _, out_node in transitive_graph.out_edges(in_node):
            sub_graph.add_edge(in_node, out_node)
            node_queue.append(out_node)
    print(f"Generation done, sub graph contains {len(sub_graph.nodes)} nodes.")
    return sub_graph