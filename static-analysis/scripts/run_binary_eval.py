import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from palantiri.arginfo import ArgInfo
from palantiri.pal_project import PalProject
from palantiri.analyses.binary_summary import BinarySummaryInterface
from palantiri.structures.value_set.function_handler.bs_functionhandler import BSFunctionHandler
from palantiri.structures.hooks.function_wrappers import *
from palantiri.cfg.cfg_util import CFGAnalysis

from misc.trace_parser import TraceParser

from scripts.getargs import getargs
import logging
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

if __name__ == "__main__":
    arginfo = ArgInfo()
    pal_proj = PalProject(arginfo=arginfo, load_local_cfg=not arginfo.args.eval_mode)

    # reset debug file
    with open(arginfo.dbg_file_path, "w") as f:
        pass

    # parse analysis arguments
    analysis_args = getargs(os.path.basename(pal_proj.angr_project.filename))

    loop_revisit_mode = analysis_args.get("loop_revisit_mode", arginfo.args.loop_revisit_mode)
    symbolic_ref_depth = analysis_args.get("symbolic_ref_depth", arginfo.args.symbolic_ref_depth)
    without_whole_segment = analysis_args.get("without_whole_segment", arginfo.args.without_whole_segment)
    start_function_name = analysis_args.get("start_function", arginfo.args.start_function)
    force_revisit_func_and_node = analysis_args.get("force_revisit", None)
    mem_rw_upperbound = analysis_args.get("mem_rw_upperbound", arginfo.args.mem_rw_upperbound)
    valueset_upperbound = analysis_args.get("valueset_upperbound", arginfo.args.valueset_upperbound)

    eval_mode = arginfo.args.eval_mode

    cfg_constr_starttime = time.time() if eval_mode else 0
    cfg = pal_proj.cfg
    cfg_constr_endtime = time.time() if eval_mode else 0
    cfg_constr_time = cfg_constr_endtime - cfg_constr_starttime

    # recover calling conventions for external lib functions
    CFGAnalysis.fast_cc_analysis(pal_proj.angr_project, pal_proj.cfg)

    # (optional) parse the given execution PTrace to the format of call-stack (help debug)
    if arginfo.args.parse_trace:
        _, callgraph_acyclic = CFGAnalysis.recover_call_graph(
            pal_proj, pal_proj.cfg, exclude_plt=True, exclude_external=True
        )
        parser = TraceParser(pal_proj, callgraph_acyclic, fpath=arginfo.args.parse_trace)
        parser.parse(load_previous_enforce_map=False, save_indirect_record=False)

    # hook special functions to general handling procedures 
    apply_special_hook(pal_proj.angr_project)
    apply_fake_hook(pal_proj.angr_project)

    # initialize knowledge base 
    pal_proj.redis_kb.reset_db()

    hook_function_addrs = []
    for flist in function_special_wrappers.keys():
        for fname in flist:
            try:
                hook_function_addrs.append(pal_proj.angr_project.kb.functions[fname].addr)
            except KeyError:
                continue
    pal_proj.redis_kb.store_hooked_info(hook_function_addrs)

    start_function = None
    if start_function_name:
        try:
            start_function = pal_proj.angr_project.kb.functions[start_function_name]
        except KeyError:
            pass
    
    # record CFG trimming time
    if eval_mode:
        cg_dump_path = os.path.join(pal_proj.arg_info.binary_output_path, "callgraph_acyclic_model.dump")
        cg_enriched_dump_path = os.path.join(pal_proj.arg_info.binary_output_path, "callgraph_acyclic_enriched_model.dump")
        os.system(f"rm {cg_dump_path}")
        os.system(f"rm {cg_enriched_dump_path}")

    cfg_trimming_starttime = time.time() if eval_mode else 0
    
    analysis_interface = BinarySummaryInterface(
        pal_proj=pal_proj, function_handler=BSFunctionHandler(), start_function=start_function,
        save_space_mode=False, auto_save=False, recover_from_disk=False,
        function_summary_dict=None, force_propagate_taint_summary=False,
        loop_revisit_mode=loop_revisit_mode,
        max_symbol_reference_depth=symbolic_ref_depth,
        eval_mode=eval_mode,
        without_whole_segment=without_whole_segment,
        force_revisit_func_and_node=force_revisit_func_and_node,
        mem_rw_upperbound=mem_rw_upperbound,
        valueset_upperbound=valueset_upperbound,
    )

    cfg_trimming_endtime = time.time() if eval_mode else 0
    cfg_trimming_time = cfg_trimming_endtime - cfg_trimming_starttime

    if eval_mode:
        if not start_function:
            start_functions = analysis_interface.interproc_manager.start_functions
            for func in start_functions:
                log.info(f"AnalysisInterface -- determined start function: {func.name}")
        else:
            log.info(f"AnalysisInterface -- determined start function: {start_function.name}")
        log.info("AnalysisInterface -- ready to start.")
        user_input = input("Press any key to start analysis, and press c to leave...")
        if user_input == "c":
            exit()

    start_time = time.time() if eval_mode else 0
    analysis_interface.start(start_function=analysis_interface.start_function)
    end_time = time.time() if eval_mode else 0

    analyze_total_time = end_time - start_time

    analysis_interface.dump_symbol_num()
    pal_proj.redis_kb.dump_db()

    if eval_mode:
        # new evaluta method for after-trimming CFG
        copied_cfg = pal_proj.cfg.copy()
        analyzed_function_addrs = list(map(lambda subj: subj.content.addr, 
                                           analysis_interface.eval_function_subj_set
                                           ))
        
        nodes_to_remove = list(filter(lambda n: n.function_address not in analyzed_function_addrs,
                                      copied_cfg.model.nodes()))
        copied_cfg.model.graph.remove_nodes_from(nodes_to_remove)
        analysis_node_num = len(copied_cfg.model.nodes())
        analysis_edge_num = len(copied_cfg.model.graph.edges)
        # static CFG
        total_node_num = len(pal_proj.cfg.graph.nodes)
        total_edge_num = len(pal_proj.cfg.graph.edges)
        # storage
        try:
            db_size = pal_proj.redis_kb.r.memory_stats()["total.allocated"]
            db_size = db_size / 1024 / 1024 # MB
        except:
            db_size = 0

        binary_size = int(os.popen(f"wc -c {pal_proj.arg_info.binary_file_path}").read().strip().split()[0])
        binary_size = binary_size / 1024 # KB

        eval_output_path = os.path.join(pal_proj.arg_info.binary_output_path, "eval_statistic.txt")
        # write evaluation statistics
        f_eval = open(eval_output_path, "w")
        f_eval.write(f"Binary {pal_proj.arg_info.binary_name}'s size: {binary_size:.1f}(KB)\n"
                     f"Binary total nodes: {total_node_num}\n"
                     f"Binary total edges: {total_edge_num}\n"
                     f"Binary after-trimming nodes: {analysis_node_num}, percent: {100 * analysis_node_num/total_node_num:.1f}%\n"
                     f"Binary after-trimming edges: {analysis_edge_num}, percent: {100 * analysis_edge_num/total_edge_num:.1f}%\n"
                     f"Taint summary statistics (item number): {len(pal_proj.redis_kb.prefix_statistic_set)}\n"
                     f"Taint summary statistics (relation number): {pal_proj.redis_kb.num_relations}\n"
                     f"CFG Construction time: {cfg_constr_time:.1f}(sec)\n"
                     f"CFG Trimming time: {cfg_trimming_time:.1f}(sec)\n"
                     f"CFG Total-handling time: {cfg_constr_time + cfg_trimming_time:.1f}(sec)\n"
                     f"Taint Analysis time: {analyze_total_time:.1f}(sec)\n"
                     f"Peak memory usage: {analysis_interface.peak_mem_usage:.1f}(MB)\n"
                     f"Redis storage size: {db_size:.1f}(MB)")
        f_eval.close()

        eval_result_msg = os.popen(f"cat {eval_output_path}").read()
        log.info("Binary Analysis Evaluation Statistic:\n" + eval_result_msg)
