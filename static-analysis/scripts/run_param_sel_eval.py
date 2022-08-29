import os
import sys
import time
import eventlet

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


def run_with_param(pal_proj: PalProject, f_eval, symbolic_ref_depth=2, insensitive_call_depth=3, operation_values=25):
    eval_mode = True
    # set eval params
    pal_proj.arg_info.args.eval_mode = True
    ## set insensitive call depth
    pal_proj.arg_info.args.irrlevant_call_depth = insensitive_call_depth
    ## set symbolic reference depth
    symbolic_ref_depth = symbolic_ref_depth
    ## set mem_rw_upperbound
    mem_rw_upperbound = operation_values
    # parse analysis arguments
    analysis_args = getargs(os.path.basename(pal_proj.angr_project.filename))
    loop_revisit_mode = analysis_args.get("loop_revisit_mode", arginfo.args.loop_revisit_mode)
    without_whole_segment = analysis_args.get("without_whole_segment", arginfo.args.without_whole_segment)
    start_function_name = analysis_args.get("start_function", arginfo.args.start_function)
    force_revisit_func_and_node = analysis_args.get("force_revisit", None)
    valueset_upperbound = mem_rw_upperbound
    
    db_name = "db_%d_%d_%d_.json" % (symbolic_ref_depth, insensitive_call_depth, mem_rw_upperbound)

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

    timeout = eventlet.timeout.Timeout(seconds=7200, exception=TimeoutError)
    try:
        analysis_interface = BinarySummaryInterface(
            pal_proj=pal_proj, function_handler=BSFunctionHandler(), start_function=start_function,
            save_space_mode=False, auto_save=False, recover_from_disk=False,
            function_summary_dict=None, force_propagate_taint_summary=False,
            loop_revisit_mode=loop_revisit_mode,
            max_symbol_reference_depth=symbolic_ref_depth,
            eval_mode=True,
            without_whole_segment=without_whole_segment,
            force_revisit_func_and_node=force_revisit_func_and_node,
            mem_rw_upperbound=mem_rw_upperbound,
            valueset_upperbound=valueset_upperbound,
        )
        if not start_function:
            start_functions = analysis_interface.interproc_manager.start_functions
            for func in start_functions:
                log.info(f"AnalysisInterface -- determined start function: {func.name}")
        else:
            log.info(f"AnalysisInterface -- determined start function: {start_function.name}")    
        start_time = time.time() 
        analysis_interface.start(start_function=analysis_interface.start_function)
        end_time = time.time() 
    except TimeoutError:
        analyze_total_time = -1
    finally:
        analyze_total_time = end_time - start_time
        timeout.cancel()
    
    # results
    analysis_interface.dump_symbol_num()
    pal_proj.redis_kb.dump_db(db_name=db_name)

    f_eval.write(f"Binary {pal_proj.arg_info.binary_name}\n"
                    f"====param: <symbolic_reference_depth: {symbolic_ref_depth}; " 
                    f"insensitive_call_depth: {insensitive_call_depth}; "
                    f"operation_values: {operation_values}> ====\n"
                    f"Taint summary statistics (item number): {len(pal_proj.redis_kb.prefix_statistic_set)}\n"
                    f"Taint summary statistics (rule number): {pal_proj.redis_kb.num_relations}\n"

                    f"Taint Analysis time: {analyze_total_time:.1f}(sec)\n"
                    f"Peak memory usage: {analysis_interface.peak_mem_usage:.1f}(MB)\n"
                )



if __name__ == "__main__":
    arginfo = ArgInfo()
    pal_proj = PalProject(arginfo=arginfo, load_local_cfg=True)
    single_run = False
    # reset debug file
    # proc once
    with open(arginfo.dbg_file_path, "w") as f:
        pass

    eval_output_path = os.path.join(pal_proj.arg_info.binary_output_path, "eval_param_selection.txt")
    # reset eval file
    with open(eval_output_path, "w") as f:
        pass

    # recover calling conventions for external lib functions
    CFGAnalysis.fast_cc_analysis(pal_proj.angr_project, pal_proj.cfg)

    # hook special functions to general handling procedures 
    apply_special_hook(pal_proj.angr_project)
    apply_fake_hook(pal_proj.angr_project)
    
    # evaluation
    for param1 in [1, 2, 3, 4, 5]:
        f_eval = open(eval_output_path, "a")
        run_with_param(pal_proj, f_eval, symbolic_ref_depth=param1)
        f_eval.close()

    for param2 in [0, 1, 2, 3, 4]:
        f_eval = open(eval_output_path, "a")
        run_with_param(pal_proj, f_eval, symbolic_ref_depth=4, insensitive_call_depth=param2, operation_values=50)
        f_eval.close()

    for param3 in [5, 10, 25, 75, 100]:
        f_eval = open(eval_output_path, "a")
        run_with_param(pal_proj, f_eval, symbolic_ref_depth=4, insensitive_call_depth=4, operation_values=param3)
        f_eval.close()
