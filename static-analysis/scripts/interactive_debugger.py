import pickle
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from palantiri.arginfo import ArgInfo
from palantiri.pal_project import PalProject
from palantiri.cfg import CFGAnalysis

from palantiri.analyses.binary_summary import BinarySummaryInterface
from palantiri.structures.value_set.function_handler.bs_functionhandler import BSFunctionHandler
from palantiri.structures.hooks.function_wrappers import *
from palantiri.cfg.cfg_util import CFGAnalysis

from misc.visualize import V
import misc.debugger as debugger

import logging
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

from misc.naive_parser import NaiveParser
from misc.trace_parser import TraceParser


if __name__ == '__main__':
    a = ArgInfo()
    """debug arginfo"""
    log.debug(f"root dir: {a.root_dir_path}")
    log.debug(f"debug file path: {a.dbg_file_path}")
    log.debug(f"binary file path: {a.binary_file_path}")
    log.debug(f"binary output path: {a.binary_output_path}")

    """debug proj"""
    pal_proj = PalProject(a)
    c = pal_proj.cfg_util
    p, cfg = c.proj, c.cfg
    v = V(pal_proj.angr_project, a)
    print("Start recovering call graph.")
    cg, cga = CFGAnalysis.recover_call_graph(pal_proj, cfg)
    print("Start recovering CC.")
    CFGAnalysis.fast_cc_analysis(p, cfg)
    
    """parsing"""
    if a.args.parse_trace:
        # np = NaiveParser(pal_proj, cga, fpath=a.args.parse)
        # np.parse(load_previous_enforce_map=False, save_indirect_record=True)
        print("Init parser!")
        parser = TraceParser(pal_proj, cga, fpath=a.args.parse_trace)
        parser.parse(load_previous_enforce_map=False, save_indirect_record=True)

    """summary"""
    analysis_interface = BinarySummaryInterface(
        pal_proj=pal_proj, function_handler=BSFunctionHandler(), start_function=None,
        save_space_mode=False, auto_save=False, recover_from_disk=False,
        function_summary_dict=None, force_propagate_taint_summary=False,
        loop_revisit_mode=False,
        max_symbol_reference_depth=2,
        eval_mode=True,
        without_whole_segment=True
    )

    """ interactive """
    import IPython; IPython.embed()