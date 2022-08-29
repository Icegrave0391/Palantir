import logging

from .cfg.cfg_util import CFGUtil, CFGAnalysis
from .cfg.callgraph import CallGraphAcyclic
from .knowledge_base import RedisKB
import angr

from .arginfo import ArgInfo
from binary import Loader, ELFLoader

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class PalProject:
    """
    Top organization of Palantiri Project
    """
    angr_project: angr.Project = None
    pal_loader: Loader = None
    _cfg_util = None

    def __init__(self, arginfo: ArgInfo, load_local_cfg=True):
        self.arg_info = arginfo
        self.pal_loader = ELFLoader(arginfo)
        self.angr_project = self.pal_loader.project
        self._load_local_cfg = load_local_cfg
        self._cfg_util = None
        self._callgraph = None
        self._redis_kb = None
        self.describe()

    @property
    def cfg_util(self) -> CFGUtil:
        if self._cfg_util is None:
            self._cfg_util = CFGUtil(self, load_local=self._load_local_cfg)
        return self._cfg_util

    @property
    def cfg(self):
        return self.cfg_util.cfg

    @property
    def callgraph(self) -> CallGraphAcyclic:
        if not self._callgraph:
            _, cga = CFGAnalysis.recover_call_graph(self, self.cfg, exclude_plt=True, exclude_external=True)
            self._callgraph = cga
        return self._callgraph

    @property
    def redis_kb(self) -> RedisKB:
        if self._redis_kb is None:
            self._redis_kb = RedisKB(self)
        return self._redis_kb

    def describe(self):
        """
        Describe pal_project information 
        """
        log.info(f"Palantiri Project info:")
        log.info(f"∟ working directory: {self.arg_info.root_dir_path}")
        log.info(f"∟ binary file: {self.arg_info.binary_file_path}")
        log.info(f"∟ debug output directory: {self.arg_info.dbg_file_path}")
        log.info(f"∟ output directory: {self.arg_info.binary_output_path}")
        log.info(f"∟ analysis verbose level: {self.arg_info.args.verbose}")

        if self.arg_info.args.verbose > 0:
            args = self.arg_info.args
            log.info(f"∟ debug mode: {args.debug}")
            log.info(f"∟ analysis loop revisit mode: {args.loop_revisit_mode}")
            log.info(f"∟ max symbolic reference depth: {args.symbolic_ref_depth}")
            log.info(f"∟ max irrlevant call depth: {self.arg_info.args.irrelevant_call_depth}")
            