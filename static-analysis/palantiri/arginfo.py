import argparse
import logging
from pathlib import Path

ROOT_DIR_NAME = "static-analysis"

log = logging.getLogger(name=__name__)
log.setLevel(logging.DEBUG)


class ArgInfo():
    """
    Top informations for Palantiri
    """
    def __init__(self):
        self.args = None    # arguments from command line
        self._root_dir_path = None   # projet root file path
        self._dbg_file_path = None   # debug file path
        self._binary_file_path = None # binary file path
        self._binary_output_path = None # binary output path
        self._libs_output_path = None # libs output path
        self._analyses_output_path = None
        self._function_graph_output_path = None
        self._transitive_graph_output_path = None
        self._dbgsym_path = None
        self._parse_arg()

    @property
    def root_dir_path(self) -> str:
        if self._root_dir_path is not None:
            return self._root_dir_path

        pwd = Path(__name__)
        rootdir = pwd
        for p in pwd.absolute().parents:
            if p.name == ROOT_DIR_NAME:
                rootdir = p
                break

        if rootdir.absolute().name != ROOT_DIR_NAME:
            raise FileNotFoundError(f"No such directory {ROOT_DIR_NAME}")

        self._root_dir_path = str(rootdir.absolute())
        return self._root_dir_path

    @property
    def dbg_file_path(self) -> str:
        if self._dbg_file_path is not None:
            return self._dbg_file_path

        dbg_dir_name = None if not self.args.dbg_dir else self.args.dbg_dir
        # dbg_dir = Path(self.root_dir_path) if dbg_dir_name is None else Path(self.root_dir_path).joinpath(dbg_dir_name)

        # try:
        #     Path.mkdir(dbg_dir)
        # except FileExistsError:
        #     pass
        dbg_dir = Path(self.binary_output_path)

        self._dbg_file_path = str(dbg_dir.joinpath("debug_temp_file.tmp").absolute())
        return self._dbg_file_path

    @property
    def binary_file_path(self) -> str:
        if self._binary_file_path is not None:
            return self._binary_file_path

        binary_dir = Path(self.root_dir_path)
        if self.args.binary_dir is not None:
            binary_dir = binary_dir.joinpath(self.args.binary_dir)

        try:
            Path.mkdir(binary_dir)
        except FileExistsError:
            pass

        self._binary_file_path = str(binary_dir.joinpath(self.args.binary).absolute())
        return self._binary_file_path

    @property
    def function_graph_output_path(self):
        if self._function_graph_output_path is not None:
            return self._function_graph_output_path

        func_outdir = Path(self.binary_output_path).joinpath("functions")
        try:
            Path.mkdir(func_outdir)
        except FileExistsError:
            pass

        self._function_graph_output_path = str(func_outdir)
        return self._function_graph_output_path

    @property
    def transitive_graph_output_path(self):
        if self._transitive_graph_output_path is not None:
            return self._transitive_graph_output_path

        trans_outdir = Path(self.binary_output_path).joinpath("transitive_graphs")
        try:
            Path.mkdir(trans_outdir)
        except FileExistsError:
            pass

        self._transitive_graph_output_path = str(trans_outdir)
        return self._transitive_graph_output_path

    @property
    def binary_output_path(self) -> str:
        if self._binary_output_path is not None:
            return self._binary_output_path

        binary_outdir = Path(self.root_dir_path).joinpath(self.args.binary_output_dir)

        try:
            Path.mkdir(binary_outdir)
        except FileExistsError:
            pass

        binary_outpath = binary_outdir.joinpath(Path(self.binary_file_path).stem)

        try:
            Path.mkdir(binary_outpath)
        except FileExistsError:
            pass

        self._binary_output_path = str(binary_outpath)
        return self._binary_output_path

    @property
    def analyses_output_path(self) -> str:
        if self._analyses_output_path is not None:
            return self._analyses_output_path

        analysis_outdir = Path(self.binary_output_path).joinpath("analyses")
        try:
            Path.mkdir(analysis_outdir)
        except FileExistsError:
            pass

        self._analyses_output_path = str(analysis_outdir)
        return self._analyses_output_path

    @property
    def libs_output_path(self) -> str:
        if self._libs_output_path is not None:
            return self._libs_output_path

        binary_outdir = Path(self.root_dir_path).joinpath(self.args.binary_output_dir)

        try:
            Path.mkdir(binary_outdir)
        except FileExistsError:
            pass

        binary_outpath = binary_outdir.joinpath(Path(self.binary_file_path).stem)

        try:
            Path.mkdir(binary_outpath)
        except FileExistsError:
            pass

        lib_outpath = binary_outpath.joinpath("libs")

        try:
            Path.mkdir(lib_outpath)
        except FileExistsError:
            pass

        self._libs_output_path = str(lib_outpath)
        return self._libs_output_path

    @property
    def binary_name(self):
        return Path(self.binary_file_path).stem


    @property
    def dbgsym_path(self):
        if self._dbgsym_path is not None:
            return self._dbgsym_path

        if self.args.dbgsym is None:
            return None

        self._dbgsym_path = self.args.dbgsym
        return self._dbgsym_path

    def _parse_arg(self):
        """
        Set and parse global arguments for Palantiri
        """
        parser = argparse.ArgumentParser(description=self.description())
        parser.add_argument("--binary_dir", help=f"Input the directory name that contains input all binary files, by default is `binaries` and the directory will be: `{ROOT_DIR_NAME}/binaries/`", 
                            type=str, default="binaries")
        parser.add_argument("-b", "--binary", help=f"Input program binary file (please first put the binary file into the `binary_dir`)", type=str, required=True)
        parser.add_argument("--binary_output_dir", help=f"Input the directory name to store the analyses results and temporary outputs, by default is `binaries_output` and the directory will be: `{ROOT_DIR_NAME}/binaries_output/`", 
                            type=str, default="binaries_output")
        parser.add_argument("--dbgsym", help="(Optional) input binary dbgsym file path to enrich binary symbol table", type=str)
        parser.add_argument(f"--dbg_dir", help="Input the directory for the temporary debug log file, by default is `debug` and the directory will be: {ROOT_DIR_NAME}/debug/",
                            type=str, default="debug")
        parser.add_argument("-l", "--loop_revisit_mode", help="Turn on loop revisit mode for binary summary analysis",
                            action="store_true")
        parser.add_argument("-e", "--eval_mode", help="Turn on evaluation mode to generate binary statistics",
                            action="store_true")
        parser.add_argument("-x", "--without_whole_segment", help="Run different segments rather than a whole segment "
                                                                  "in analysis", action="store_true", default=False)
        parser.add_argument("-p", "--parse_trace", help="Input the execution trace path to parse (this option is used for debugging PT traces only)", type=str, default=None)
        parser.add_argument("-v", "--verbose", help="Input verbose level count (e.g., -vvv)", action="count", default=0)
        parser.add_argument("-f", "--start_function", help="(Optional) Assign the starting function for the analysis, by default is None that it will determined by CFG Refinement",
                            type=str, default=None)
        parser.add_argument("-r", "--mem_rw_upperbound", help="Set upper bound of the approximate number of memory r/w values, by default is 10",
                            type=int, default=10)
        parser.add_argument("-u", "--valueset_upperbound", help="Set upper bound number of the approximate number of value site, by default is 15",
                            type=int, default=15)
        parser.add_argument("-s", "--symbolic_ref_depth", help="Set the max level of symbolic (de)reference depth for analysis (N_sym), by default is 2",
                            type=int, default=2)
        parser.add_argument("-d", "--irrelevant_call_depth", help="Set the max irrelevant call depth of out-of-scope functions for analysis (N_dep), by default is 3",
                            type=int, default=3)
        parser.add_argument("--redis_ip", help="Set up redis database server (for taint summary storage) ip address, by default is 127.0.0.1",
                            type=str, default="127.0.0.1")
        parser.add_argument("--redis_port", help="Set up redis database server (for taint summary storage) port, by default is 6379",
                            type=int, default=6379)
        parser.add_argument("--debug", help="Turn on debug mode, which will automatically draw and visualize transitive closures to the local files",
                            action="store_true")
        self.args = parser.parse_args()
        # resolve debug path

    def description(self) -> str:
        return "Palantiri Binary Pre-processing and Static (Data-flow) Analysis Framework."


if __name__ == "__main__":
    a = ArgInfo()
    """debug arginfo"""
    log.warning(f"root dir: {a.root_dir_path}")
    log.debug(f"debug file path: {a.dbg_file_path}")
    log.debug(f"binary file path: {a.binary_file_path}")
    log.debug(f"binary output path: {a.binary_output_path}")