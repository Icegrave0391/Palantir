import json
import logging
import networkx as nx
from pathlib import Path
from palantiri.cfg.cfg_util import CFGAnalysis, CallGraphAcyclic

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class NaiveParser:

    def __init__(self, pal_proj: 'PalProject', callgraph: CallGraphAcyclic, fpath="/home/chuqiz/wget_block"):
        self.pal_proj = pal_proj
        self.project = pal_proj.angr_project
        self.cfg = pal_proj.cfg_util.cfg
        self._cfg_node_map = None

        self.callgraph = callgraph
        self.fpath = fpath
        self.enforce_indirect_map = {}

        self.parsed_call_graph = nx.DiGraph()

        self._current_indirect_caller = None
        self._current_indirect_callsite = None

    @property
    def output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"raw_trace.txt"))

    def graph_output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"raw_trace.txt"))

    @property
    def indirect_output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"indirect_enforce.txt"))

    @property
    def cfg_node_map(self):
        if not self._cfg_node_map:
            self._cfg_node_map = {}
            for node in self.cfg.nodes_iter():
                node_addr = node.addr
                func_addr = node.function_address
                try:
                    func = self.project.kb.functions[node.function_address]
                except:
                    func = None
                func_node = func.get_node(node_addr) if func else None

                self._cfg_node_map[node_addr] = (func, func_node)
        return self._cfg_node_map

    def parse(self, load_previous_enforce_map=True, save_indirect_record=False, max_line_num=6350000):
        """
        Parse the execution trace obtained by PT.
        :param load_previous_enforce_map: Load the previously resolved enforce map to further update.
        :param save_indirect_record:
        :return:
        """

        # load previous enforce map
        if load_previous_enforce_map:
            try:
                with open(self.indirect_output_path, "r") as f:
                    self.enforce_indirect_map = json.load(f)
            except FileNotFoundError:
                pass

        # start parsing the execution trace
        num_pads = 0
        indirect_funcs = CFGAnalysis.get_indirect_jmps(self.project, self.cfg)
        indirect_funcs.update(CFGAnalysis.get_indirect_callers(self.project, self.callgraph))

        log.info(f"Start parsing {self.fpath}, it may takes a few minutes...")
        with open(self.output_path, "w+") as fw:
            with open(self.fpath, "r") as f:
                lines = f.readlines()
                if max_line_num:
                    lines = lines[0: max_line_num]

                bb_and_syscall_list = list(filter(lambda l: l.find("block") >= 0 or l.find("syscall") >= 0, lines))

                last_func = None
                start = False

                for idx, blk in enumerate(bb_and_syscall_list):

                    # its a syscall, print
                    if blk.find("syscall") >= 0:
                        if not start:
                            continue
                        
                        if self.pal_proj.arg_info.args.verbose > 0:
                            log.info(f"Parsing index {idx}, {blk}")

                        fw.write(num_pads * '\t' + f"{blk}" + '\n')
                        continue

                    # blk_addr = int(blk.replace("block: ", "").strip(), 16)
                    blk_addr = self._get_blkaddr(blk)
                    next_blk_addr = self._get_next_blkaddr(idx, bb_and_syscall_list)

                    if self.pal_proj.arg_info.args.verbose > 0:
                        log.info(f"Parsing index {idx}, block: {hex(blk_addr)}")
                    else:
                        if idx % 200 == 0:
                            print(f"Parsing index {idx}, block: {hex(blk_addr)}")
                    if blk_addr >= 0x800000:
                        continue
                    if blk_addr == 0x415cc0:
                        print('dbg')

                    cfgnode = self.cfg.model.get_any_node(blk_addr)
                    try:
                        func = self.project.kb.functions[cfgnode.function_address]
                    except:
                        func = last_func

                    func_node = func.get_node(blk_addr) if func else None

                    # func = self.cfg_node_map[blk_addr][0]
                    # func_node = self.cfg_node_map[blk_addr][1]

                    block = self.project.factory.block(blk_addr, func_node.size) if func_node\
                        else self.project.factory.block(blk_addr)

                    # standardrize block
                    sz = block.size
                    standardized_addrs = [block.addr]

                    while block.capstone.insns[-1].mnemonic not in ['call', 'ret'] and \
                       not block.capstone.insns[-1].mnemonic.startswith("j"):
                        next_blk = self.project.factory.block(blk_addr + sz)
                        standardized_addrs.append(blk_addr + sz)
                        sz += next_blk.size
                        block = self.project.factory.block(blk_addr, sz)

                    if func and func.name == "main":
                        start = True

                    if not start:
                        continue

                    # print
                    if func != last_func:
                        fw.write(num_pads * '\t' + f"{func.name} ({hex(block.addr)})" + '\n')
                        last_func = func

                    # update indirect
                    if self._current_indirect_caller is not None:
                        if self._current_indirect_caller == "ngx_http_write_filter":
                            print('dbg')
                        self._update_enforce_map(func.name)

                    if func in indirect_funcs.keys():
                        callsites = indirect_funcs[func]
                        for b_addr in standardized_addrs:
                            if b_addr in callsites:
                                self._current_indirect_caller = func.name
                                self._current_indirect_callsite = b_addr
                                fw.write(num_pads * '\t' + f"{func.name} ({hex(block.addr)})(Indirect call)." + '\n')

                    # padding
                    if (blk_addr in func.get_call_sites()) or \
                        block.capstone.insns[-1].mnemonic == "call" :
                        num_pads += 1
                    elif ( func.is_plt) or \
                         (blk_addr in list(map(lambda n: n.addr, func.ret_sites))) or \
                         block.capstone.insns[-1].mnemonic == 'ret':
                        num_pads -= 1
                    # continuous plt functions
                    if next_blk_addr and next_blk_addr in self.project.kb.functions.keys():
                        if func.is_plt and self.project.kb.functions[next_blk_addr].is_plt:
                            num_pads += 1

        # save enforce map to local file
        if save_indirect_record:
            with open(self.indirect_output_path, "w") as f:
                dump_dict = {}
                for k, vmap in self.enforce_indirect_map.items():
                    dump_dict[k] = {}
                    for k2, vset in vmap.items():
                        dump_dict[k][k2] = list(vset)

                json.dump(dump_dict, f)

    def _update_enforce_map(self, calltarget_name: str):
        """
        update indirect enforce map
        """
        assert self._current_indirect_caller is not None and self._current_indirect_callsite is not None

        if self._current_indirect_caller not in self.enforce_indirect_map.keys():
            self.enforce_indirect_map[self._current_indirect_caller] = {}
        if self._current_indirect_callsite not in self.enforce_indirect_map[self._current_indirect_caller].keys():
            self.enforce_indirect_map[self._current_indirect_caller][self._current_indirect_callsite] = set()

        self.enforce_indirect_map[self._current_indirect_caller][self._current_indirect_callsite].add(calltarget_name)

        self._current_indirect_callsite = None
        self._current_indirect_caller = None

    def _get_next_blkaddr(self, idx, bb_and_syscall_list):
        bb_and_syscall_list = list(bb_and_syscall_list)
        nlist = bb_and_syscall_list[idx+1:]
        for b in nlist:
            if b.find("syscall") >= 0:
                continue
            blk_addr = self._get_blkaddr(b)
            # int(b.replace("block: ", "").strip(), 16)
            return blk_addr
        return None

    def _get_blkaddr(self, blk_string: str) -> int:
        # assert(blk_string.find("block:") >= 0)
        # blk_substring = blk_string[blk_string.index("block"):]
        # blk_addr = int(blk_substring.replace("block:", "").strip(), 16)
        blk_addr = int(blk_string.replace("block: ", "").strip(), 16)
        return blk_addr