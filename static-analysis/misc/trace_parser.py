import json
import logging
import networkx as nx
from pathlib import Path

from angr.knowledge_plugins.functions.function import Function
from palantiri.cfg.cfg_util import CFGAnalysis, CallGraphAcyclic
import pandas as pd
from dask import dataframe as df1

from typing import TYPE_CHECKING, Optional, Tuple, Generator, Union
if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

START_FUNCTIONS = ["main"]


class TraceParser:
    """
    TODO(): The parser currently only parses the format correctly on single thread programs.
    TODO(): multi-thread & process programs need to be supported.
    TODO(): determine indirect jump target (intra-jump or inter-jump)
    """    
    def __init__(self, pal_proj: 'PalProject', callgraph: CallGraphAcyclic, fpath="/home/chuqiz/wget_block"):
        self.pal_proj = pal_proj
        self.project = pal_proj.angr_project
        self.cfg = pal_proj.cfg_util.cfg
        
        self._cfg_node_map = None
        self.callgraph = callgraph
        
        self.fpath = fpath

        self.enforce_indirect_map = {}
        self.enforce_indirect_intrajmp_map = {}

        self.parsed_call_graph = nx.DiGraph()

        self._current_indirect_caller: Optional[str] = None
        self._current_indirect_callsite: Optional[int] = None

        # padding 
        self._pad_num = 0
        self._start_parsing = False

    @property
    def output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"raw_trace.txt"))

    @property
    def indirect_output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"indirect_enforce.txt"))

    @property
    def indirect_intrajmp_output_path(self):
        return str(Path(self.pal_proj.arg_info.binary_output_path).joinpath(
            f"indirect_intrajmp_enforce.txt"
        ))

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

    def write_syscall_line(self, fw, row: pd.Series):
        syscall_with_number = "(" + row['TYPE'] + ")"
        sys_id = int(row['SYS_NUM'])
        sys_name = row['SYS_NAME']
        sys_tuple_str = "(" + str(sys_id) + ", " + sys_name + ")"
        fw.write(self._pad_num * "  " + syscall_with_number + " " + sys_tuple_str + "\n")
    
    def write_trace_line(self, fw, cur_func: Function, cur_block, indirect=False):
        indirect_msg = "" if not indirect else "(indirect call)"
        fw.write(self._pad_num * '  ' + f"{cur_func.name} ({hex(cur_block.addr)}){indirect_msg}.\n")

    def extract_block_row(self, row: pd.Series) -> Tuple[int, str]:
        block_addr_str, jmp_type = row['ADDR'], row['JMP_TYPE']
        return int(block_addr_str, 16), jmp_type

    def yield_block(self, fw, rows_generator: Generator) -> Union[None, pd.Series]:
        """
        yield a basic block from the trace
        """
        while True:
            try:
                index, row = next(rows_generator)
            except StopIteration:
                yield None, None

            if row['TYPE'].startswith('block'):
                # yield from the start block
                if not self._start_parsing:
                    blk_addr, _ = self.extract_block_row(row)
                    try:
                        func, _ = self.cfg_node_map[blk_addr]
                    except KeyError:
                        continue
                    # continue until starting 
                    if func and func.name in START_FUNCTIONS:
                        self._start_parsing = True
                    else:
                        continue
                yield index, row
                
            else:
                self.write_syscall_line(fw, row)

    def parse(self, load_previous_enforce_map=True, save_indirect_record=True):
        # initialize enforce map from previous map
        if load_previous_enforce_map:
            try:
                with open(self.indirect_output_path, "r") as f1:
                    self.enforce_indirect_map = json.load(f1)
                with open(self.indirect_intrajmp_output_path, "r") as f2:
                    self.enforce_indirect_intrajmp_map = json.load(f2)
            except FileNotFoundError:
                pass
        # open output file 
        fw = open(self.output_path, "w")
        
        # generate data frame
        f_df: df1.DataFrame = df1.read_csv(self.fpath, skipinitialspace=True)
        rows_generator = f_df.iterrows()

        # initialize parsing stage
        global_function_stack = []
        cur_block_row = None
        
        parsing_start = False
        should_align = False

        indirect_funcs = CFGAnalysis.get_indirect_jmps(self.project, self.cfg)
        indirect_funcs.update(CFGAnalysis.get_indirect_callers(self.project, self.callgraph))
        # start parsing trace
        idx = 0
        while True:
            # recover current block addr & function info
            cur_index, cur_block_row = next(self.yield_block(fw, rows_generator))
            if cur_index is None:
                break    
            cur_block_addr, _ = self.extract_block_row(cur_block_row)
            idx += 1
            if self.pal_proj.arg_info.args.verbose > 0:
                print(f"Parsing num: {idx}, dataframe index: {cur_index}, block: {hex(cur_block_addr)}.")
            
            try:
                cur_func, cur_func_node = self.cfg_node_map[cur_block_addr]
            except:
                print("error in get cfg node")
                import IPython; IPython.embed()
            # initialize 
            if not parsing_start:
                parsing_start = True
                global_function_stack.append(cur_func)
                prev_func, prev_block = None, None

            # if cur_block_addr == 0x47b042:
            #     import ipdb; ipdb.set_trace()
            # handle angr's internal limitation of losing some functions
            # such functions are likely to be @plt functions    
            if not cur_func:
                print("error in function recovery")
                prev_block, prev_func = None, None
                should_align = True
                continue
            # alignment the call stack
            elif should_align:
                should_align = False
                if global_function_stack:
                    # it can be a return from plt
                    if cur_func in global_function_stack:
                        while global_function_stack[-1] != cur_func:
                            print(f"cur func: {cur_func.name}, stack: {global_function_stack}")
                            global_function_stack.pop()
                    # it can also be plt to another function
                    else:
                        global_function_stack.append(cur_func)

            # recover & standardize current basic block
            cur_block = self.project.factory.block(cur_block_addr, cur_func_node.size) \
                if cur_func_node else self.project.factory.block(cur_block_addr)
            
            standardized_addrs = [cur_block.addr]
            
            sz = cur_block.size
            while cur_block.capstone.insns[-1].mnemonic not in ['call', 'ret'] and \
                not cur_block.capstone.insns[-1].mnemonic.startswith('j'):
                # widen current block
                widen_blk = self.project.factory.block(cur_block_addr + sz)
                # update standardized_addrs
                standardized_addrs.append(cur_block_addr + sz)
                # update the block size
                sz += widen_blk.size
                cur_block = self.project.factory.block(cur_block_addr, size=sz)
            #
            # start handling trace lines & parsing functions
            #
            # if cur_block.addr == 0x406da9:
            #     import ipdb; ipdb.set_trace()
            if prev_block:
                jkind = prev_block.capstone.insns[-1].mnemonic
                if jkind == "call":
                    global_function_stack.append(cur_func)
                elif jkind == "ret":
                    try:
                        global_function_stack.pop()
                        # manually align the current function
                        # in case of irregular <jmp - ret> in <@plt - normal function> sequences
                        # A -call -> unknown @plt -> func1 (thats weird) -jmp -> func2 -ret-> func1 (thats weird)
                        if cur_func and not global_function_stack:
                            global_function_stack.apend(cur_func)
                        elif cur_func and global_function_stack[-1] != cur_func:
                            global_function_stack.append(cur_func)
                    except:
                        print("global function stack is empty...")
                        # import IPython; IPython.embed()
                # normal jmp & inter-proc jmp & plt return & multi-plts
                else:
                    # normal jmp
                    if prev_func and prev_func.name == cur_func.name:
                        pass
                    else:
                        # inter-proc jmp
                        if prev_func and not prev_func.is_plt and prev_func.name != cur_func.name:
                            if global_function_stack: global_function_stack.pop()
                            global_function_stack.append(cur_func)
                        # plt return
                        elif prev_func and prev_func.is_plt and not cur_func.is_plt:
                            global_function_stack.pop()
                        # plt sequences @plt1 - @plt2
                        elif prev_func and prev_func.is_plt and cur_func.is_plt:
                            global_function_stack.pop()
                            global_function_stack.append(cur_func)

            self._pad_num = len(global_function_stack) - 1

            #
            # start handling indirect calls 
            #

            # resolve indirect call
            if self._current_indirect_caller is not None:
                try:
                    self._update_enforce_map(cur_func, target_addr=cur_block_addr)
                except:
                    import IPython; IPython.embed()
            # write indirect call line
            if cur_func in indirect_funcs.keys():
                callsites = indirect_funcs[cur_func]
                for b_addr in standardized_addrs:
                    if b_addr in callsites:
                        self._current_indirect_caller = cur_func.name
                        self._current_indirect_callsite = b_addr
                        self.write_trace_line(fw, cur_func, cur_block, indirect=True)

            if cur_func != prev_func:
                self.write_trace_line(fw, cur_func, cur_block)

            prev_func, prev_block = cur_func, cur_block
        
        # end parsing
        fw.close()
        # save indirect map
        if save_indirect_record:
            # dump inter-proc indirect call/jmp enforce map
            with open(self.indirect_output_path, "w") as f:
                dump_dict = {}
                for k, vmap in self.enforce_indirect_map.items():
                    dump_dict[k] = {}
                    for k2, vset in vmap.items():
                        dump_dict[k][k2] = list(vset)
                json.dump(dump_dict, f)
            # dump intra-proc indirect jmp enforce map
            with open(self.indirect_intrajmp_output_path, "w") as f:
                dump_dict = {}
                for k, vmap in self.enforce_indirect_intrajmp_map.items():
                    dump_dict[k] = {}
                    for k2, vset in vmap.items():
                        dump_dict[k][k2] = list(vset)
                json.dump(dump_dict, f)
        pass

    def _update_enforce_map(self, calltarget: Function, target_addr:Optional[int]=None):
        """
        update indirect enforce map
        """
        assert self._current_indirect_caller is not None and self._current_indirect_callsite is not None
        calltarget_name = calltarget.name
        # determine whether is an intra-proc indirect jmp or an inter-proc indirect call/jmp
        if target_addr is not None and self._current_indirect_caller == calltarget_name:
            # intra-proc indirect jmp
            if target_addr != calltarget.addr:
                if self._current_indirect_caller not in self.enforce_indirect_intrajmp_map.keys():
                    self.enforce_indirect_intrajmp_map[self._current_indirect_caller] = {}
                if self._current_indirect_callsite not in self.enforce_indirect_intrajmp_map[self._current_indirect_caller].keys():
                    self.enforce_indirect_intrajmp_map[self._current_indirect_caller][self._current_indirect_callsite] = set()
                self.enforce_indirect_intrajmp_map[self._current_indirect_caller][self._current_indirect_callsite].add(target_addr)
                self._reset_indirect_caller_info()
                return

        if self._current_indirect_caller not in self.enforce_indirect_map.keys():
            self.enforce_indirect_map[self._current_indirect_caller] = {}
        if self._current_indirect_callsite not in self.enforce_indirect_map[self._current_indirect_caller].keys():
            self.enforce_indirect_map[self._current_indirect_caller][self._current_indirect_callsite] = set()
        self.enforce_indirect_map[self._current_indirect_caller][self._current_indirect_callsite].add(calltarget_name)
        # clear indirect caller - callee info
        self._reset_indirect_caller_info()
        pass

    def _reset_indirect_caller_info(self):
        self._current_indirect_caller = None
        self._current_indirect_callsite = None
        pass

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