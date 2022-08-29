from cmath import e
import redis
import logging
import os
import sys
import re
from typing import TYPE_CHECKING, List, Tuple, Iterable
from collections import defaultdict
from angr.knowledge_plugins.functions import Function
from palantiri.structures.value_set.taint.taint_summary import TaintSummary, TaintType, LOOKUP_FMT
from palantiri.structures.value_set import register_to_offset
from palantiri.structures.value_set.vs_subject import VSSubject
from palantiri.singletons.global_symdict import global_symmem_dict
from palantiri.structures.key_definitions import GENERAL_REGS_x64
from palantiri.analyses import PAL_ISA

if TYPE_CHECKING:
    from palantiri.pal_project import PalProject

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class RedisKB:

    def __init__(self, pal_proj: 'PalProject', decode_responses=True):
        self.host = pal_proj.arg_info.args.redis_ip
        self.port = pal_proj.arg_info.args.redis_port
        self.db_id = 0
        self.pal_proj = pal_proj
        self.decode_responses = decode_responses
        self._r = None

        self.prefix_statistic_set = set() # for evaluation
        self.num_relations = 0  # for evaluation


    @property
    def r(self) -> redis.client.Redis:
        if self._r is None:
            try:
                self._r = redis.Redis(host=self.host, port=self.port, db=self.db_id,
                                    decode_responses=self.decode_responses)
            except:
                log.error(f"ANALYSIS ABORT. Please set up redis-server at {self.host}:{self.port} first.")
                sys.exit(1)
        return self._r

    def reset_db(self):
        try:
            if not self.r.flushdb():
                log.warning(f"Flushing database failed.")
        except:
            log.error(f"ANALYSIS ABORT. Please set up redis-server at {self.host}:{self.port} first.")
            sys.exit(1)

    def dump_db(self, db_name=None):
        output_dir = self.pal_proj.arg_info.binary_output_path
        if not db_name:
            output_path = os.path.join(output_dir, self.pal_proj.arg_info.binary_name + f"_db{self.db_id}.json")
        else:
            output_path = os.path.join(output_dir, self.pal_proj.arg_info.binary_name + "_" + db_name)
        os.system(f"redis-dump -u {self.host}:{self.port} -d {self.db_id} > {output_path}")

    def store_section_info(self, section_name):
        """
        Store ELF section info
        """
        section_info_map = self.pal_proj.pal_loader.get_section_info(section_name)
        if not len(section_info_map):
            log.error(f"Section {section_name} is not a valid section.")
            return
        sec_vaddr, sec_size = section_info_map["vaddr_start"], section_info_map["size"]
        
        # TODO(): angr currently can not resolve the last plt entry for pure-ftpd.
        if self.pal_proj.angr_project.filename.find("pure-ftpd") >= 0 and section_name == ".plt":
            sec_size += 8

        proc_name = os.path.basename(self.pal_proj.angr_project.filename)
        self.r.lpush(f"{proc_name}:{section_name}", sec_vaddr, sec_size)
        log.info(f"{self.r} stored section info: [{section_name}, vaddr: {sec_vaddr}, size: {sec_size}].")

    def store_hooked_info(self, hooked_function_addrs: Iterable):
        """
        Store those hooked functions (i.e. xmalloc)
        """
        angr_proj = self.pal_proj.angr_project
        hooked_node_addrs = []
        for function_addr in hooked_function_addrs:
            vs_subj = VSSubject(angr_proj, angr_proj.kb.functions[function_addr])

            for node in vs_subj.refined_func_graph.nodes:
                node_addr = node.addr
                hooked_node_addrs.append(node_addr)
        proc_name = os.path.basename(self.pal_proj.angr_project.filename)
        if hooked_function_addrs:
            self.r.lpush(f"{proc_name}:.hook", *hooked_node_addrs)

    def store_stack_info(self, callsites, function_addr, initial_stack_offset):
        """
        Store the initial stack offset of a function
        """
        prefix_key = self._gen_prefix_key(callsites)
        info_key = prefix_key + hex(function_addr) + ":stack"
        # TODO(): param eval
        try:
            self.r.set(info_key, initial_stack_offset)
        except:
            pass
        log.debug(f"Stored initial stack info for {info_key}, {initial_stack_offset}")

    def store_pruned_function(self, callsites: Iterable, function_addr):
        """
        Mark a function's nodes as out of scope
        """
        prefix_key = self._gen_prefix_key(callsites)
        angr_proj = self.pal_proj.angr_project
        try:
            vs_subj = VSSubject(angr_proj, angr_proj.kb.functions[function_addr])
            for node in vs_subj.refined_func_graph.nodes:
                node_addr = node.addr
                node_key = prefix_key + hex(node_addr) + ":scope"
                self.r.set(node_key, 0)
        # corner case: pure-ftpd 4207288 (readdir)
        except KeyError:
            node_key = prefix_key + hex(function_addr) + ":scope"
            self.r.set(node_key, 0)

    def store_start_func_info(self, start_funcs: List):
        """
        Store start function info
        """
        proc_name = os.path.basename(self.pal_proj.angr_project.filename)
        s_key = proc_name + ":.start"
        v_list = []
        for item in start_funcs:
            if isinstance(item, Function):
                v_list.append(hex(item.addr))
            else:
                v_list.append(hex(item))
        self.r.lpush(s_key, *v_list)

    def _dbg_append_db(self):
        fo = os.popen(f"redis-dump -u {self.host}:{self.port} -d {self.db_id}")
        val = fo.read()
        output_dir = self.pal_proj.arg_info.binary_output_path
        output_path = os.path.join(output_dir, self.pal_proj.arg_info.binary_name + f"_db{self.db_id}.json")
        with open(output_path, "r+") as f:
            content = f.read()
            f.seek(0, 0)
            f.write(val.strip().split("\n")[-1] + "\n" + content)

    def store_pruned_node(self, callsites: Iterable, node_addr):
        """
        Mark a node as out of scope
        """
        prefix_key = self._gen_prefix_key(callsites)
        node_key = prefix_key + hex(node_addr) + ":scope"
        self.r.set(node_key, 0)

    def store_redirect_info(self, callsites: Iterable, redirect_src_addr, redirect_tar_addr):
        """
        Store a redirect callsite info
        """
        prefix_key = self._gen_prefix_key(callsites)
        info_key = prefix_key + hex(redirect_src_addr) + ":redirect"
        self.r.set(info_key, redirect_tar_addr)
        log.debug(f"Stored redirect info for {hex(redirect_src_addr)} -> {hex(redirect_tar_addr)}")

    def store_symbol_num(self, symbol_num: int):
        """
        Store the total number of symbols
        """
        proc_name = os.path.basename(self.pal_proj.angr_project.filename)
        self.r.set(f"{proc_name}:.symbol_num", symbol_num)

    def store_empty_context(self, callsites, nodes: Iterable):
        prefix_key = self._gen_prefix_key(callsites)
        for node in nodes:
            node_prefix_key = prefix_key + hex(node.addr) + ":"
            self.r.set(node_prefix_key + "unum", 0)
            self.r.set(node_prefix_key + "rnum", 0)

    def store_taint_summary(self, callsites, block_key, taint_summary: TaintSummary):
        """
        cs1:cs2:...:bb_addr:
        :return:
        """
        unique_id = 0
        id_to_taint = {}
        taint_def_use = defaultdict(set)
        # load
        prefix_key = self._gen_prefix_key(callsites)
        prefix_key = prefix_key + hex(block_key) + ":"

        if self.pal_proj.arg_info.args.eval_mode:
            self.prefix_statistic_set.add(prefix_key)

        log.debug(f"Storing taint summary of {prefix_key}")

        def assign_unique_id(taint_tag: Tuple):
            # already assigned id, just return it
            if taint_tag in id_to_taint.values():
                return list(id_to_taint.keys())[list(id_to_taint.values()).index(taint_tag)]
            # assign unique id
            nonlocal unique_id
            id_to_taint[unique_id] = taint_tag
            unique_id += 1
            return unique_id - 1

        for defined_k, defined in taint_summary._state_defined.items():
            def_type = LOOKUP_FMT[defined_k]

            for defined_off, defined_sz in defined:

                if defined_k == TaintType.REG and \
                    defined_off not in list(map(lambda x: register_to_offset(x, self.pal_proj.angr_project),
                                                GENERAL_REGS_x64)):
                    continue

                if defined_k != TaintType.SYM:
                    off = defined_off if defined_k != TaintType.REG else \
                        PAL_ISA.register_to_id(self.pal_proj.angr_project, defined_off, defined_sz)
                    defined_fmt = (def_type, off, defined_sz)
                else:
                    defined_fmt = (def_type, str(defined_off), 1)

                defined_id = assign_unique_id(defined_fmt)

                used_taints = taint_summary.load(defined_k, defined_off, defined_sz, adjust_stack=False)
                if not len(used_taints):
                    used_fmt = ("empty", 0, 0)
                    used_id = assign_unique_id(used_fmt)
                    taint_def_use[defined_id].add(used_id)
                    continue

                for used_tag in used_taints:
                    if used_tag.function is None:
                        use_type, off, sz = used_tag.metadata["tagged_tp"], used_tag.metadata["tagged_off"], \
                                        used_tag.metadata["tagged_sz"]
                        if use_type == "symbol":
                            off = str(off)
                        elif use_type == "register":
                            off = PAL_ISA.register_to_id(self.pal_proj.angr_project, off, sz)
                        used_fmt = (use_type, off, sz)
                    else:
                        # get taint function
                        taint_sys_name = "syscall_" + re.sub(r"[0-9]+", "", used_tag.metadata["tagged_by"])
                        used_fmt = (taint_sys_name, used_tag.metadata["tagged_tp"], used_tag.metadata["tagged_off"])

                    used_id = assign_unique_id(used_fmt)
                    taint_def_use[defined_id].add(used_id)

        num_units, num_relations = len(id_to_taint), len(taint_def_use)
        # store unit nums and relation nums, as key cs:bb:unum, cs:bb:rnum
        self.r.set(prefix_key + "unum", num_units)
        self.r.set(prefix_key + "rnum", num_relations)
        # store units (taint items) as key cs:bb:u:i
        for i in range(num_units):
            type, off, sz = id_to_taint[i]
            log.debug(f"Store taint unit: {(type, off, sz)}")
            # TODO(): now hard coded type: memory -> global,
            # TODO(): now hard coded symbol offset: sym_str -> uuid
            type = "global" if type == "memory" else type
            off = global_symmem_dict.symbol_to_uuid(off) if type == "symbol" else off
            try:
                rl_key = prefix_key + f"u:{i}"
                self.r.delete(rl_key)
                self.r.lpush(rl_key, type, off, sz)
            except:
                print('dbg')
                import IPython; IPython.embed()
        # store relations (taint flows) as key cs:bb:r:i
        for i, item in enumerate(taint_def_use.items()):
            k, v = item
            l = [k] + list(v)

            # evaluation statistic
            if self.pal_proj.arg_info.args.eval_mode:
                self.num_relations += len(v)

            rl_key = prefix_key + f"r:{i}"
            self.r.delete(rl_key)
            self.r.lpush(rl_key, *l)

        pass

    def _gen_prefix_key(self, callsites: Iterable) -> str:
        """
        Generate the prefix key for a given calling context.
        """
        proc_name = os.path.basename(self.pal_proj.angr_project.filename)
        prefix_key = f"{proc_name}:0x0:"
        for cs in callsites:
            prefix_key = prefix_key + hex(cs) + ":"
        return prefix_key