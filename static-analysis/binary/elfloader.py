import angr
from cle.backends.elf.regions import ELFSection
from angr import Project

from palantiri.arginfo import ArgInfo
from .loader import Loader

from typing import Dict, Optional
from pathlib import Path
import os
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class ELFLoader(Loader):
    """
    Loader class for ELF format binaries
    """
    def __init__(self, arginfo: ArgInfo):
        super().__init__(arginfo)
        self._disasm_binary()

    def _load_external_libraries(self):
        """
        Get external libraries info
        """
        external_lib_path = Path(self.arginfo.binary_output_path).joinpath(self.arginfo.binary_name + "_libs.txt")
        os.system(f"ldd {self.arginfo.binary_file_path} > {external_lib_path}")

        # parse externals
        with open(external_lib_path, "r") as f:
            for line in f.readlines():
                if line.find("linux-vdso") >= 0 or line.find("ld") >= 0:
                    continue
                libname, libpaths = line.split("=>")
                libname = libname.strip()
                if libname.find("linux-vdso") >= 0 or libname.find("ld") >= 0:
                    continue
                libpath = libpaths.split()[0]
                os.system(f"cp {libpath} {os.path.join(self.arginfo.libs_output_path, libname)}")



    def _load_binary(self, base_addr: Optional[int]=None, optional_args: Optional[Dict]=None, auto_load_libs=False,
                     **kwargs):
        """
        generate angr project for binary
        """
        main_opts = {}
        if base_addr is not None:
            main_opts["base_addr"] = base_addr

        load_options = {"main_opts": main_opts}
        # set load options
        if optional_args is not None:
            optional_args: Dict
            for k, v in optional_args.items():
                if k == "debug_symbols":
                    main_opts["debug_symbols"] = v
                elif k == "main_opts" and isinstance(v, dict):
                    main_opts.update(v)
                elif k == "main_opts" and not isinstance(v, dict):
                    pass
                else:
                    load_options[k] = v

        binary = self.arginfo.binary_file_path
        log.info(f"Loading binary file {binary}...")

        # load lib option
        load_external_libs = kwargs.pop("load_external", None)
        if load_external_libs:
            lib_dir = self.arginfo.libs_output_path
            lib_files = []
            for file in Path(lib_dir).iterdir():
                if file.is_file():
                    lib_files.append(file.stem)
                    log.info(f"External library found at {str(file)}")
            p = Project(binary, main_opts=main_opts, auto_load_libs=auto_load_libs, force_load_libs=lib_files,
                        lib_opts=None, ld_path=[lib_dir], use_system_libs=False)
        else:
            # load binary
            p = Project(binary, main_opts=main_opts, auto_load_libs=auto_load_libs, load_options=load_options)
        return p

    def _disasm_binary(self):
        """
        generate disasm file for binary
        """
        disasm_outpath = Path(self.arginfo.binary_output_path).joinpath(self.arginfo.binary_name + "_asm.txt")
        log.info(f"Generating binary disassembly file to {disasm_outpath}")
        os.system(f"objdump -d {self.arginfo.binary_file_path} > {disasm_outpath}")

    def get_section_info(self, sec_name: str) -> Dict:
        """
        Get ELF format binary section info
        :param sec_name: a valid section name like .interp .plt .plt.got .text ...
        :return:
        """
        try:
            section: ELFSection = self.project.loader.main_object.sections_map[sec_name]
        except KeyError:
            log.error(f"Section {sec_name} is not a valid section in binary {self.arginfo.binary_name}.")
            return dict()

        section_info = {
            "offset": section.offset,
            "base": self.project.loader.main_object.mapped_base,
            "size": section.memsize,
            "vaddr_start": section.vaddr,
            "vaddr_end": section.vaddr + section.memsize
        }
        return section_info

