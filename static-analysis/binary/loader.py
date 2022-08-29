from angr import Project
from palantiri.arginfo import ArgInfo

import logging
from typing import Dict

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class Loader:
    """
    Top class of binary loader
    """
    def __init__(self, arginfo: ArgInfo, load_external=False):
        self.arginfo = arginfo

        optional_kwargs = {}

        if self.arginfo.dbgsym_path is not None:
            optional_kwargs["debug_symbols"] = self.arginfo.dbgsym_path

        if load_external:
            self._load_external_libraries()
        self.project: Project = self._load_binary(load_external=load_external, optional_args=optional_kwargs)   # angr project for binary file

    def _load_external_libraries(self):
        raise NotImplementedError()

    def _load_binary(self, *optional_args, **optional_kwargs) -> Project:
        raise NotImplementedError()

    def _disasm_binary(self):
        """
        generate disasm file for binary
        """
        raise NotImplementedError()

    def load_int(self, addr: int, size: int) -> int:
        """
        Load the content of memory at the specified address
        """
        val = self.project.loader.memory.load(addr=addr, n=size)
        return int.from_bytes(val, "little")

    def load_byte(self, addr: int, size: int) -> bytes:
        """
        Load the content of memory as raw bytes at the specified address
        """
        return self.project.loader.memory.load(addr=addr, n=size)

    def load_string(self, addr: int, max_size: int = 1000) -> str:
        """
        Load the string at the specified address
        """
        idx, string = 0, ""
        while idx < max_size:
            last_chr = self.load_int(addr + idx, 1)
            if last_chr == 0:
                break
            string += chr(last_chr)
            idx += 1
        else:
            log.warning(f'String "{string}..." exceeded the max size {max_size}')
        return string

    def get_section_info(self, sec_name: str) -> Dict:
        raise NotImplementedError()