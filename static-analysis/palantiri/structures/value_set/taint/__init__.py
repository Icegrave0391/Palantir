from .taint_summary import TaintSummary, TaintType


def str_to_taint_type(str_type: str) -> int:
    if "reg" in str_type or "register" in str_type:
        return TaintType.REG
    elif "stack" in str_type:
        return TaintType.STACK
    elif "heap" in str_type:
        return TaintType.HEAP
    elif "mem" in str_type or "global" in str_type or "memory" in str_type:
        return TaintType.GLB
    elif "sym" in str_type or "symbolic" in str_type or "symbol" in str_type:
        return TaintType.SYM
    else:
        return TaintType.SYSCALL


def str_to_tagged_tp(str_type: str) -> str:
    if "reg" in str_type or "register" in str_type:
        return "register"
    elif "stack" in str_type:
        return "stack"
    elif "heap" in str_type:
        return "heap"
    elif "mem" in str_type or "global" in str_type or "memory" in str_type:
        return "memory"
    elif "sym" in str_type or "symbolic" in str_type or "symbol" in str_type:
        return "symbol"
    else:
        return "syscall"