from functools import cmp_to_key

import logging
import claripy
from typing import Optional, Tuple, Union

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def bv_to_str(expr: claripy.ast.Base) -> str:
    return str(expr).strip("<BV" + str(expr.size())).strip(">").strip()


def bvv_to_int(bvv: claripy.ast.BV):
    """
    convert bvv to its correct format:
    s + 0xffff...fff => s - 1
    s * 0xffff...fff => s
    """

    # MASK = {
    #     64: 0xffff_ffff_ffff_ffff,
    #     32: 0xffff_ffff,
    #     16: 0xffff,
    #     8: 0xff
    # }
    def _MASK(x):
        return 2 ** x - 1

    assert bvv.op == "BVV"
    origin_size = bvv.size()
    conc = bvv._model_concrete.value
    sig_bit = conc >> (bvv.size() - 1)
    if not sig_bit:
        # return conc
        # reserve its size in case of concat
        return conc
    return -((conc ^ _MASK(bvv.size())) + 1)


def resize_bvs(expr: claripy.ast.Base, to_size: int) -> claripy.ast.Base:
    """
    Simply resize the linear expression (k * symvar + b) and do nothing
    :param to_size: bit width size
    """
    if not isinstance(expr, claripy.ast.Base):
        return expr

    if expr.op == "BVS":
        return claripy.BVS(expr.args[0], to_size, explicit_name=True)
    elif expr.op == "BVV":
        return expr[to_size-1:0]
    else:
        if expr.op not in ["__mul__", "__add__", "__sub__"]:
            return claripy.BVS("TOP", to_size, explicit_name=True)

        symvar = extract_bvs(expr)
        b = bvv_to_int(expr.replace(symvar, claripy.BVV(0, expr.size())))
        k = bvv_to_int(expr.replace(symvar, claripy.BVV(1, expr.size()))) - b
        new_symvar = claripy.BVS(symvar.args[0], to_size, explicit_name=True)
        return simplify_ast(k * new_symvar + b)


def extract_bvs(expr: claripy.ast.Base) -> Optional[claripy.ast.Base]:
    """
    Extract the BVS value from linear symbolic expression
    """
    if not isinstance(expr, claripy.ast.Base):
        return None
    elif expr.op == "BVS":
        return expr
    elif expr.op == "BVV":
        return None
    else:
        for expr_arg in expr.args:
            res = extract_bvs(expr_arg)
            if res is not None:
                return res
        return None


def extract_sym_and_off(symaddr: str) -> Optional[Tuple[str, int]]:
    """
    Extract the symbolic base and offset of the linear symbolic memory address.
    """
    if symaddr.find("+") >= 0:
        positive = True
    elif symaddr.find("-") >= 0:
        positive = False
    else:
        return symaddr, 0
    symbase, off_str = symaddr.split("+") if positive else symaddr.split("-")
    symbase = symbase.strip()
    offset = int(off_str.strip(), 16)
    offset = offset if positive else -offset
    return symbase, offset


def simplify_ast(expr: claripy.ast.Base) -> Union[claripy.ast.Base, int]:
    """
    A 'simple' simplification method to solve symbolic expression.
    Note that only linear expression is allowed.
    """
    bits = expr.size()
    # filter invalid expression
    valid_op_list = ["BVV", "BVS", "__add__", "__mul__", "__sub__"]

    if expr.op not in valid_op_list:
        # log.error(f"Simplification doesn't support expr: {expr} with op: {expr.op}.")
        return claripy.BVS("TOP", bits, explicit_name=True)
    elif expr.op not in ["BVV", "BVS"]:
        if any(expr_arg.op not in valid_op_list for expr_arg in expr.args):
            return claripy.BVS("TOP", bits, explicit_name=True)

    variables_set = set(expr.variables)

    # filter TOP based expression
    if "TOP" in variables_set:
        return claripy.BVS("TOP", bits, explicit_name=True)

    # filter multi-symbol expression
    variables_without_bases = variables_set
    if len(variables_without_bases) > 1:
        return claripy.BVS("TOP", bits, explicit_name=True)
    # filter formats like a * stack_base or a * heap_base
    if expr.op == "__mul__" and variables_set & {"stack_base", "heap_base"}:
        return claripy.BVS("TOP", bits, explicit_name=True)
    elif not variables_without_bases:
        return expr

    # start simplify
    # 1. use claripy's builtin simplification as a naive simplifier
    naive_simplified_expr = claripy.simplify(expr)
    if naive_simplified_expr.op in ["BVS", "BVV", "__mul__"]:
        return naive_simplified_expr
    # 2. simplify linear expression a * sym + b   or  stack_base + a * sym + b
    try:
        assert naive_simplified_expr.op in ["__add__"]
    except AssertionError:
        return claripy.BVS("TOP", bits, explicit_name=True)
    sorted_args = sorted(naive_simplified_expr.args, key=cmp_to_key(_sort_args))

    s_expr = None
    for arg in sorted_args:
        if arg.op == "BVS":
            s_expr = s_expr + arg if s_expr is not None else arg
        elif arg.op == "__mul__":
            try:
                conc_val = next(iter(filter(lambda x: x.op == "BVV", arg.args)))
                conc = bvv_to_int(conc_val)
                sym_val = next(iter(filter(lambda x: x.op == "BVS", arg.args)))
            except:
                return claripy.BVS("TOP", bits, explicit_name=True)
            if conc < 0 and sym_val.args[0] in ["stack_base", "heap_base"]:
                return claripy.BVS("TOP", bits, explicit_name=True)
            s_expr = s_expr + conc * sym_val if s_expr is not None else conc * sym_val
        elif arg.op == "BVV":
            conc = bvv_to_int(arg)
            if s_expr is not None:
                s_expr = s_expr + conc if conc >= 0 else s_expr - abs(conc)
            else:
                s_expr = conc if conc >= 0 else -abs(conc)
        else:
            return claripy.BVS("TOP", bits, explicit_name=True)
    return s_expr


def _sort_args(arg1, arg2):
    if arg1.op == "BVS" and arg1.args[0] in ["stack_base", "heap_base"]:
        return -1
    elif arg2.op == "BVS" and arg2.args[0] in ["stack_base", "heap_base"]:
        return 1
    elif arg1.variables:
        return -1
    elif arg2.variables:
        return 1
    else:
        return 0