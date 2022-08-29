from palantiri.global_configs import *
from palantiri.structures.utils.anno_utils import get_abs_regions
from palantiri.structures.value_set.value_domains.abstract_region import AbstractType
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class InvalidType:
    NoRegions = 0,
    InvalidVal = 1,
    Always = 2,


special_function_and_param_set = {
    "ngx_http_trailers_filter": {"param": "rsi", "invalid_type": InvalidType.NoRegions},
}


class FunctionFilter:
    """
    Special Adaptor is used for magic heuristic, to determine whether or not we should step into some `KEY` functions.

    i.e. when a filter like ngx_output_filter(_, ngx_chain_t * out) is called, however param `out` is not set well, we
    will ignore such call.
    """
    def __init__(self):
        pass

    def handle_analyze(self, analyze_subject, init_state):
        func = analyze_subject.content
        if func.name not in special_function_and_param_set:
            return True
        invalid_param_and_valset = special_function_and_param_set[func.name]
        param, invalid_type = invalid_param_and_valset["param"], invalid_param_and_valset["invalid_type"]

        if invalid_type == InvalidType.Always:
            log.info(f"Special filter dismiss the analyze of {func.name} (Its always filtered)")
            return False

        reg_offset, size = init_state.arch.registers[param]
        try:
            param_valset = init_state.register_definitions.load(reg_offset, size)
        except:
            return True

        if invalid_type == InvalidType.NoRegions:
            # check value regions
            regions = list(filter(lambda region: region.type != AbstractType.Symbolic,
                                  get_abs_regions(init_state, param_valset)))
            if not len(regions):
                log.info(f"Special filter dismiss the analyze of {func.name} (Due to param {param} value-set: "
                         f"{param_valset} has no AbsRegions.)")
                return False

        return True


special_filter = FunctionFilter()