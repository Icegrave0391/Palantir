def getargs(binary_name: str):
    """
    specify arguments for evaluation
    """
    args = {}
    if binary_name.find("nginx") >= 0:
        args = {
            "loop_revisit_mode": True,
            "symbolic_ref_depth": 2,
            # "without_whole_segment": False,
        }
    elif binary_name.find("curl") >= 0:
        args = {
            "loop_revisit_mode": False,
            # "without_whole_segment": True,
        }
    elif binary_name.find("cp") >= 0:
        args = {
            "start_function": "copy_reg",
        }
    elif binary_name.find("sendmail") >= 0:
        args = {
            "loop_revisit_mode": False,
            "start_function": "collect",
            "mem_rw_upperbound": 70,
            "force_revisit": ("collect", 0x40fa6a),
        }
    elif binary_name.find("pure-ftpd") >= 0:
        args = {
            "loop_revisit_mode": False,
            "start_function": "parser",
        }
    elif binary_name.find("haproxy") >= 0:
        args = {
            "symbolic_ref_depth": 2,
        }
    elif binary_name.find("varnishd") >= 0:
        args = {
            "start_function": "VCLS_Poll",
        }
    elif binary_name.find("cupsd") >= 0:
        args = {
            "start_function": "update_job",
        }
    elif binary_name.find("httpd2") >= 0:
        args = {
            "without_whole_segment": True,
        }
    return args