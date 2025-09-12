#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.server_side_calls.v1 import noop_parser, SpecialAgentConfig, SpecialAgentCommand

def _agent_arguments(params, host_config):
    """Genera gli argomenti per l'esecuzione dello special agent"""
    args = [
        "--hostname", host_config.primary_ip_config.address or host_config.name,
        "--api-key", params["api_key"].unsafe(),
    ]
    
    # Parametri opzionali
    # Branch change criticality flag (accept bool or 'critical'/'warn')
    crit_param = params.get("critical_on_branch_change", True)
    if isinstance(crit_param, str):
        crit_flag = crit_param.lower() in ("critical", "true", "yes", "on", "1")
    else:
        crit_flag = bool(crit_param)

    if crit_flag:
        args.append("--branch-change-critical")
    else:
        args.append("--no-branch-change-critical")

    if "port" in params:
        args.extend(["--port", str(params["port"])])
    
    if "timeout" in params:
        args.extend(["--timeout", str(params["timeout"])])

    # OpenCVE integration (optional nested dictionary: 'opencve')
    ocve = params.get("opencve") or {}
    if ocve.get("enabled"):
        args.append("--opencve-enabled")
        base_url = ocve.get("base_url") or "https://app.opencve.io"
        vendor = ocve.get("vendor")
        product = ocve.get("product")
        username = ocve.get("username")
        password = ocve.get("password").unsafe() if ocve.get("password") else None
        conn_timeout = ocve.get("timeout") or 20
        list_limit = ocve.get("list_limit") or 10
        warn_th = ocve.get("warn_threshold") or 1
        crit_th = ocve.get("crit_threshold") or 5

        args.extend(["--opencve-base-url", str(base_url)])
        if username:
            args.extend(["--opencve-user", str(username)])
        if password is not None:
            args.extend(["--opencve-pass", str(password)])
        if vendor:
            args.extend(["--opencve-vendor", str(vendor)])
        if product:
            args.extend(["--opencve-product", str(product)])
        args.extend(["--opencve-conn-timeout", str(int(conn_timeout))])
        args.extend(["--opencve-list-limit", str(int(list_limit))])
        args.extend(["--opencve-warn-threshold", str(int(warn_th))])
        args.extend(["--opencve-crit-threshold", str(int(crit_th))])

    yield SpecialAgentCommand(command_arguments=args)

special_agent_fortigate_firmware = SpecialAgentConfig(
    name="fortigate",
    parameter_parser=noop_parser,
    commands_function=_agent_arguments
)
