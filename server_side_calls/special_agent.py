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
    if "port" in params:
        args.extend(["--port", str(params["port"])])
    
    if "timeout" in params:
        args.extend(["--timeout", str(params["timeout"])])
    
    yield SpecialAgentCommand(command_arguments=args)

special_agent_fortigate = SpecialAgentConfig(
    name="fortigate",
    parameter_parser=noop_parser,
    commands_function=_agent_arguments
)
