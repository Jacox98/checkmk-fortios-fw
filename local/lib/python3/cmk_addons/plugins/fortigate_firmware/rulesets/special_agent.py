#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Integer,
    Password,
    DefaultValue,
    Checkbox,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic, Help, Title

def _formspec():
    return Dictionary(
        title=Title("Fortigate Firmware via REST API"),
        help_text=Help(
            "Monitor FortiGate firmware via REST API. "
            "Requires valid API key with read permissions for system endpoints."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API Key"),
                    help_text=Help(
                        "FortiGate API key for authentication. "
                        "Generate in System > Administrators with read-only profile."
                    ),
                    migrate=migrate_to_password,
            ),
        ),
        "critical_on_branch_change": DictElement(
            required=False,
            parameter_form=Checkbox(
                title=Title("Consider branch change critical"),
                help_text=Help(
                    "If enabled, moving to a newer FortiOS branch (e.g. 7.4 → 7.6) can contribute to a CRIT state. "
                    "Disable to report branch changes as WARN only."
                ),
                prefill=DefaultValue(True),
            ),
        ),
        "port": DictElement(
            required=False,
            parameter_form=Integer(
                title=Title("HTTPS Port"),
                help_text=Help("FortiGate HTTPS port"),
                    prefill=DefaultValue(443),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Connection Timeout"),
                    help_text=Help("Timeout in seconds for API requests"),
                    prefill=DefaultValue(30),
                ),
            ),
        }
    )

rule_spec_fortigate_firmware = SpecialAgent(
    topic=Topic.NETWORKING,
    name="fortigate",
    title=Title("Fortigate Firmware"),
    parameter_form=_formspec
)
