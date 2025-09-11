#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Integer,
    Password,
    DefaultValue,
    DropdownChoice,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _parameter_form():
    return Dictionary(
        title=Title("FortiGate Firmware (Special Agent)"),
        help_text=Help(
            "Query FortiGate via REST API to collect system and firmware information. "
            "Provide an API key with read access."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API key"),
                    help_text=Help(
                        "FortiGate API token used for authentication. "
                        "Create it in System > Administrators with a read-only profile."
                    ),
                    migrate=migrate_to_password,
                ),
            ),
            "critical_on_branch_change": DictElement(
                required=False,
                parameter_form=DropdownChoice(
                    title=Title("Branch upgrade severity"),
                    help_text=Help(
                        "How to rate availability of a newer FortiOS branch (e.g. 7.4 -> 7.6)."
                    ),
                    choices=[
                        (True, "Critical: treat branch upgrades as CRIT candidate"),
                        (False, "Warn only: branch upgrades are non-critical"),
                    ],
                    prefill=DefaultValue(True),
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    help_text=Help("FortiGate HTTPS port (default 443)."),
                    prefill=DefaultValue(443),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Connection timeout (s)"),
                    help_text=Help("Timeout in seconds for API requests (default 30)."),
                    prefill=DefaultValue(30),
                ),
            ),
        },
    )


rule_spec_fortigate_firmware = SpecialAgent(
    topic=Topic.NETWORKING,
    name="fortigate",
    title=Title("FortiGate Firmware"),
    parameter_form=_parameter_form,
)

