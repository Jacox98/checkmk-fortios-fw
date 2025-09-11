#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Integer,
    Password,
    DefaultValue,
    migrate_to_password,
)
try:  # Compatibility across Checkmk builds
    from cmk.rulesets.v1.form_specs import BooleanChoice  # type: ignore
    def bool_choice(title, help_text, prefill):
        return BooleanChoice(title=title, help_text=help_text, prefill=prefill)
except Exception:  # Fallback to dropdown if BooleanChoice is unavailable
    from cmk.rulesets.v1.form_specs import DropdownChoice  # type: ignore
    def bool_choice(title, help_text, prefill):
        return DropdownChoice(
            title=title,
            help_text=help_text,
            choices=[(True, "Yes"), (False, "No")],
            prefill=prefill,
        )
from cmk.rulesets.v1 import Label, Title, Help
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("FortiGate Firmware (Special Agent)"),
        help_text=Help(
            "Queries FortiGate via REST API to collect system and firmware information. "
            "Provide an API key with read access."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API key"),
                    help_text=Help(
                        "FortiGate API token used for authentication. "
                        "Create it in System → Administrators with a read-only profile."
                    ),
                    migrate=migrate_to_password,
                ),
            ),
            "critical_on_branch_change": DictElement(
                required=False,
                parameter_form=bool_choice(
                    title=Title("Treat branch upgrades as critical"),
                    help_text=Help(
                        "Controls severity when a newer FortiOS branch is available (e.g. 7.4 → 7.6).\n"
                        "Enabled: branch change may lead to CRIT depending on thresholds.\n"
                        "Disabled: branch change reported as WARN with an explicit note."
                    ),
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
    parameter_form=_formspec,
)
