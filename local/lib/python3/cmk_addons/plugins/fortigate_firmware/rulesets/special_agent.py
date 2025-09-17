#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Integer,
    Password,
    DefaultValue,
    BooleanChoice,
    migrate_to_password,
)
try:
    from cmk.rulesets.v1.form_specs import SingleChoice, SingleChoiceElement  # type: ignore
except Exception:  # pragma: no cover - fallback for older CheckMK builds
    SingleChoice = None  # type: ignore
    SingleChoiceElement = None  # type: ignore

from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def branch_choice():
    if SingleChoice is not None and SingleChoiceElement is not None:
        return SingleChoice(
            title=Title("Branch upgrade severity"),
            help_text=Help(
                "How to rate availability of a newer FortiOS branch (e.g. 7.4 -> 7.6)."
            ),
            elements=[
                SingleChoiceElement("critical", Title("Critical: treat branch upgrades as CRIT candidate")),
                SingleChoiceElement("warn", Title("Warn only: branch upgrades are non-critical")),
            ],
            prefill=DefaultValue("critical"),
        )

    return BooleanChoice(
        title=Title("Treat branch upgrades as critical"),
        help_text=Help(
            "Enabled: branch change may lead to CRIT depending on thresholds.\n"
            "Disabled: branch change reported as WARN with an explicit note."
        ),
        prefill=DefaultValue(True),
    )


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
                parameter_form=branch_choice(),
            ),
            "ok_if_unmatured_branch": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("OK when only immature branch upgrades exist"),
                    help_text=Help(
                        "Return OK if the installed firmware is the newest in its branch and all newer branches "
                        "only offer immature images."
                    ),
                    prefill=DefaultValue(False),
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
