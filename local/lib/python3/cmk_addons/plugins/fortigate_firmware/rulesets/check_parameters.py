#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Checkbox,
    DefaultValue,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, Title, Help


def _formspec():
    return Dictionary(
        title=Title("FortiGate Firmware parameters"),
        elements={
            "critical_on_branch_change": DictElement(
                parameter_form=Checkbox(
                    title=Title("Consider branch change critical"),
                    help_text=Help(
                        "If enabled, changing to a newer FortiOS branch (e.g. 7.4 → 7.6) "
                        "may trigger a CRIT state based on thresholds. Disable to only WARN "
                        "when a newer branch exists while staying CRIT-free within a mature branch."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
        },
    )


rule_spec_fortigate_firmware_params = CheckParameters(
    name="fortigate_firmware",
    topic=Topic.NETWORKING,
    title=Title("FortiGate Firmware"),
    parameter_form=_formspec,
)

