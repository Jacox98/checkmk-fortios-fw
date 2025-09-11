#!/usr/bin/env python3
# Minimal manual check ruleset to satisfy GUI lookup for static checks

from cmk.rulesets.v1.form_specs import Dictionary, Title
from cmk.rulesets.v1.rule_specs import ManualCheck, Topic


def _empty_form():
    # No parameters needed for manual assignment; keep placeholder
    return Dictionary(title=Title("FortiGate Firmware (manual assignment)"), elements={})


rule_spec_fortigate_firmware_manual = ManualCheck(
    name="fortigate_firmware",
    title=Title("FortiGate Firmware"),
    topic=Topic.NETWORKING,
    parameter_form=_empty_form,
)

