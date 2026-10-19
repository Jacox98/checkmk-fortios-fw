#!/usr/bin/env python3

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    List,
    SingleChoice,
    SingleChoiceElement,
    String,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _severity_form(title: str, default: str) -> SingleChoice:
    return SingleChoice(
        title=Title(title),
        elements=[
            SingleChoiceElement("OK", Title("OK")),
            SingleChoiceElement("WARN", Title("WARN")),
            SingleChoiceElement("CRIT", Title("CRIT")),
            SingleChoiceElement("UNKNOWN", Title("UNKNOWN")),
        ],
        prefill=DefaultValue(default),
    )


def _status_severity_form(*, optional: bool) -> Dictionary:
    return Dictionary(
        title=Title("Severity by license status"),
        elements={
            "licensed": DictElement(
                required=not optional,
                parameter_form=_severity_form("Licensed", "OK"),
            ),
            "free_license": DictElement(
                required=not optional,
                parameter_form=_severity_form("Free license", "OK"),
            ),
            "registered": DictElement(
                required=not optional,
                parameter_form=_severity_form("Registered", "OK"),
            ),
            "no_license": DictElement(
                required=not optional,
                parameter_form=_severity_form("No license", "CRIT"),
            ),
            "unavailable": DictElement(
                required=not optional,
                parameter_form=_severity_form("Unavailable", "WARN"),
            ),
            "other": DictElement(
                required=not optional,
                parameter_form=_severity_form("Other/unknown", "WARN"),
            ),
        },
    )


def _expiry_form(*, optional: bool) -> Dictionary:
    return Dictionary(
        title=Title("Expiration thresholds"),
        elements={
            "warn_days": DictElement(
                required=not optional,
                parameter_form=Integer(
                    title=Title("WARN at days to expiry <="),
                    prefill=DefaultValue(14),
                ),
            ),
            "crit_days": DictElement(
                required=not optional,
                parameter_form=Integer(
                    title=Title("CRIT at days to expiry <="),
                    prefill=DefaultValue(3),
                ),
            ),
            "warn_severity": DictElement(
                required=not optional,
                parameter_form=_severity_form("Severity when in WARN window", "WARN"),
            ),
            "crit_severity": DictElement(
                required=not optional,
                parameter_form=_severity_form("Severity when in CRIT window", "CRIT"),
            ),
            "expired_severity": DictElement(
                required=not optional,
                parameter_form=_severity_form("Severity when expired", "CRIT"),
            ),
        },
    )


def _fortigate_license_parameters() -> Dictionary:
    return Dictionary(
        title=Title("FortiGate Licenses"),
        elements={
            "status_severity": DictElement(
                required=True,
                parameter_form=_status_severity_form(optional=False),
            ),
            "expiry": DictElement(
                required=True,
                parameter_form=_expiry_form(optional=False),
            ),
            "fortiguard_connectivity": DictElement(
                required=True,
                parameter_form=Dictionary(
                    title=Title("FortiGuard connectivity issue severity"),
                    elements={
                        "issue_severity": DictElement(
                            required=True,
                            parameter_form=_severity_form(
                                "Severity when connectivity issue detected",
                                "WARN",
                            ),
                        ),
                    },
                ),
            ),
            "ignore_modules": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Globally ignored modules"),
                    element_template=String(
                        title=Title("Module name (exact)"),
                    ),
                ),
            ),
            "overrides": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Per-module overrides"),
                    add_element_label=Label("Add override"),
                    element_template=Dictionary(
                        title=Title("Per-module override"),
                        elements={
                            "match": DictElement(
                                required=True,
                                parameter_form=String(
                                    title=Title("Module name or regular expression"),
                                    help_text=Help(
                                        "The matching mode below determines whether this is an exact "
                                        "module name or a Python regular expression."
                                    ),
                                ),
                            ),
                            "match_type": DictElement(
                                required=True,
                                parameter_form=SingleChoice(
                                    title=Title("Match type"),
                                    elements=[
                                        SingleChoiceElement("exact", Title("Exact")),
                                        SingleChoiceElement("regex", Title("Regex")),
                                    ],
                                    prefill=DefaultValue("exact"),
                                ),
                            ),
                            "ignore": DictElement(
                                required=False,
                                parameter_form=BooleanChoice(
                                    label=Label("Ignore this module"),
                                    prefill=DefaultValue(False),
                                ),
                            ),
                            "status_severity": DictElement(
                                required=False,
                                parameter_form=_status_severity_form(optional=True),
                            ),
                            "expiry": DictElement(
                                required=False,
                                parameter_form=_expiry_form(optional=True),
                            ),
                        },
                    ),
                ),
            ),
        },
    )


rule_spec_fortigate_license = CheckParameters(
    name="fortigate_license",
    title=Title("FortiGate Licenses"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=_fortigate_license_parameters,
)
