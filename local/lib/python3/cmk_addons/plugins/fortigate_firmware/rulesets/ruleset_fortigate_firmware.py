#!/usr/bin/env python3
# Shebang needed only for editors

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    Dictionary,
    DictElement,
    Integer,
    Password,
    DefaultValue,
    migrate_to_password,
)
try:
    from cmk.rulesets.v1.form_specs import String  # type: ignore
    def string_field(title: str, help_text: str, default: str | None = None, required: bool = False):
        kwargs = {"title": Title(title), "help_text": Help(help_text)}
        if default is not None:
            kwargs["prefill"] = DefaultValue(default)
        return String(**kwargs)
except Exception:
    # Fallback: use Password field as a generic text input if String is unavailable
    def string_field(title: str, help_text: str, default: str | None = None, required: bool = False):  # type: ignore
        kwargs = {"title": Title(title), "help_text": Help(help_text)}
        if default is not None:
            kwargs["prefill"] = DefaultValue(default)
        return Password(**kwargs)
try:
    from cmk.rulesets.v1.form_specs import SingleChoice, SingleChoiceElement  # type: ignore
    def branch_choice():
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
except Exception:
    from cmk.rulesets.v1.form_specs import BooleanChoice  # type: ignore
    def branch_choice():
        return BooleanChoice(
            title=Title("Treat branch upgrades as critical"),
            help_text=Help(
                "Enabled: branch change may lead to CRIT depending on thresholds.\n"
                "Disabled: branch change reported as WARN with an explicit note."
            ),
            prefill=DefaultValue(True),
        )
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic

# Simple boolean for OpenCVE enable/disable
try:
    from cmk.rulesets.v1.form_specs import BooleanChoice as _BoolChoice  # type: ignore
    def enabled_choice():
        return _BoolChoice(
            title=Title("Enable OpenCVE"),
            help_text=Help("Enable querying OpenCVE for product CVEs."),
            prefill=DefaultValue(False),
        )
except Exception:
    def enabled_choice():  # type: ignore
        return Integer(
            title=Title("Enable OpenCVE"),
            help_text=Help("Set to 1 to enable, 0 to disable."),
            prefill=DefaultValue(0),
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
            # OpenCVE nested configuration
            "opencve": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("OpenCVE Integration"),
                    help_text=Help(
                        "Optionally query OpenCVE for the number of CVEs associated with a vendor/product.\n"
                        "Supports self-hosted OpenCVE via configurable base URL and Basic Auth."
                    ),
                    elements={
                        "enabled": DictElement(
                            required=False,
                            parameter_form=enabled_choice(),
                        ),
                        "base_url": DictElement(
                            required=False,
                            parameter_form=string_field(
                                "OpenCVE base URL",
                                "Base URL of OpenCVE instance (default https://app.opencve.io).",
                                default="https://app.opencve.io",
                            ),
                        ),
                        "username": DictElement(
                            required=False,
                            parameter_form=string_field(
                                "OpenCVE username",
                                "Username for Basic Auth (leave empty for public access if enabled).",
                            ),
                        ),
                        "password": DictElement(
                            required=False,
                            parameter_form=Password(
                                title=Title("OpenCVE password"),
                                help_text=Help("Password for Basic Auth (if required by your instance)."),
                                migrate=migrate_to_password,
                            ),
                        ),
                        "vendor": DictElement(
                            required=False,
                            parameter_form=string_field(
                                "Product vendor",
                                "OpenCVE vendor name (e.g. 'fortinet').",
                            ),
                        ),
                        "product": DictElement(
                            required=False,
                            parameter_form=string_field(
                                "Product name",
                                "OpenCVE product name (e.g. 'fortios').",
                            ),
                        ),
                        "timeout": DictElement(
                            required=False,
                            parameter_form=Integer(
                                title=Title("OpenCVE timeout (s)"),
                                help_text=Help("Timeout in seconds for OpenCVE requests (default 20)."),
                                prefill=DefaultValue(20),
                            ),
                        ),
                        "list_limit": DictElement(
                            required=False,
                            parameter_form=Integer(
                                title=Title("Max CVE IDs in details"),
                                help_text=Help("How many CVE IDs to show from first page (default 10)."),
                                prefill=DefaultValue(10),
                            ),
                        ),
                        "warn_threshold": DictElement(
                            required=False,
                            parameter_form=Integer(
                                title=Title("WARN at CVE count >="),
                                help_text=Help("Set to 0 to disable WARN threshold."),
                                prefill=DefaultValue(1),
                            ),
                        ),
                        "crit_threshold": DictElement(
                            required=False,
                            parameter_form=Integer(
                                title=Title("CRIT at CVE count >="),
                                help_text=Help("Set to a high value to reduce noise."),
                                prefill=DefaultValue(5),
                            ),
                        ),
                    },
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
