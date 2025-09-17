#!/usr/bin/env python3
"""Bakery plugin stub for fortigate_firmware.

The Checkmk bakery can use this module to add packaging rules for the special
agent or agent plugin if needed. Currently, no additional files are baked
because the special agent is shipped as part of the site.
"""

from __future__ import annotations

try:
    from cmk.base.cee.plugins.bakery.register import register_bakery_plugin
except Exception:  # pragma: no cover - bakery not available in raw edition
    register_bakery_plugin = None  # type: ignore

if register_bakery_plugin is not None:
    register_bakery_plugin(
        name="fortigate_firmware",
        files=[],
    )

