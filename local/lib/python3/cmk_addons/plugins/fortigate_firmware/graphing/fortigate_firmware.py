#!/usr/bin/env python3
"""Graph templates for FortiGate firmware metrics (placeholder)."""

try:
    from cmk.graphing.v1 import graph_info  # type: ignore
except Exception:  # pragma: no cover - graphing API not available on all editions
    graph_info = None  # type: ignore

if graph_info is not None:
    graph_info.update({
        # Graph definitions can be added here when visualization is required.
    })

