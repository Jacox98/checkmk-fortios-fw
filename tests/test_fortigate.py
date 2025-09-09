import os
import sys
import json

# Ensure the stub cmk package is importable
sys.path.insert(0, os.path.dirname(__file__))

from agent_based.fortigate import parse_fortigate_system, check_fortigate_system
from cmk.agent_based.v2 import State, Metric


def test_parse_fortigate_system_valid():
    sample = {"status": "success", "version": "v7.0.12", "build": "1234"}
    string_table = [[json.dumps(sample)]]
    assert parse_fortigate_system(string_table) == sample


def test_parse_fortigate_system_invalid():
    result = parse_fortigate_system([["{invalid"]])
    assert result == {"error": "JSON parse failed"}


def test_check_fortigate_system_ok():
    section = {
        "status": "success",
        "version": "v7.0.12",
        "build": "1234",
        "serial": "FGT123",
        "results": {"hostname": "forti1", "model": "FGT", "model_name": "FortiGate"},
    }
    results = list(check_fortigate_system(section))
    assert results[0].state == State.OK
    assert "Version v7.0.12" in results[0].summary
    assert any(isinstance(r, Metric) and r.name == "build_number" and r.value == 1234 for r in results[1:])


def test_check_fortigate_system_error():
    section = {"error": "JSON parse failed"}
    results = list(check_fortigate_system(section))
    assert results[0].state == State.CRIT
