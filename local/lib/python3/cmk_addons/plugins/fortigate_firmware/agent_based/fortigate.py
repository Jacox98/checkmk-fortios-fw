#!/usr/bin/env python3
"""
CheckMK Agent-based check plugin for FortiGate monitoring
Enhanced version with detailed firmware update information
"""

from cmk.agent_based.v2 import (
    AgentSection, 
    CheckPlugin, 
    Service, 
    Result, 
    State, 
    Metric
)
from typing import Any, Dict, Optional
import itertools
import json

# =============================================================================
# FORTIGATE SYSTEM
# =============================================================================

def parse_fortigate_system(string_table):
    """Parse fortigate_system section"""
    if not string_table:
        return None
    
    try:
        flatlist = list(itertools.chain.from_iterable(string_table))
        json_str = " ".join(flatlist)
        data = json.loads(json_str)
        return data
    except (json.JSONDecodeError, ValueError, TypeError):
        return {"error": "JSON parse failed"}

def discover_fortigate_system(section):
    """Discovery function for FortiGate System"""
    if section and section.get("status") == "success":
        yield Service()

def check_fortigate_system(section):
    """Check function for FortiGate System"""
    if not section:
        yield Result(state=State.UNKNOWN, summary="No data received")
        return

    # Unified error handling: prefer structured errors from special agent
    if "error" in section or section.get("status") == "error":
        err_type = str(section.get("error", "")).lower()
        msg = section.get("message") or section.get("error") or "Request failed"
        detail = section.get("detail")

        # Map connectivity to UNKNOWN, auth/ssl/http to CRIT
        unknown_hints = ["no route to host", "failed to connect", "failed to establish", "dns", "resolution", "refused", "timed out", "timeout"]
        is_unknown = err_type in ("connection", "timeout") or any(h in str(msg).lower() for h in unknown_hints) or any(h in str(detail).lower() for h in unknown_hints) if detail else False
        state = State.UNKNOWN if is_unknown else State.CRIT

        yield Result(state=state, summary=msg, details=(detail or None))
        return

    if section.get("status") != "success":
        yield Result(state=State.CRIT, summary="FortiGate API request failed")
        return
    
    # Extract real FortiGate data structure
    version = section.get("version", "Unknown")
    build = section.get("build", "Unknown") 
    serial = section.get("serial", "Unknown")
    
    results = section.get("results", {})
    hostname = results.get("hostname", "Unknown")
    model = results.get("model", "Unknown")
    model_name = results.get("model_name", "Unknown")
    
    summary = f"Version {version} Build {build}"
    details = f"Model: {model_name} {model}, Hostname: {hostname}, Serial: {serial}"
    
    yield Result(state=State.OK, summary=summary, details=details)
    
    # Metrics for trending
    try:
        version_clean = str(version).replace('v', '')
        version_parts = version_clean.split('.')
        if len(version_parts) >= 2:
            major = int(version_parts[0])
            minor = int(version_parts[1]) 
            patch = int(version_parts[2]) if len(version_parts) > 2 else 0
            version_numeric = major * 10000 + minor * 100 + patch
            yield Metric("version_numeric", version_numeric)
        
        if isinstance(build, (int, str)) and str(build).isdigit():
            yield Metric("build_number", int(build))
    except (ValueError, TypeError, AttributeError):
        pass

# =============================================================================
# FORTIGATE FIRMWARE
# =============================================================================

def parse_fortigate_firmware(string_table):
    """Parse fortigate_firmware section"""
    if not string_table:
        return None
    
    try:
        flatlist = list(itertools.chain.from_iterable(string_table))
        json_str = " ".join(flatlist)
        data = json.loads(json_str)
        return data
    except (json.JSONDecodeError, ValueError, TypeError):
        return {"error": "JSON parse failed"}

def discover_fortigate_firmware(section):
    """Discovery function for Fortigate Firmware"""
    if section:
        yield Service()

def check_fortigate_firmware(section):
    """Check function for Fortigate Firmware - Enhanced with CRITICAL logic"""
    if not section:
        yield Result(state=State.UNKNOWN, summary="No firmware data received")
        return

    # Unified error handling: prefer structured errors from special agent
    if "error" in section or section.get("status") == "error":
        err_type = str(section.get("error", "")).lower()
        msg = section.get("message") or section.get("error") or "Cannot retrieve firmware information"
        detail = section.get("detail")

        unknown_hints = [
            "no route to host",
            "failed to connect",
            "failed to establish",
            "dns",
            "resolution",
            "refused",
            "timed out",
            "timeout",
        ]
        is_unknown = (
            err_type in ("connection", "timeout")
            or any(h in str(msg).lower() for h in unknown_hints)
            or (detail and any(h in str(detail).lower() for h in unknown_hints))
        )
        # For firmware, connection issues -> UNKNOWN, other errors -> WARN (non-service-impacting)
        state = State.UNKNOWN if is_unknown else State.WARN

        yield Result(state=state, summary=f"Cannot check updates: {msg}", details=(detail or None))
        return

    status = section.get("status", "success")
    if status != "success":
        yield Result(state=State.WARN, summary="Cannot retrieve firmware information")
        return

    results_raw = section.get("results")
    results = dict(results_raw) if isinstance(results_raw, dict) else {}
    if "current" not in results and isinstance(section.get("current"), dict):
        results["current"] = section["current"]
    if "available" not in results and isinstance(section.get("available"), list):
        results["available"] = section["available"]

    current_fw = results.get("current") if isinstance(results.get("current"), dict) else {}
    available_raw = results.get("available") if isinstance(results.get("available"), list) else []

    current_version = current_fw.get("version") or "Unknown"
    current_build_value = current_fw.get("build")
    current_build_str = str(current_build_value) if current_build_value not in (None, "") else "Unknown"
    current_maturity = (current_fw.get("maturity") or "").upper()

    def _to_int(value: Any) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return 0

    def _version_tuple(fw: Dict[str, Any]) -> tuple[int, int, int, int]:
        return (
            _to_int(fw.get("major")),
            _to_int(fw.get("minor")),
            _to_int(fw.get("patch")),
            _to_int(fw.get("build")),
        )

    def _platform_id(data: Dict[str, Any]) -> Optional[str]:
        for key in ("platform-id", "platform_id", "platformId"):
            value = data.get(key)
            if value:
                return str(value)
        return None

    current_major_int = _to_int(current_fw.get("major"))
    current_minor_int = _to_int(current_fw.get("minor"))
    current_build_int = _to_int(current_fw.get("build"))
    current_tuple = _version_tuple(current_fw)

    current_platform_id = _platform_id(current_fw)
    available_fw = []
    skipped_incompatible = 0
    for fw in available_raw:
        if not isinstance(fw, dict):
            continue
        if fw.get("can_upgrade") is False:
            skipped_incompatible += 1
            continue
        if current_platform_id:
            fw_platform = _platform_id(fw)
            if fw_platform and fw_platform != current_platform_id:
                skipped_incompatible += 1
                continue
        available_fw.append(fw)

    if not available_fw:
        yield Result(
            state=State.OK,
            summary=f"System is up to date: {current_version}",
            details=f"Current: {current_version} build {current_build_str}",
        )
        yield Metric("updates_available", 0)
        return

    available_fw.sort(key=_version_tuple)

    newer_updates = []
    recommended_fw = None
    highest_fw = None
    security_updates = 0

    for fw in available_fw:
        fw_tuple = _version_tuple(fw)
        if fw_tuple <= current_tuple:
            continue

        newer_updates.append(fw)

        if (fw.get("maturity") or "").upper() == "M":
            security_updates += 1

        fw_major = _to_int(fw.get("major"))
        fw_minor = _to_int(fw.get("minor"))

        if fw_major == current_major_int and fw_minor == current_minor_int:
            if recommended_fw is None or fw_tuple < _version_tuple(recommended_fw):
                recommended_fw = fw

        if highest_fw is None or fw_tuple > _version_tuple(highest_fw):
            highest_fw = fw

    if not newer_updates:
        yield Result(
            state=State.OK,
            summary=f"System is up to date: {current_version}",
            details=f"Current: {current_version} build {current_build_str}",
        )
        yield Metric("updates_available", 0)
        return

    update_count = len(newer_updates)
    builds_behind_latest = 0
    major_versions_behind = 0
    minor_versions_behind = 0

    if highest_fw:
        high_build = _to_int(highest_fw.get("build"))
        if high_build > current_build_int:
            builds_behind_latest = high_build - current_build_int

        high_major = _to_int(highest_fw.get("major"))
        high_minor = _to_int(highest_fw.get("minor"))
        if high_major > current_major_int:
            major_versions_behind = high_major - current_major_int
        elif high_major == current_major_int and high_minor > current_minor_int:
            minor_versions_behind = high_minor - current_minor_int

    branch_change_available = any(
        (_to_int(fw.get("major")), _to_int(fw.get("minor")))
        != (current_major_int, current_minor_int)
        for fw in newer_updates
    )

    summary_parts = [f"Current: {current_version} build {current_build_str}"]
    if recommended_fw and recommended_fw is not highest_fw:
        rec_version = recommended_fw.get("version", "Unknown")
        rec_build = recommended_fw.get("build", 0)
        summary_parts.append(f"Recommended: {rec_version} build {rec_build}")
    if highest_fw:
        high_version = highest_fw.get("version", "Unknown")
        summary_parts.append(f"Highest available: {high_version}")
    summary = " | ".join(summary_parts)

    consider_branch_change_critical = True
    try:
        consider_branch_change_critical = bool(
            section.get("config", {}).get("critical_on_branch_change", True)
        )
    except Exception:
        consider_branch_change_critical = True

    is_critical_all = False
    critical_reasons_all = []
    if update_count >= 30:
        is_critical_all = True
        critical_reasons_all.append(f"Extremely outdated ({update_count} versions behind)")
    if major_versions_behind >= 2:
        is_critical_all = True
        critical_reasons_all.append(f"Major version gap ({major_versions_behind} major versions behind)")
    if builds_behind_latest >= 150:
        is_critical_all = True
        critical_reasons_all.append(f"Large build gap ({builds_behind_latest} builds behind)")
    if security_updates >= 8:
        is_critical_all = True
        critical_reasons_all.append(f"Multiple security updates missed ({security_updates} maintenance releases)")
    if current_maturity == "F" and update_count >= 20:
        is_critical_all = True
        critical_reasons_all.append("Current version deprecated (F-level) with many newer versions")
    if minor_versions_behind >= 4 and major_versions_behind == 0:
        is_critical_all = True
        critical_reasons_all.append(f"Multiple minor versions behind ({minor_versions_behind} minor versions)")

    def _same_branch_criticality():
        same_branch_updates = []
        same_branch_security = 0
        highest_same_branch = None
        for fw in newer_updates:
            fw_major = _to_int(fw.get("major"))
            fw_minor = _to_int(fw.get("minor"))
            if fw_major == current_major_int and fw_minor == current_minor_int:
                same_branch_updates.append(fw)
                if (fw.get("maturity") or "").upper() == "M":
                    same_branch_security += 1
                if highest_same_branch is None or _version_tuple(fw) > _version_tuple(highest_same_branch):
                    highest_same_branch = fw

        builds_behind_same = 0
        if highest_same_branch is not None:
            high_same_build = _to_int(highest_same_branch.get("build"))
            if high_same_build > current_build_int:
                builds_behind_same = high_same_build - current_build_int

        is_crit = False
        reasons = []
        if len(same_branch_updates) >= 30:
            is_crit = True
            reasons.append(
                f"Extremely outdated within branch ({len(same_branch_updates)} versions)"
            )
        if major_versions_behind >= 2:
            is_crit = True
            reasons.append(f"Major version gap ({major_versions_behind} major versions behind)")
        if builds_behind_same >= 150:
            is_crit = True
            reasons.append(f"Large build gap within branch ({builds_behind_same} builds behind)")
        if same_branch_security >= 8:
            is_crit = True
            reasons.append(
                f"Multiple security updates missed within branch ({same_branch_security} maintenance releases)"
            )
        if current_maturity == "F" and len(same_branch_updates) >= 20:
            is_crit = True
            reasons.append("Current version deprecated (F-level) with many newer in branch")
        return is_crit, reasons

    if consider_branch_change_critical:
        is_critical = is_critical_all
        critical_reasons = critical_reasons_all
    else:
        is_critical, critical_reasons = _same_branch_criticality()

    details_parts = []
    if recommended_fw:
        rec_type = recommended_fw.get("release-type", "Unknown")
        rec_maturity = recommended_fw.get("maturity", "Unknown")
        details_parts.append(
            f"Recommended update: {recommended_fw.get('version')} (Build {recommended_fw.get('build')}, {rec_type}, Maturity: {rec_maturity})"
        )

    if highest_fw and highest_fw is not recommended_fw:
        high_type = highest_fw.get("release-type", "Unknown")
        high_maturity = highest_fw.get("maturity", "Unknown")
        details_parts.append(
            f"Latest version: {highest_fw.get('version')} (Build {highest_fw.get('build')}, {high_type}, Maturity: {high_maturity})"
        )

    details_parts.append(f"Total {update_count} newer versions available")

    if security_updates > 0:
        details_parts.append(f"Security/maintenance updates: {security_updates}")

    if skipped_incompatible > 0:
        details_parts.append(
            f"Ignored {skipped_incompatible} incompatible images (can_upgrade=false or different platform)"
        )

    if is_critical:
        details_parts.append(f"CRITICAL: {'; '.join(critical_reasons)}")

    if is_critical:
        state = State.CRIT
        status_prefix = "CRITICAL - System dangerously outdated"
    elif (not consider_branch_change_critical) and branch_change_available:
        state = State.WARN
        status_prefix = "Feature release available (branch change not critical)"
        details_parts.append("Note: branch change is configured as non-critical")
    elif update_count >= 15:
        state = State.WARN
        status_prefix = "System significantly outdated"
    elif update_count >= 8:
        state = State.WARN
        status_prefix = "Multiple updates available"
    elif security_updates >= 3:
        state = State.WARN
        status_prefix = "Security updates available"
    else:
        state = State.WARN
        status_prefix = "Updates available"

    yield Result(
        state=state,
        summary=f"{status_prefix} | {summary}",
        details="\n".join(details_parts),
    )

    yield Metric("updates_available", update_count)
    yield Metric("security_updates", security_updates)

    if recommended_fw:
        rec_build_num = _to_int(recommended_fw.get("build"))
        if rec_build_num > current_build_int:
            builds_behind_recommended = rec_build_num - current_build_int
            yield Metric("builds_behind_recommended", builds_behind_recommended)

    if highest_fw:
        yield Metric("builds_behind_latest", builds_behind_latest)
        yield Metric("major_versions_behind", major_versions_behind)
        yield Metric("minor_versions_behind", minor_versions_behind)

# =============================================================================
# PLUGIN REGISTRATION
# =============================================================================

agent_section_fortigate_system = AgentSection(
    name="fortigate_system",
    parse_function=parse_fortigate_system,
)

check_plugin_fortigate_system = CheckPlugin(
    name="fortigate_system",
    service_name="FortiGate System",
    discovery_function=discover_fortigate_system,
    check_function=check_fortigate_system,
)

agent_section_fortigate_firmware = AgentSection(
    name="fortigate_firmware",
    parse_function=parse_fortigate_firmware,
)

check_plugin_fortigate_firmware = CheckPlugin(
    name="fortigate_firmware",
    service_name="FortiGate Firmware Updates",
    discovery_function=discover_fortigate_firmware,
    check_function=check_fortigate_firmware,
)

