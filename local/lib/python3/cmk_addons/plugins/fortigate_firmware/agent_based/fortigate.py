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
from datetime import datetime, timezone
import itertools, re, json

# =============================================================================
# FORTIGATE LICENSES (AGGREGATED SERVICE)
# =============================================================================

# Default rule parameters (can be overridden via WATO)
DEFAULT_LICENSE_PARAMS = {
    "status_severity": {           # overall default severity by module status
        "licensed": "OK",
        "free_license": "OK",    # set to OK if you treat free as OK
        "registered": "OK",
        "no_license": "CRIT",
        "unavailable": "WARN",
        "other": "WARN",
    },
    "expiry": {
        "warn_days": 14,
        "crit_days": 3,
        "warn_severity": "WARN",
        "crit_severity": "CRIT",
        "expired_severity": "CRIT",
    },
    "fortiguard_connectivity": {
        "issue_severity": "WARN",  # choose "WARN" or "CRIT" or "OK"
    },
    # List of module names to ignore globally
    "ignore_modules": [],
    # Per-module overrides (exact or regex match)
    # Example:
    # [
    #   {"match": "antivirus", "match_type": "exact", "ignore": False,
    #    "status_severity": {"licensed":"OK","free_license":"OK","no_license":"CRIT","other":"WARN"},
    #    "expiry": {"warn_days":30,"crit_days":7,"warn_severity":"WARN","crit_severity":"CRIT","expired_severity":"CRIT"}}
    # ]
    "overrides": [],
}

def _state_from_text(name: str) -> State:
    m = {"OK": State.OK, "WARN": State.WARN, "CRIT": State.CRIT, "UNKNOWN": State.UNKNOWN}
    return m.get(str(name).strip().upper(), State.UNKNOWN)

def _fmt_date(ts: int) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).date().isoformat()
    except Exception:
        return str(ts)

def _days_left(now_ts: int, exp_ts: int) -> int:
    return int((exp_ts - now_ts) // 86400)

def _match_override(name: str, overrides: list[dict]) -> dict | None:
    """Return first override that matches module name."""
    for ov in overrides or []:
        mtype = str(ov.get("match_type", "exact")).lower()
        pat = ov.get("match")
        if not pat:
            continue
        if mtype == "regex":
            try:
                if re.search(pat, name):
                    return ov
            except re.error:
                continue
        else:  # exact
            if name == pat:
                return ov
    return None

def _merge_params_for_module(module: str, params: dict) -> dict:
    """Merge defaults with per-module override, if any."""
    p = {**DEFAULT_LICENSE_PARAMS, **(params or {})}
    ov = _match_override(module, p.get("overrides"))
    if ov:
        # deep-merge status_severity / expiry if provided
        merged_status = {**p["status_severity"], **ov.get("status_severity", {})}
        merged_expiry = {**p["expiry"], **ov.get("expiry", {})}
        p = {**p, **ov}
        p["status_severity"] = merged_status
        p["expiry"] = merged_expiry
    return p

def discover_fortigate_license(section):
    """Aggregated service (one per host)."""
    if section and section.get("status") == "success":
        yield Service()

def check_fortigate_license(params, section):
    """Aggregated license evaluation with param support."""
    if not section:
        yield Result(state=State.UNKNOWN, summary="No license data received")
        return

    if "error" in section or section.get("status") == "error":
        msg = section.get("message") or section.get("error") or "Cannot retrieve license information"
        detail = section.get("detail")
        yield Result(state=State.WARN, summary=f"Cannot check licenses: {msg}", details=(detail or None))
        return

    if section.get("status") != "success":
        yield Result(state=State.WARN, summary="Cannot retrieve license information")
        return

    results = section.get("results") or {}
    if not isinstance(results, dict):
        yield Result(state=State.UNKNOWN, summary="Invalid license payload format")
        return

    # FortiGuard connectivity handling (not a license status)
    fortiguard_issue = False
    fortiguard_reason = None
    fg_entry = results.get("fortiguard")
    if isinstance(fg_entry, dict):
        connected = bool(fg_entry.get("connected", True))
        conn_issue = bool(fg_entry.get("connection_issue", False))
        if (not connected) or conn_issue:
            fortiguard_issue = True
            fortiguard_reason = "FortiGuard not connected" if not connected else "FortiGuard connection_issue=true"

    # Global ignores
    global_ignore = set(x.strip() for x in (params or {}).get("ignore_modules", []) if str(x).strip())

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    total_modules = 0
    licensed_modules = 0
    free_modules = 0
    no_license_modules = 0
    expired_list = []
    exp_crit_list = []
    exp_warn_list = []

    earliest_name = None
    earliest_ts = None
    earliest_days = None

    # Iterate modules
    for name, entry in results.items():
        if not isinstance(entry, dict):
            continue
        if name == "fortiguard":
            continue  # handled separately
        if name in global_ignore:
            continue

        total_modules += 1

        # Compute module-specific params (overrides)
        mp = _merge_params_for_module(name, params or {})

        if mp.get("ignore"):
            # Module explicitly ignored by override
            continue

        status_lower = str(entry.get("status") or "").lower()
        if status_lower == "licensed":
            licensed_modules += 1
        elif status_lower == "free_license":
            free_modules += 1
        elif status_lower == "no_license":
            no_license_modules += 1

        # Track earliest expiry
        exp_ts = entry.get("expires")
        if isinstance(exp_ts, (int, float, str)):
            try:
                exp_ts = int(exp_ts)
            except Exception:
                exp_ts = None
        else:
            exp_ts = None

        if exp_ts:
            dleft = _days_left(now_ts, exp_ts)
            if earliest_ts is None or exp_ts < earliest_ts:
                earliest_ts = exp_ts
                earliest_days = dleft
                earliest_name = name

            if dleft < 0:
                expired_list.append((name, exp_ts))
            elif dleft <= int(mp["expiry"]["crit_days"]):
                exp_crit_list.append((name, dleft, exp_ts))
            elif dleft <= int(mp["expiry"]["warn_days"]):
                exp_warn_list.append((name, dleft, exp_ts))

    # Build summary
    summary_parts = [
        f"Licensed: {licensed_modules}/{total_modules}",
        f"Free: {free_modules}",
        f"No license: {no_license_modules}",
    ]
    if earliest_ts is not None:
        if earliest_days is not None and earliest_days >= 0:
            summary_parts.append(f"Earliest expiry: {earliest_name} in {earliest_days}d ({_fmt_date(earliest_ts)})")
        else:
            summary_parts.append(f"Earliest expiry: {earliest_name} expired on {_fmt_date(earliest_ts)}")
    if fortiguard_issue:
        summary_parts.append("FortiGuard connectivity: issue")

    # Decide overall state
    overall = State.OK
    details_lines = []

    # Expiry driven states
    if expired_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["expired_severity"]))
        details_lines.append("Expired:")
        for name, ts in sorted(expired_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: expired on {_fmt_date(ts)}")

    if exp_crit_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["crit_severity"]))
        details_lines.append(f"Expiring within {(params or DEFAULT_LICENSE_PARAMS)['expiry']['crit_days']} days:")
        for name, dleft, ts in sorted(exp_crit_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: {dleft}d left (until {_fmt_date(ts)})")

    if exp_warn_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["warn_severity"]))
        details_lines.append(f"Expiring within {(params or DEFAULT_LICENSE_PARAMS)['expiry']['warn_days']} days:")
        for name, dleft, ts in sorted(exp_warn_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: {dleft}d left (until {_fmt_date(ts)})")

    # FortiGuard connectivity severity
    if fortiguard_issue:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["fortiguard_connectivity"]["issue_severity"]))
        details_lines.append(f"FortiGuard: {fortiguard_reason}")

    yield Result(
        state=overall,
        summary=("All licenses OK" if overall is State.OK else "License issues") + " | " + " | ".join(summary_parts),
        details="\n".join(details_lines) if details_lines else None,
    )

    # Perfdata
    yield Metric("licenses_total", total_modules)
    yield Metric("licenses_licensed", licensed_modules)
    yield Metric("licenses_free", free_modules)
    yield Metric("licenses_no_license", no_license_modules)
    yield Metric("licenses_expiring_soon", len(exp_warn_list) + len(exp_crit_list))
    yield Metric("licenses_expired", len(expired_list))
    if earliest_ts is not None and (earliest_days is not None) and earliest_days >= 0:
        yield Metric("days_to_earliest_expiry", earliest_days)

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
    if isinstance(section, dict):
        yield Service()

def check_fortigate_system(section):
    """Check function for FortiGate System"""
    if not isinstance(section, dict) or not section:
        yield Result(state=State.UNKNOWN, summary="No data received")
        return

    # Unified error handling: prefer structured errors from special agent
    if "error" in section or section.get("status") == "error":
        err_type = str(section.get("error", "")).lower()
        msg = section.get("message") or section.get("error") or "Request failed"
        detail = section.get("detail")

        # Map connectivity to UNKNOWN, auth/ssl/http to CRIT
        unknown_hints = ["no route to host", "failed to connect", "failed to establish", "dns", "resolution", "refused", "timed out", "timeout"]
        is_unknown = (
            err_type in ("connection", "timeout")
            or any(hint in str(msg).lower() for hint in unknown_hints)
            or (
                detail is not None
                and any(hint in str(detail).lower() for hint in unknown_hints)
            )
        )
        state = State.UNKNOWN if is_unknown else State.CRIT

        yield Result(state=state, summary=msg, details=(detail or None))
        return

    if section.get("status", "success") != "success":
        yield Result(state=State.CRIT, summary="FortiGate API request failed")
        return
    
    # Extract real FortiGate data structure
    results = section.get("results")
    if not isinstance(results, dict):
        results = {}

    version = section.get("version", results.get("version", "Unknown"))
    build = section.get("build", results.get("build", "Unknown"))
    serial = section.get("serial", results.get("serial", "Unknown"))

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
    if isinstance(section, dict):
        yield Service()

def check_fortigate_firmware(section):
    """Check function for Fortigate Firmware - Enhanced with CRITICAL logic"""
    if not isinstance(section, dict) or not section:
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
        version_match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(fw.get("version", "")))
        version_parts = (
            tuple(int(part) for part in version_match.groups())
            if version_match is not None
            else (0, 0, 0)
        )
        return (
            _to_int(fw.get("major")) if fw.get("major") is not None else version_parts[0],
            _to_int(fw.get("minor")) if fw.get("minor") is not None else version_parts[1],
            _to_int(fw.get("patch")) if fw.get("patch") is not None else version_parts[2],
            _to_int(fw.get("build")),
        )

    def _platform_id(data: Dict[str, Any]) -> Optional[str]:
        for key in ("platform-id", "platform_id", "platformId"):
            value = data.get(key)
            if value:
                return str(value)
        return None

    def _is_mature_fw(fw: Dict[str, Any]) -> bool:
        maturity = fw.get("maturity")
        if maturity is None:
            return False
        return str(maturity).strip().upper().startswith("M")

    current_tuple = _version_tuple(current_fw)
    current_major_int, current_minor_int = current_tuple[:2]
    current_build_int = current_tuple[3]

    if current_version == "Unknown" and current_tuple[:3] != (0, 0, 0):
        current_version = ".".join(str(part) for part in current_tuple[:3])
    elif current_version == "Unknown":
        yield Result(
            state=State.UNKNOWN,
            summary="Current FortiGate firmware version is missing",
        )
        return

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
    has_same_branch_updates = False
    next_branch_updates = []

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
            has_same_branch_updates = True
            if recommended_fw is None or fw_tuple < _version_tuple(recommended_fw):
                recommended_fw = fw
        else:
            next_branch_updates.append(fw)

        fw_major = _to_int(fw.get("major"))
        fw_minor = _to_int(fw.get("minor"))

        if fw_major == current_major_int and fw_minor == current_minor_int:
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
        if (
            _to_int(highest_fw.get("major")) == current_major_int
            and _to_int(highest_fw.get("minor")) == current_minor_int
        ):
            high_build = _to_int(highest_fw.get("build"))
            if high_build > current_build_int:
                builds_behind_latest = high_build - current_build_int
        else:
            builds_behind_latest = 0  # build gap meaningless across branches

        high_major = _to_int(highest_fw.get("major"))
        high_minor = _to_int(highest_fw.get("minor"))
        if high_major > current_major_int:
            major_versions_behind = high_major - current_major_int
        elif high_major == current_major_int and high_minor > current_minor_int:
            minor_versions_behind = high_minor - current_minor_int

    branch_change_available = bool(next_branch_updates)

    summary_parts = [f"Current: {current_version} build {current_build_str}"]
    if recommended_fw and recommended_fw is not highest_fw:
        rec_version = recommended_fw.get("version", "Unknown")
        rec_build = recommended_fw.get("build", 0)
        summary_parts.append(f"Recommended: {rec_version} build {rec_build}")
    if highest_fw:
        high_version = highest_fw.get("version", "Unknown")
        summary_parts.append(f"Highest available: {high_version}")
    summary = " | ".join(summary_parts)

    config = section.get("config", {})
    if not isinstance(config, dict):
        config = {}

    crit_value = config.get("critical_on_branch_change", True)
    if isinstance(crit_value, str):
        consider_branch_change_critical = crit_value.lower() not in ("warn", "false", "no", "off", "0")
    else:
        consider_branch_change_critical = bool(crit_value)

    ok_value = config.get("ok_if_unmatured_branch", False)
    if isinstance(ok_value, str):
        ok_if_unmatured_branch = ok_value.lower() in ("1", "true", "yes", "on")
    else:
        ok_if_unmatured_branch = bool(ok_value)

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

    if branch_change_available and not has_same_branch_updates:
        # Only feature branch available → never CRITICAL
        is_critical = False
        critical_reasons = []

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

    should_force_ok = False
    if ok_if_unmatured_branch and not is_critical:
        if branch_change_available and not has_same_branch_updates:
            if next_branch_updates and all(not _is_mature_fw(fw) for fw in next_branch_updates):
                should_force_ok = True
                details_parts.append("Override to OK: next-branch images are immature and allowed by configuration")

    if is_critical:
        state = State.CRIT
        status_prefix = "CRITICAL - System dangerously outdated"
    elif should_force_ok:
        state = State.OK
        status_prefix = "Current branch up to date (next branch immature)"
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
# FORTIGATE LICENSES (CONSOLIDATED, PARAMETERIZED)
# =============================================================================
# ---- Parser: be permissive so discovery still yields a service on parse error
def parse_fortigate_license(string_table):
    if not string_table:
        return {}  # empty dict -> discovery can still yield a service
    try:
        flat = list(itertools.chain.from_iterable(string_table))
        return json.loads(" ".join(flat))
    except Exception:
        return {"status": "error", "error": "parse", "message": "JSON parse failed"}

# ---- Defaults (tunable via WATO)
DEFAULT_LICENSE_PARAMS = {
    "status_severity": {
        "licensed": "OK",
        "free_license": "WARN",
        "no_license": "CRIT",
        "unavailable": "WARN",
        "other": "WARN",
    },
    "expiry": {
        "warn_days": 14,
        "crit_days": 3,
        "warn_severity": "WARN",
        "crit_severity": "CRIT",
        "expired_severity": "CRIT",
    },
    "fortiguard_connectivity": { "issue_severity": "WARN" },
    "ignore_modules": [],
    "overrides": [],  # list of dicts with match/match_type/ignore/status_severity/expiry
}

def _state_from_text(name: str) -> State:
    return {
        "OK": State.OK, "WARN": State.WARN, "CRIT": State.CRIT, "UNKNOWN": State.UNKNOWN
    }.get(str(name).strip().upper(), State.UNKNOWN)

def _fmt_date(ts: int) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).date().isoformat()
    except Exception:
        return str(ts)

def _days_left(now_ts: int, exp_ts: int) -> int:
    return int((exp_ts - now_ts) // 86400)

def _match_override(name: str, overrides: list[dict]) -> dict | None:
    for ov in overrides or []:
        mtype = str(ov.get("match_type", "exact")).lower()
        pat = ov.get("match")
        if not pat:
            continue
        if mtype == "regex":
            try:
                if re.search(pat, name):
                    return ov
            except re.error:
                continue
        else:
            if name == pat:
                return ov
    return None

def _merge_params_for_module(module: str, params: dict) -> dict:
    p = {**DEFAULT_LICENSE_PARAMS, **(params or {})}
    ov = _match_override(module, p.get("overrides"))
    if ov:
        merged_status = {**p["status_severity"], **ov.get("status_severity", {})}
        merged_expiry = {**p["expiry"], **ov.get("expiry", {})}
        p = {**p, **ov}
        p["status_severity"] = merged_status
        p["expiry"] = merged_expiry
    return p

# ---- Aggregated service (one per host)
def discover_fortigate_license(section):
    # Permissive discovery: if parser returned any dict, show the service
    if isinstance(section, dict):
        yield Service()

def check_fortigate_license(params, section):
    if not section:
        yield Result(state=State.UNKNOWN, summary="No license data received")
        return

    if "error" in section or section.get("status") == "error":
        msg = section.get("message") or section.get("error") or "Cannot retrieve license information"
        detail = section.get("detail")
        yield Result(state=State.WARN, summary=f"Cannot check licenses: {msg}", details=(detail or None))
        return

    if section.get("status") != "success":
        yield Result(state=State.WARN, summary="Cannot retrieve license information")
        return

    results = section.get("results") or {}
    if not isinstance(results, dict):
        yield Result(state=State.UNKNOWN, summary="Invalid license payload format")
        return

    # FortiGuard connectivity
    fortiguard_issue = False
    fortiguard_reason = None
    fg_entry = results.get("fortiguard")
    if isinstance(fg_entry, dict):
        connected = bool(fg_entry.get("connected", True))
        conn_issue = bool(fg_entry.get("connection_issue", False))
        if (not connected) or conn_issue:
            fortiguard_issue = True
            fortiguard_reason = "FortiGuard not connected" if not connected else "FortiGuard connection_issue=true"

    global_ignore = set(x.strip() for x in (params or {}).get("ignore_modules", []) if str(x).strip())
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    total_modules = licensed_modules = free_modules = no_license_modules = 0
    expired_list, exp_crit_list, exp_warn_list = [], [], []
    earliest_name = earliest_ts = earliest_days = None

    for name, entry in results.items():
        if not isinstance(entry, dict):
            continue
        if name == "fortiguard":
            continue
        if name in global_ignore:
            continue

        total_modules += 1
        mp = _merge_params_for_module(name, params or {})
        if mp.get("ignore"):
            continue

        status_lower = str(entry.get("status") or "").lower()
        if status_lower == "licensed":
            licensed_modules += 1
        elif status_lower == "free_license":
            free_modules += 1
        elif status_lower == "no_license":
            no_license_modules += 1

        exp_ts = entry.get("expires")
        try:
            exp_ts = int(exp_ts) if isinstance(exp_ts, (int, float, str)) and str(exp_ts).strip() else None
        except Exception:
            exp_ts = None

        if exp_ts:
            dleft = _days_left(now_ts, exp_ts)
            if earliest_ts is None or exp_ts < earliest_ts:
                earliest_ts, earliest_days, earliest_name = exp_ts, dleft, name

            if dleft < 0:
                expired_list.append((name, exp_ts))
            elif dleft <= int(mp["expiry"]["crit_days"]):
                exp_crit_list.append((name, dleft, exp_ts))
            elif dleft <= int(mp["expiry"]["warn_days"]):
                exp_warn_list.append((name, dleft, exp_ts))

    summary_parts = [
        f"Licensed: {licensed_modules}/{total_modules}",
        f"Free: {free_modules}",
        f"No license: {no_license_modules}",
    ]
    if earliest_ts is not None:
        if earliest_days is not None and earliest_days >= 0:
            summary_parts.append(f"Earliest expiry: {earliest_name} in {earliest_days}d ({_fmt_date(earliest_ts)})")
        else:
            summary_parts.append(f"Earliest expiry: {earliest_name} expired on {_fmt_date(earliest_ts)}")
    if fortiguard_issue:
        summary_parts.append("FortiGuard connectivity: issue")

    overall = State.OK
    details_lines = []

    if expired_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["expired_severity"]))
        details_lines.append("Expired:")
        for name, ts in sorted(expired_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: expired on {_fmt_date(ts)}")

    if exp_crit_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["crit_severity"]))
        details_lines.append(f"Expiring within {(params or DEFAULT_LICENSE_PARAMS)['expiry']['crit_days']} days:")
        for name, dleft, ts in sorted(exp_crit_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: {dleft}d left (until {_fmt_date(ts)})")

    if exp_warn_list:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["expiry"]["warn_severity"]))
        details_lines.append(f"Expiring within {(params or DEFAULT_LICENSE_PARAMS)['expiry']['warn_days']} days:")
        for name, dleft, ts in sorted(exp_warn_list, key=lambda x: x[1]):
            details_lines.append(f"  - {name}: {dleft}d left (until {_fmt_date(ts)})")

    if fortiguard_issue:
        overall = max(overall, _state_from_text((params or DEFAULT_LICENSE_PARAMS)["fortiguard_connectivity"]["issue_severity"]))
        details_lines.append(f"FortiGuard: {fortiguard_reason}")

    yield Result(
        state=overall,
        summary=("All licenses OK" if overall is State.OK else "License issues") + " | " + " | ".join(summary_parts),
        details="\n".join(details_lines) if details_lines else None,
    )

    yield Metric("licenses_total", total_modules)
    yield Metric("licenses_licensed", licensed_modules)
    yield Metric("licenses_free", free_modules)
    yield Metric("licenses_no_license", no_license_modules)
    yield Metric("licenses_expiring_soon", len(exp_warn_list) + len(exp_crit_list))
    yield Metric("licenses_expired", len(expired_list))
    if earliest_ts is not None and (earliest_days is not None) and earliest_days >= 0:
        yield Metric("days_to_earliest_expiry", earliest_days)

# ---- Itemized services (optional)
def discover_fortigate_license_item(section):
    if not section or section.get("status") != "success":
        return
    results = section.get("results") or {}
    if not isinstance(results, dict):
        return
    for name, entry in results.items():
        if not isinstance(entry, dict):
            continue
        if name == "fortiguard":
            continue
        yield Service(item=name)

def check_fortigate_license_item(item, params, section):
    if not section or section.get("status") != "success":
        yield Result(state=State.UNKNOWN, summary="No license data received")
        return

    results = section.get("results") or {}
    entry = results.get(item)
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary=f"Module {item}: no data")
        return

    p = _merge_params_for_module(item, params or {})
    if p.get("ignore") or (item in set(x.strip() for x in (params or {}).get("ignore_modules", []))):
        yield Result(state=State.OK, summary=f"{item}: ignored by rule")
        return

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    status_lower = str(entry.get("status") or "").lower()
    exp_ts = entry.get("expires")
    try:
        exp_ts = int(exp_ts) if isinstance(exp_ts, (int, float, str)) and str(exp_ts).strip() else None
    except Exception:
        exp_ts = None

    state = _state_from_text(p["status_severity"].get(status_lower, p["status_severity"].get("other", "WARN")))
    details = [f"Status: {status_lower or 'n/a'}"]

    if exp_ts:
        dleft = _days_left(now_ts, exp_ts)
        details.append(f"Expiry: {_fmt_date(exp_ts)} ({dleft}d left)")
        if dleft < 0:
            state = max(state, _state_from_text(p["expiry"]["expired_severity"]))
        elif dleft <= int(p["expiry"]["crit_days"]):
            state = max(state, _state_from_text(p["expiry"]["crit_severity"]))
        elif dleft <= int(p["expiry"]["warn_days"]):
            state = max(state, _state_from_text(p["expiry"]["warn_severity"]))

    yield Result(state=state, summary=f"{item}: {status_lower or 'n/a'}", details="\n".join(details))
    if exp_ts and dleft >= 0:
        yield Metric("days_to_expiry", dleft)

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

agent_section_fortigate_license = AgentSection(
    name="fortigate_license",
    parse_function=parse_fortigate_license,
)

check_plugin_fortigate_license = CheckPlugin(
    name="fortigate_license",
    service_name="FortiGate Licenses",
    discovery_function=discover_fortigate_license,
    check_function=check_fortigate_license,
    check_ruleset_name="fortigate_license",               # <-- add
    check_default_parameters=DEFAULT_LICENSE_PARAMS,      # <-- add
)

check_plugin_fortigate_license_item = CheckPlugin(
    name="fortigate_license_item",
    sections=["fortigate_license"],
    service_name="FortiGate License %s",
    discovery_function=discover_fortigate_license_item,
    check_function=check_fortigate_license_item,
    check_ruleset_name="fortigate_license",
    check_default_parameters=DEFAULT_LICENSE_PARAMS,
)
