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
    
    if "error" in section:
        yield Result(state=State.CRIT, summary=f"Error: {section['error']}")
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
    """Discovery function for FortiGate Firmware"""
    if section:
        yield Service()

def check_fortigate_firmware(section):
    """Check function for FortiGate Firmware Updates - Enhanced with CRITICAL logic"""
    if not section:
        yield Result(state=State.UNKNOWN, summary="No firmware data received")
        return
    
    if "error" in section:
        yield Result(state=State.WARN, summary=f"Cannot check updates: {section['error']}")
        return
    
    if section.get("status") != "success":
        yield Result(state=State.WARN, summary="Cannot retrieve firmware information")
        return
    
    results = section.get("results", {})
    current_fw = results.get("current", {})
    available_fw = results.get("available", [])
    
    current_version = current_fw.get("version", "Unknown")
    current_build = current_fw.get("build", 0)
    current_major = current_fw.get("major", 0)
    current_minor = current_fw.get("minor", 0)
    current_maturity = current_fw.get("maturity", "")
    
    if not available_fw:
        yield Result(
            state=State.OK, 
            summary=f"System is up to date: {current_version}",
            details=f"Current: {current_version} build {current_build}"
        )
        yield Metric("updates_available", 0)
        return
    
    # Filter and categorize updates
    try:
        current_build_int = int(current_build)
        current_major_int = int(current_major)
        current_minor_int = int(current_minor)
        
        newer_updates = []
        recommended_fw = None
        highest_fw = None
        security_updates = 0
        
        for fw in available_fw:
            fw_build = int(fw.get("build", 0))
            fw_major = int(fw.get("major", 0))
            fw_minor = int(fw.get("minor", 0))
            fw_maturity = fw.get("maturity", "")
            
            if fw_build > current_build_int:
                newer_updates.append(fw)
                
                # Count potential security updates (maturity M typically means maintenance/security)
                if fw_maturity == "M":
                    security_updates += 1
                
                # Find recommended (next version in same minor series)
                if (fw_major == current_major_int and 
                    fw_minor == current_minor_int and 
                    (recommended_fw is None or fw_build < int(recommended_fw.get("build", 99999)))):
                    recommended_fw = fw
                
                # Find highest available version
                if (highest_fw is None or 
                    fw_major > int(highest_fw.get("major", 0)) or
                    (fw_major == int(highest_fw.get("major", 0)) and fw_minor > int(highest_fw.get("minor", 0))) or
                    (fw_major == int(highest_fw.get("major", 0)) and fw_minor == int(highest_fw.get("minor", 0)) and fw_build > int(highest_fw.get("build", 0)))):
                    highest_fw = fw
    
    except (ValueError, TypeError):
        # Fallback if version parsing fails
        newer_updates = available_fw
        recommended_fw = available_fw[0] if available_fw else None
        highest_fw = available_fw[0] if available_fw else None
        security_updates = 0
    
    if not newer_updates:
        yield Result(
            state=State.OK,
            summary=f"System is up to date: {current_version}",
            details=f"Current: {current_version} build {current_build}"
        )
        yield Metric("updates_available", 0)
        return
    
    # Calculate gaps for CRITICAL logic
    update_count = len(newer_updates)
    builds_behind_latest = 0
    major_versions_behind = 0
    minor_versions_behind = 0
    
    if highest_fw:
        try:
            high_build = int(highest_fw.get("build", 0))
            high_major = int(highest_fw.get("major", 0))
            high_minor = int(highest_fw.get("minor", 0))
            
            builds_behind_latest = high_build - current_build_int
            
            if high_major > current_major_int:
                major_versions_behind = high_major - current_major_int
            elif high_major == current_major_int and high_minor > current_minor_int:
                minor_versions_behind = high_minor - current_minor_int
        except (ValueError, TypeError):
            pass
    
    # Build enhanced summary
    summary_parts = [f"Current: {current_version} build {current_build}"]
    
    if recommended_fw and recommended_fw != highest_fw:
        rec_version = recommended_fw.get("version", "Unknown")
        rec_build = recommended_fw.get("build", 0)
        summary_parts.append(f"Recommended: {rec_version} build {rec_build}")
    
    if highest_fw:
        high_version = highest_fw.get("version", "Unknown")
        summary_parts.append(f"Highest available: {high_version}")
    
    summary = " → ".join(summary_parts)
    
    # CRITICAL logic based on multiple criteria
    is_critical = False
    critical_reasons = []
    
    # 1. Extremely outdated (>30 updates behind)
    if update_count >= 30:
        is_critical = True
        critical_reasons.append(f"Extremely outdated ({update_count} versions behind)")
    
    # 2. Major version gap (2+ major versions behind)
    if major_versions_behind >= 2:
        is_critical = True
        critical_reasons.append(f"Major version gap ({major_versions_behind} major versions behind)")
    
    # 3. Large build gap (>150 builds behind latest)
    if builds_behind_latest >= 150:
        is_critical = True
        critical_reasons.append(f"Large build gap ({builds_behind_latest} builds behind)")
    
    # 4. Many security/maintenance updates missed (>8 M-level updates)
    if security_updates >= 8:
        is_critical = True
        critical_reasons.append(f"Multiple security updates missed ({security_updates} maintenance releases)")
    
    # 5. Current version no longer maintained (maturity level check)
    if current_maturity == "F" and update_count >= 20:
        is_critical = True
        critical_reasons.append("Current version deprecated (F-level) with many newer versions")
    
    # 6. Extreme minor version gap (>3 minor versions in same major)
    if minor_versions_behind >= 4 and major_versions_behind == 0:
        is_critical = True
        critical_reasons.append(f"Multiple minor versions behind ({minor_versions_behind} minor versions)")
    
    # Additional details
    details_parts = []
    if recommended_fw:
        rec_type = recommended_fw.get("release-type", "Unknown")
        rec_maturity = recommended_fw.get("maturity", "Unknown")
        details_parts.append(f"Recommended update: {recommended_fw.get('version')} (Build {recommended_fw.get('build')}, {rec_type}, Maturity: {rec_maturity})")
    
    if highest_fw and highest_fw != recommended_fw:
        high_type = highest_fw.get("release-type", "Unknown")
        high_maturity = highest_fw.get("maturity", "Unknown") 
        details_parts.append(f"Latest version: {highest_fw.get('version')} (Build {highest_fw.get('build')}, {high_type}, Maturity: {high_maturity})")
    
    details_parts.append(f"Total {update_count} newer versions available")
    
    if security_updates > 0:
        details_parts.append(f"Security/maintenance updates: {security_updates}")
    
    if is_critical:
        details_parts.append(f"CRITICAL: {'; '.join(critical_reasons)}")
    
    # Determine final state and message
    if is_critical:
        state = State.CRIT
        status_prefix = "CRITICAL - System dangerously outdated"
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
        summary=f"{status_prefix} → {summary}",
        details="\n".join(details_parts)
    )
    
    yield Metric("updates_available", update_count)
    yield Metric("security_updates", security_updates)
    
    # Additional metrics for monitoring trends
    if recommended_fw:
        try:
            rec_build_num = int(recommended_fw.get("build", 0))
            builds_behind_recommended = rec_build_num - current_build_int
            yield Metric("builds_behind_recommended", max(0, builds_behind_recommended))
        except (ValueError, TypeError):
            pass
    
    if highest_fw:
        yield Metric("builds_behind_latest", max(0, builds_behind_latest))
        yield Metric("major_versions_behind", max(0, major_versions_behind))
        yield Metric("minor_versions_behind", max(0, minor_versions_behind))

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
