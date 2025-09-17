# FortiGate Monitoring Plugin for CheckMK

Extension for CheckMK to monitor FortiGate firewalls via the REST API.

## Package Contents

- Special agent: `libexec/agent_fortigate` - queries the FortiGate API for system status and firmware details.
- Check plugin: `agent_based/fortigate.py` - evaluates collected data and exposes services like "FortiGate System" and "FortiGate Firmware Updates".
- Configuration helpers: `rulesets/special_agent.py` and `server_side_calls/special_agent.py` - define rulesets and server-side commands in CheckMK.
- Check manuals: `local/lib/python3/cmk_addons/plugins/fortigate_firmware/checkman/`.

## Installation

1. Copy the files into your CheckMK site's local directory, or package them as an MKP.
2. Create an API key on the FortiGate with read permissions for system endpoints.

## Configuration

- Special agent rule: Fortigate Firmware
  - Parameters: `api_key` (required), `port`, `timeout`.
  - `critical_on_branch_change` (default: true)
    - Enabled: a jump to a newer FortiOS branch (e.g., 7.4 -> 7.6) can contribute to a CRIT state depending on thresholds.
    - Disabled: branch changes are reported as WARN with an explicit note; CRIT triggers only when you are significantly behind within the same branch or multiple major versions.
  - `ok_if_unmatured_branch` (default: false)
    - Enabled: keep the firmware service OK when the device already runs the newest build in its branch and newer branches only provide immature images.

## Features

- Retrieves system information: version, build, model, and serial number.
- Detects firmware update availability and highlights critical maintenance gaps (configurable branch-change severity).
- Filters firmware images by platform ID and the `can_upgrade` flag so only installable builds are counted.
- Provides metrics to trend the installed version and number of pending updates.

## Error Handling

- The branch-change parameter is configured on the special agent and passed to the check via the agent payload (no separate check-parameters ruleset required).
- Firmware update retrieval problems unrelated to connectivity are reported as WARN to avoid unnecessary CRIT noise.
- Authentication/SSL/HTTP errors on the System service are reported as CRIT with a clear summary.

## Development

The repository currently ships without automated tests. To verify your environment you can run:

```bash
pytest
```

Contributions welcome.
