# FortiGate Monitoring Plugin for CheckMK

Extension for CheckMK to monitor FortiGate firewalls via the REST API.

## Package Contents

- Special agent: `share/check_mk/agents/plugins/fortigate_firmware` - queries the FortiGate API for system status and firmware details.
- Check plugin: `agent_based/fortigate.py` - evaluates collected data and exposes services like "FortiGate System" and "FortiGate Firmware Updates".
- Configuration helpers: `rulesets/fortigate_firmware.py` and `rulesets/fortigate_firmware_bakery.py` - define rulesets and server-side commands in CheckMK.
- Optional OpenCVE integration - adds the "FortiGate CVEs" service reporting the number of CVEs for a given vendor/product.

## Installation

1. Copy the files into your CheckMK site's `local` directory, or package them as an MKP.
2. Create an API key on the FortiGate with read permissions for system endpoints.
1. Copy the files into your CheckMK site's `local` directory, or package them as an MKP.

## Configuration

- Special agent rule: `Fortigate Firmware`
  - Parameters: `api_key` (required), `port`, `timeout`.
  - `critical_on_branch_change` (default: true)
    - Enabled: a jump to a newer FortiOS branch (e.g., 7.4 -> 7.6) can contribute to a CRIT state depending on thresholds.
    - Disabled: branch changes are reported as WARN with an explicit note; CRIT triggers only when you are significantly behind within the same branch or multiple major versions.

- Details: `Note: branch change is configured as non-critical`

- Summary: `Feature release available (branch change not critical)`
- Details: `Note: branch change is configured as non-critical`
- Detects firmware update availability and highlights critical maintenance gaps (configurable branch-change severity).
## Features

- Retrieves system information: version, build, model, and serial number.
- Detects firmware update availability and highlights critical maintenance gaps (configurable branch-change severity).
- Filters firmware images by platform ID and the can_upgrade flag so only installable builds are counted.
- Provides metrics to trend the installed version and number of pending updates.

## Error Handling

- The branch-change parameter is configured on the special agent and passed to the check via the agent payload (no separate check-parameters ruleset required).
- Firmware update retrieval problems unrelated to connectivity are reported as WARN to avoid unnecessary CRIT noise.
- Authentication/SSL/HTTP errors on the System service are reported as CRIT with a clear summary.

Enable the nested "OpenCVE Integration" in the same special agent rule to add a service that counts CVEs for a product via OpenCVE's API.

- The branch-change parameter is configured on the special agent and passed to the check via the agent payload (no separate check-parameters ruleset required).
- Check manuals for the shipped services are provided under `local/lib/python3/cmk_addons/plugins/fortigate_firmware/checkman/`.

## OpenCVE Integration (optional)

Enable the nested "OpenCVE Integration" in the same special agent rule to add a service that counts CVEs for a product via OpenCVE's API.

- `enabled`: turn the integration on
- `base_url`: your OpenCVE instance (default `https://app.opencve.io`)
- `username` / `password`: Basic Auth credentials (your instance may require them)
- `vendor` / `product`: names used by OpenCVE (defaults: `fortinet` / `fortios`)
- `timeout`: request timeout (default 20s)
- `list_limit`: how many CVE IDs to show in details (default 10)
- `warn_threshold` / `crit_threshold`: state thresholds on total CVE count
  (TLS certificate verification is always enabled by default.)

Technical details:
- The integration calls `/api/vendors/<vendor>/products/<product>/cve` and uses the `count` field from the first page; pagination is not required to compute totals.
- The special agent prints a new section `<<<fortigate_cves:sep(0)>>>` consumed by the "FortiGate CVEs" check.

CLI tips (passwords with special characters):
- Use single quotes around `--opencve-pass` in bash/zsh when testing the agent manually.

## Development

The repository currently ships without automated tests. To verify your environment you can run:

```bash
pytest
```

Contributions welcome.
