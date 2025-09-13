# FortiGate Monitoring Plugin for CheckMK

Extension for CheckMK to monitor FortiGate firewalls via the REST API.

## Package Contents

- Special agent: `libexec/agent_fortigate` — queries the FortiGate API for system status and firmware details.
- Check plugin: `agent_based/fortigate.py` — evaluates collected data and exposes services like "FortiGate System" and "FortiGate Firmware Updates".
- Configuration helpers: `rulesets/special_agent.py` and `server_side_calls/special_agent.py` — define rulesets and server‑side commands in CheckMK.
- Optional OpenCVE integration — adds the "FortiGate CVEs" service reporting the number of CVEs for a given vendor/product.

## Installation

1. Copy the files into your CheckMK site’s `local` directory, or package them as an MKP.
2. Create an API key on the FortiGate with read permissions for system endpoints.
3. In CheckMK, configure the "Fortigate Firmware" special agent rule and provide the API key, optional port, and timeout.

## Configuration

- Special agent rule: `Fortigate Firmware`
  - Parameters: `api_key` (required), `port`, `timeout`.
  - `critical_on_branch_change` (default: true)
    - Enabled: a jump to a newer FortiOS branch (e.g., 7.4 → 7.6) can contribute to a CRIT state depending on thresholds.
    - Disabled: branch changes are reported as WARN with an explicit note; CRIT triggers only when you are significantly behind within the same branch or multiple major versions.

Example messages when a branch change is not critical:

- Summary: `Feature release available (branch change not critical)`
- Details: `Note: branch change is configured as non‑critical`

## Features

- Retrieves system information: version, build, model, and serial number.
- Detects firmware update availability and highlights critical maintenance gaps (configurable branch‑change severity).
- Provides metrics to trend the installed version and number of pending updates.

## Error Handling

- Connectivity issues (e.g., no route to host, timeouts, DNS failures) are classified by the special agent and reported as UNKNOWN with concise messages instead of raw tracebacks.
- Firmware update retrieval problems unrelated to connectivity are reported as WARN to avoid unnecessary CRIT noise.
- Authentication/SSL/HTTP errors on the System service are reported as CRIT with a clear summary.

## Notes

- The branch‑change parameter is configured on the special agent and passed to the check via the agent payload (no separate check‑parameters ruleset required).

## OpenCVE Integration (optional)

Enable the nested "OpenCVE Integration" in the same special agent rule to add a service that counts CVEs for a product via OpenCVE’s API.

- `enabled`: turn the integration on
- `base_url`: your OpenCVE instance (default `https://app.opencve.io`)
- `username` / `password`: Basic Auth credentials (your instance may require them)
- `vendor` / `product`: names used by OpenCVE (e.g., `fortinet` / `fortios`)
- `timeout`: request timeout (default 20s)
- `list_limit`: how many CVE IDs to show in details (default 10)
- `warn_threshold` / `crit_threshold`: state thresholds on total CVE count
- `ssl_verify`: enable/disable TLS verification for self‑hosted instances

Technical details:
- The integration calls `/api/vendors/<vendor>/products/<product>/cve` and uses the `count` field from the first page; pagination is not required to compute totals.
- The special agent prints a new section `<<<fortigate_cves:sep(0)>>>` consumed by the "FortiGate CVEs" check.

CLI tips (passwords with special characters):
- Use single quotes around `--opencve-pass` in bash/zsh, or prefer:
  - `--opencve-pass-file /path/secret.txt` (file contains only the password)
  - `--opencve-pass-env OPENCVE_PASS` (read from environment variable)

## Development

The repository currently ships without automated tests. To verify your environment you can run:

```bash
pytest
```

Contributions welcome.
