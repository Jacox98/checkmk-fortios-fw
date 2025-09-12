# FortiGate CheckMK Monitoring Plugin

This repository provides a CheckMK extension for monitoring FortiGate firewalls via the REST API. It contains:

- **Special agent** (`libexec/agent_fortigate`) that queries the FortiGate API for system status and firmware details.
- **Check plugins** (`agent_based/fortigate.py`) that evaluate the gathered data and expose services such as *FortiGate System* and *FortiGate Firmware Updates*.
- **Configuration helpers** (`rulesets/special_agent.py` and `server_side_calls/special_agent.py`) to define rule sets and agent commands within CheckMK.
 - Optional integration with **OpenCVE** to expose a *FortiGate CVEs* service that reports the number of CVEs for a given vendor/product.

## Installation

1. Copy the files to your CheckMK site's `local` directory or package them as an MKP.
2. Create an API key on the FortiGate with read permissions for system endpoints.
3. In CheckMK, configure the **Fortigate Firmware** special agent rule and provide the API key, optional port and timeout values.

## Configuration

- Special agent rule: `Fortigate Firmware`
  - `api_key` (required), `port`, `timeout`
  - `critical_on_branch_change` (default: true)
    - When enabled, a jump to a newer FortiOS branch (e.g. 7.4 → 7.6) can contribute to a CRIT state depending on thresholds.
    - When disabled, branch changes are reported as WARN with an explicit note; CRIT is only triggered when you are significantly behind within the same branch or multiple major versions behind.

Example messages when branch change is not critical:

- Summary: `Feature release available (branch change not critical)`
- Details: `Note: branch change is configured as non-critical`

## Features

- Retrieves system information such as version, build, model and serial number.
- Detects firmware update availability and highlights critical gaps in maintenance (with configurable branch-change severity).
- Provides metrics for trending the installed version and number of pending updates.

## Error Handling

- Connection issues (e.g. no route to host, timeouts, DNS failures) are classified by the special agent and reported as UNKNOWN with concise messages instead of raw tracebacks.
- Firmware update retrieval problems that are not connectivity-related are reported as WARN to avoid unnecessary CRIT noise.
- Authentication/SSL/HTTP errors on the System service are reported as CRIT with a clear summary.

## Notes

- The branch-change parameter is configured on the special agent and passed to the check through the agent payload (no separate check-parameters ruleset required).

## Development

The repository currently ships without automated tests. To ensure the environment is set up correctly you can run:

```bash
pytest
```

Contributions are welcome.
### OpenCVE (optional)

Enable the nested "OpenCVE Integration" in the same special agent rule to add a service that counts CVEs for a product via OpenCVE's API.

- `enabled`: turn the integration on
- `base_url`: your OpenCVE instance (default `https://app.opencve.io`)
- `username` / `password`: Basic Auth credentials (your instance may require them)
- `vendor` and `product`: names used by OpenCVE (e.g. `fortinet` / `fortios`)
- `timeout`: request timeout (default 20s)
- `list_limit`: how many CVE IDs to show in details (default 10)
- `warn_threshold` / `crit_threshold`: state thresholds on total CVE count

Notes:
- The integration requests `/api/vendors/<vendor>/products/<product>/cve` and uses the `count` field from the first page; pagination is not required to compute totals.
- The special agent prints a new section `<<<fortigate_cves:sep(0)>>>` consumed by the `FortiGate CVEs` check.
