# FortiGate CheckMK Monitoring Plugin

This repository provides a CheckMK extension for monitoring FortiGate firewalls via the REST API. It contains:

- **Special agent** (`libexec/agent_fortigate`) that queries the FortiGate API for system status and firmware details.
- **Check plugins** (`agent_based/fortigate.py`) that evaluate the gathered data and expose services such as *FortiGate System* and *FortiGate Firmware Updates*.
- **Configuration helpers** (`rulesets/special_agent.py` and `server_side_calls/special_agent.py`) to define rule sets and agent commands within CheckMK.

## Installation

1. Copy the files to your CheckMK site's `local` directory or package them as an MKP.
2. Create an API key on the FortiGate with read permissions for system endpoints.
3. In CheckMK, configure the **FortiGate via REST API** rule and provide the API key, optional port and timeout values.

## Features

- Retrieves system information such as version, build, model and serial number.
- Detects firmware update availability and highlights critical gaps in maintenance.
- Provides metrics for trending the installed version and number of pending updates.

## Development

The repository currently ships without automated tests. To ensure the environment is set up correctly you can run:

```bash
pytest
```

Contributions are welcome.
