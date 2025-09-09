# checkmk-fortios-fw

Utilities and CheckMK plugins for monitoring Fortinet FortiOS firewalls.

## Setup

1. Copy the files from this repository into your CheckMK site:
   - `agent_based/fortigate.py` → `local/lib/python3/cmk/base/plugins/agent_based/`
   - `libexec/` scripts → `local/lib/exe/`
2. Reload or restart the CheckMK site so the new plugins are detected.
3. Run a service discovery for your FortiGate host:
   ```bash
   cmk -vII <hostname>
   cmk -v <hostname>
   ```

To run the unit tests locally:
```bash
pytest
```

## Usage

The agent section returns JSON data which is parsed and evaluated by
`agent_based/fortigate.py`. Example of using the parser directly:
```python
from agent_based.fortigate import parse_fortigate_system

sample = [['{"status": "success", "version": "v7.0.12"}']]
print(parse_fortigate_system(sample))
```

## Dependencies

- Python 3.10+
- [CheckMK](https://checkmk.com/) providing `cmk.agent_based.v2`
- `pytest` for running the tests
