# Test Development Guide

This guide explains how to write network validation tests that integrate with the AI agent infrastructure via the PyATS MCP server.

## Table of Contents
- [Overview](#overview)
- [Test Categories](#test-categories)
- [Test Structure Standards](#test-structure-standards)
- [PyATS-Based Tests](#pyats-based-tests)
- [Netmiko-Based Tests](#netmiko-based-tests)
- [Output Standards](#output-standards)
- [Catalog Registration](#catalog-registration)
- [Testing Your Test](#testing-your-test)

## Overview

Tests in this repository are designed to be:
- **Agent-friendly**: Provide clear, structured output that AI agents can interpret
- **Standardized**: Follow consistent patterns for device connection and validation
- **Maintainable**: Use fixtures for device parameters and test configuration
- **Discoverable**: Registered in `catalog.json` with rich metadata

All tests are executed via pytest and integrate with the FastMCP server that provides tools to AI agents.

## Test Categories

Tests are organized by category and stored in corresponding directories:

```
test-repo/general/
├── state/                    # State validation tests
│   ├── connectivity/         # Network connectivity checks
│   ├── routing/              # Routing protocol validation
│   ├── monitoring/           # Monitoring/logging checks
│   └── security/             # Security posture validation
├── compliance/               # Compliance/policy tests
│   ├── security/
│   ├── config/
│   └── operational/
└── config/                   # Configuration validation
    ├── interface/
    ├── routing/
    └── system/
```

## Test Structure Standards

### File Naming
- Use descriptive, lowercase names with underscores
- Format: `{category}_{specific_check}.py`
- Examples: `state_bgp_neighbors.py`, `compliance_password_policy.py`

### Function Naming
- Test functions must start with `test_`
- Use descriptive names that indicate what is being validated
- Examples: `test_bgp_neighbors_established()`, `test_gateway_reachability()`

### Required Fixtures
All tests must accept two fixtures:

```python
def test_example(device_params, test_config):
    """
    device_params: dict - Contains device connection details
    test_config: dict - Contains test-specific configuration
    """
```

#### `device_params` Structure
```python
{
    "device_name": str,      # Hostname of the device (required for PyATS)
    "host": str,             # IP address or FQDN
    "username": str,         # SSH username
    "password": str,         # SSH password
    "device_type": str,      # Device type (cisco_xe, cisco_ios, etc.)
    "port": int              # SSH port (default: 22)
}
```

#### `test_config` Structure
```python
{
    # Test-specific parameters defined in catalog.json
    "target_ip": "8.8.8.8",
    "min_neighbors": 2,
    # ... any custom parameters
}
```

## PyATS-Based Tests

PyATS tests use the Genie library for device learning and structured data parsing.

### Connection Template

```python
from genie.testbed import load as genie_loader
from pyats.topology import loader

def test_pyats_example(device_params, test_config):
    """Example PyATS test with proper connection handling."""
    
    # Map device_type to PyATS OS
    os_map = {
        "cisco_xe": "iosxe",
        "cisco_ios": "ios",
        "cisco_nxos": "nxos",
        "cisco_iosxr": "iosxr",
        "juniper_junos": "junos",
        "arista_eos": "eos"
    }
    device_os = os_map.get(device_params["device_type"], device_params["device_type"])
    
    # Build PyATS testbed dynamically
    testbed_dict = {
        "devices": {
            device_params["device_name"]: {
                "type": "router",  # Generic PyATS device type
                "os": device_os,   # Specific OS for parser selection
                "credentials": {
                    "default": {
                        "username": device_params["username"],
                        "password": device_params["password"]
                    }
                },
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"],
                        "port": device_params.get("port", 22),
                        "arguments": {
                            "learn_hostname": True,           # Auto-learn hostname
                            "init_exec_commands": [],         # Disable init commands
                            "init_config_commands": []        # Disable init configs
                        }
                    }
                }
            }
        }
    }
    
    # Load testbed and connect
    testbed = loader.load(testbed_dict)
    device = testbed.devices[device_params["device_name"]]
    device.connect()
    
    try:
        # Perform validation
        learned_data = device.learn("routing")
        
        # Extract and validate data
        # ... your validation logic ...
        
        # Print validation results (see Output Standards)
        print("\n✓ Validation results here")
        
    finally:
        # Always disconnect
        if device.is_connected():
            device.disconnect()
```

### Key PyATS Concepts

#### OS Mapping
PyATS requires specific OS strings to load the correct parsers:
- `cisco_xe` → `iosxe`
- `cisco_ios` → `ios`
- `cisco_nxos` → `nxos`

Always map the MCP server's `device_type` to the correct PyATS OS string.

#### Connection Arguments
```python
"arguments": {
    "learn_hostname": True,           # Let PyATS discover the hostname
    "init_exec_commands": [],         # Prevent unnecessary commands
    "init_config_commands": []        # Prevent config mode entry
}
```

#### Device Learning
```python
# Learn structured data
routing_data = device.learn("routing")
interface_data = device.learn("interface")
arp_data = device.learn("arp")

# Access learned data
routing_data.info['vrf']['default']['address_family']['ipv4']
```

## Netmiko-Based Tests

Netmiko tests use SSH connections for simple command execution and parsing.

### Connection Template

```python
from netmiko import ConnectHandler

def test_netmiko_example(device_params, test_config):
    """Example Netmiko test."""
    
    # Build connection parameters
    connection_params = {
        "device_type": device_params["device_type"],
        "host": device_params["host"],
        "username": device_params["username"],
        "password": device_params["password"],
        "port": device_params.get("port", 22)
    }
    
    # Connect to device
    device = ConnectHandler(**connection_params)
    
    try:
        # Execute command
        output = device.send_command("show version")
        
        # Parse output (use regex, text processing, etc.)
        # ... your parsing logic ...
        
        # Print validation results
        print("\n✓ Validation results here")
        
        # Assert validation
        assert some_condition, "Validation failed message"
        
    finally:
        device.disconnect()
```

### When to Use Netmiko
- Simple command execution and text parsing
- Devices not fully supported by PyATS Genie
- Quick connectivity tests
- Custom parsing requirements

## Output Standards

The MCP server's `run_tests_tool.py` extracts test output for agents. Follow these standards:

### Print Validation Details
Use `print()` statements (not `logger.info()`) to output validation details:

```python
# Good: Uses print() for stdout capture
print(f"\n✓ Found {count} BGP neighbors:")
for neighbor in neighbors:
    print(f"  ✓ {neighbor['ip']}: {neighbor['state']}")
print(f"\n✓ All neighbors are Established")

# Bad: Uses logger (not captured by pytest for agent visibility)
logger.info(f"Found {count} neighbors")
```

### Use Status Icons
- `✓` for successful validations
- `✗` for failures
- `⚠` for warnings

```python
print(f"\n✓ Test passed: {reason}")
print(f"  ✗ Failed check: {detail}")
print(f"  ⚠ Warning: {concern}")
```

### Structure Output
1. **Discovery phase**: Print what was found
2. **Validation phase**: Print status for each check
3. **Summary**: Print overall result

```python
# Discovery
print(f"\n✓ Found {len(gateways)} default gateway(s):")
for gw in gateways:
    print(f"  - {gw['ip']} via {gw['interface']}")

# Validation
for gw in gateways:
    result = ping_test(gw['ip'])
    if result.success:
        print(f"  ✓ {gw['ip']}: Reachable ({result.rtt}ms)")
    else:
        print(f"  ✗ {gw['ip']}: Unreachable")

# Summary
print(f"\n✓ All {len(gateways)} gateway(s) are reachable")
```

### Assertion Messages
Make assertion failures clear and actionable:

```python
# Good: Specific, actionable error
assert len(neighbors) > 0, (
    f"No BGP neighbors configured. Expected at least 1 neighbor."
)

# Bad: Vague error
assert len(neighbors) > 0, "Test failed"
```

## Catalog Registration

After creating a test, register it in `catalog.json`:

```json
{
  "state_checks": [
    {
      "name": "state_example_check",
      "file": "general/state/category/state_example_check.py",
      "category": "category",
      "description": "Brief description of what this test validates",
      "test_type": "state_checks",
      "severity": "critical",
      "tags": ["tag1", "tag2"],
      "default_params": {
        "param1": "default_value",
        "param2": 100
      },
      "vendor": "cisco",
      "platform": "ios-xe",
      "framework": "pyats",
      "requires_config": false
    }
  ]
}
```

### Catalog Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique test identifier (used by agents) |
| `file` | Yes | Path to test file relative to repo root |
| `category` | Yes | Test category (connectivity, routing, etc.) |
| `description` | Yes | Clear description of validation |
| `test_type` | Yes | Type: state_checks, compliance, config |
| `severity` | Yes | critical, high, medium, low |
| `tags` | No | Array of searchable tags |
| `default_params` | No | Default test_config parameters |
| `vendor` | No | Device vendor filter |
| `platform` | No | Platform filter |
| `framework` | Yes | pyats, netmiko, custom |
| `requires_config` | No | Whether test modifies device config |

## Testing Your Test

### 1. Validate Locally
```bash
# Run test with pytest
cd test-repo
pytest -v general/state/category/state_example_check.py
```

### 2. Test via MCP Server
Using an AI agent with access to the PyATS MCP server:

```
Agent: Load the test from the catalog
User: pyats_load_tests with test_names: ["state_example_check"]

Agent: Create a testbed
User: pyats_create_testbed with devices including device_name (hostname)

Agent: Run the test
User: pyats_run_tests_on_testbed with testbed_id and test_names
```

### 3. Verify Output
Check that:
- Test output shows clear validation details with ✓/✗ icons
- Failures provide actionable error messages
- Success cases print discovered values
- Agent can interpret the results

### 4. Commit and Push
```bash
git add catalog.json general/state/category/state_example_check.py
git commit -m "Add state_example_check test"
git push
```

## Best Practices

### Do's
- ✅ Always use `try/finally` for device connections
- ✅ Print validation details to stdout using `print()`
- ✅ Map `device_type` to PyATS OS correctly
- ✅ Use descriptive assertion messages
- ✅ Handle connection timeouts gracefully
- ✅ Test against real devices before committing

### Don'ts
- ❌ Don't use `logger.info()` for validation output
- ❌ Don't hardcode credentials or IP addresses
- ❌ Don't leave devices connected on failure
- ❌ Don't assume specific device hostnames
- ❌ Don't output raw CLI config in successful tests
- ❌ Don't forget to register in `catalog.json`

## Example Tests

Reference these tests for examples:
- PyATS State Check: `general/state/connectivity/state_gateway_reachability.py`
- Netmiko Connectivity: `general/state/connectivity/state_connectivity_ping.py`
- Complex Validation: `general/state/routing/state_bgp_neighbors.py`
- Logging/Monitoring: `general/state/monitoring/state_logging.py`

## Support

For questions or issues:
1. Review existing tests in the repository
2. Check the MCP server implementation in `src/servers/pyats-python/`
3. Test locally with pytest before pushing
4. Ensure catalog entries match the test file structure

---

**Version**: 1.0  
**Last Updated**: 2026-02-04
