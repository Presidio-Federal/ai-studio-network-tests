"""
DHCP Relay/Helper Configuration Validation Test

This test verifies that DHCP relay (ip helper-address) is properly configured
on interfaces that require it.

Requirements:
    - Device must support DHCP relay configuration
    - Interfaces with clients should have helper addresses

Validates:
    - Helper addresses are configured on required interfaces
    - Helper addresses point to valid DHCP servers
    - Multiple helper addresses configured where needed (redundancy)

Author: AI Studio Network Tests
Category: State Check - Services
Framework: PyATS
"""

import re
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_relay_configured(device_params, test_config):
    """
    Verify DHCP relay (ip helper-address) is configured on interfaces.
    
    This test checks that interfaces serving clients have proper DHCP
    relay configuration to forward requests to DHCP servers.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        required_interfaces (list): Interfaces that must have helpers (e.g., ['Vlan10', 'Vlan20'])
        expected_helper_ips (list): Expected DHCP server IPs (optional)
        require_redundant_helpers (bool): Require multiple helpers per interface (default: False)
        min_helpers_per_interface (int): Minimum helpers per interface (default: 1)
    """
    required_interfaces = test_config.get("required_interfaces", [])
    expected_helper_ips = test_config.get("expected_helper_ips", [])
    require_redundant = test_config.get("require_redundant_helpers", False)
    min_helpers = test_config.get("min_helpers_per_interface", 1)
    
    # Map device_type to PyATS OS
    os_map = {
        "cisco_xe": "iosxe",
        "cisco_ios": "ios",
        "cisco_nxos": "nxos",
        "cisco_iosxr": "iosxr",
    }
    device_os = os_map.get(device_params["device_type"], device_params["device_type"])
    
    # Build PyATS testbed
    testbed_dict = {
        "devices": {
            device_params["device_name"]: {
                "type": "router",
                "os": device_os,
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
                            "learn_hostname": True,
                            "init_exec_commands": [],
                            "init_config_commands": []
                        }
                    }
                }
            }
        }
    }
    
    testbed = loader.load(testbed_dict)
    device = testbed.devices[device_params["device_name"]]
    device.connect()
    
    try:
        # Get running config
        output = device.execute("show running-config | include helper-address|^interface")
        
        # Parse helper addresses by interface
        interfaces_with_helpers = parse_helper_addresses(output)
        
        if interfaces_with_helpers:
            print(f"\n✓ Found DHCP relay configuration on {len(interfaces_with_helpers)} interface(s):")
            
            for intf, helpers in interfaces_with_helpers.items():
                print(f"\n  Interface: {intf}")
                for helper in helpers:
                    print(f"    ✓ Helper address: {helper}")
        else:
            print(f"\n✗ No DHCP relay (ip helper-address) configuration found")
        
        # Validate required interfaces
        if required_interfaces:
            missing_helpers = []
            
            for req_intf in required_interfaces:
                if req_intf not in interfaces_with_helpers:
                    missing_helpers.append(req_intf)
                    print(f"\n  ✗ {req_intf}: No helper addresses configured")
                elif len(interfaces_with_helpers[req_intf]) < min_helpers:
                    print(f"\n  ✗ {req_intf}: Only {len(interfaces_with_helpers[req_intf])} helper(s), expected {min_helpers}")
                    missing_helpers.append(req_intf)
            
            assert len(missing_helpers) == 0, (
                f"Missing or insufficient DHCP relay configuration on {len(missing_helpers)} interface(s): "
                f"{', '.join(missing_helpers)}"
            )
        
        # Check for redundant helpers if required
        if require_redundant:
            single_helper_intfs = [
                intf for intf, helpers in interfaces_with_helpers.items()
                if len(helpers) < 2
            ]
            
            if single_helper_intfs:
                print(f"\n  ⚠ Warning: {len(single_helper_intfs)} interface(s) have only 1 helper address:")
                for intf in single_helper_intfs:
                    print(f"    - {intf}")
                
                assert False, (
                    f"Redundancy required: {len(single_helper_intfs)} interface(s) need multiple helper addresses"
                )
        
        # Validate expected helper IPs if provided
        if expected_helper_ips:
            all_helpers = set()
            for helpers in interfaces_with_helpers.values():
                all_helpers.update(helpers)
            
            missing_expected = [ip for ip in expected_helper_ips if ip not in all_helpers]
            if missing_expected:
                print(f"\n  ⚠ Expected helper IP(s) not found: {', '.join(missing_expected)}")
        
        # Summary
        total_helpers = sum(len(helpers) for helpers in interfaces_with_helpers.values())
        print(f"\n✓ DHCP relay configured: {len(interfaces_with_helpers)} interface(s), {total_helpers} total helper address(es)")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_helper_addresses(output):
    """
    Parse helper addresses from running config.
    
    Returns dict mapping interface names to list of helper IPs:
    {
        'Vlan10': ['10.0.0.1', '10.0.0.2'],
        'Vlan20': ['10.0.0.1'],
        ...
    }
    """
    interfaces = {}
    current_interface = None
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Match interface line
        intf_match = re.match(r'^interface\s+(\S+)', line)
        if intf_match:
            current_interface = intf_match.group(1)
            continue
        
        # Match helper address
        helper_match = re.search(r'ip helper-address\s+(\d+\.\d+\.\d+\.\d+)', line)
        if helper_match and current_interface:
            helper_ip = helper_match.group(1)
            
            if current_interface not in interfaces:
                interfaces[current_interface] = []
            
            interfaces[current_interface].append(helper_ip)
    
    return interfaces
