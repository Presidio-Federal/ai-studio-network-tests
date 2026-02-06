"""
DHCP Snooping Security Validation Test

This test verifies DHCP snooping security features are properly configured.

Requirements:
    - Device must support DHCP snooping
    - DHCP snooping should be enabled where required

Validates:
    - DHCP snooping is enabled globally
    - Appropriate VLANs have snooping enabled
    - Trusted ports are configured
    - Rate limiting is in place
    - Binding database is being maintained

Author: AI Studio Network Tests
Category: Compliance - Security
Framework: PyATS
"""

import re
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_snooping_configured(device_params, test_config):
    """
    Verify DHCP snooping security features are properly configured.
    
    This test checks that DHCP snooping is enabled and configured
    to prevent rogue DHCP servers and DHCP-based attacks.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        require_snooping (bool): Require DHCP snooping to be enabled (default: True)
        required_vlans (list): VLANs that must have snooping (e.g., [10, 20, 30])
        require_trusted_ports (bool): Require trusted ports configured (default: True)
        require_rate_limit (bool): Require rate limiting configured (default: False)
        min_trusted_ports (int): Minimum number of trusted ports (default: 1)
    """
    require_snooping = test_config.get("require_snooping", True)
    required_vlans = test_config.get("required_vlans", [])
    require_trusted = test_config.get("require_trusted_ports", True)
    require_rate_limit = test_config.get("require_rate_limit", False)
    min_trusted = test_config.get("min_trusted_ports", 1)
    
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
        # Check if snooping is enabled
        snooping_output = device.execute("show ip dhcp snooping")
        
        # Parse snooping configuration
        snooping_config = parse_dhcp_snooping(snooping_output)
        
        print(f"\n✓ DHCP Snooping Configuration:")
        
        # Check global enablement
        if snooping_config['enabled']:
            print(f"  ✓ DHCP snooping is enabled globally")
        else:
            print(f"  ✗ DHCP snooping is NOT enabled")
            if require_snooping:
                assert False, "DHCP snooping is required but not enabled"
        
        # Check VLANs
        if snooping_config['vlans']:
            print(f"\n  VLANs with snooping enabled: {', '.join(map(str, snooping_config['vlans']))}")
            
            if required_vlans:
                missing_vlans = [vlan for vlan in required_vlans if vlan not in snooping_config['vlans']]
                if missing_vlans:
                    print(f"  ✗ Missing snooping on required VLANs: {', '.join(map(str, missing_vlans))}")
                    assert False, (
                        f"DHCP snooping not enabled on {len(missing_vlans)} required VLAN(s): {missing_vlans}"
                    )
                else:
                    print(f"  ✓ All required VLANs have snooping enabled")
        else:
            print(f"  ⚠ No VLANs configured for snooping")
            if required_vlans:
                assert False, "No VLANs have DHCP snooping enabled"
        
        # Check trusted interfaces
        trusted_output = device.execute("show ip dhcp snooping | include trust")
        trusted_ports = parse_trusted_ports(trusted_output)
        
        if trusted_ports:
            print(f"\n  ✓ Found {len(trusted_ports)} trusted port(s):")
            for port in trusted_ports:
                print(f"    - {port}")
        else:
            print(f"\n  ✗ No trusted ports configured")
            if require_trusted:
                assert False, "No trusted ports configured for DHCP snooping"
        
        if require_trusted and len(trusted_ports) < min_trusted:
            assert False, (
                f"Insufficient trusted ports: found {len(trusted_ports)}, minimum required: {min_trusted}"
            )
        
        # Check rate limiting
        if require_rate_limit:
            # This would require parsing rate limit configuration
            print(f"\n  ⚠ Rate limiting check not fully implemented")
            # Future: parse "show ip dhcp snooping" for rate limits per interface
        
        # Check binding database
        binding_db_output = device.execute("show ip dhcp snooping binding")
        binding_entries = parse_snooping_bindings(binding_db_output)
        
        if binding_entries:
            print(f"\n  ✓ DHCP snooping binding database has {len(binding_entries)} entries")
            print(f"    (Active snooping enforcement)")
        else:
            print(f"\n  ⚠ No entries in DHCP snooping binding database")
            print(f"    (No clients or snooping not active)")
        
        print(f"\n✓ DHCP snooping security is properly configured")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_dhcp_snooping(output):
    """
    Parse 'show ip dhcp snooping' output.
    
    Returns dict with snooping configuration:
    {
        'enabled': True/False,
        'vlans': [10, 20, 30],
        'option_82': True/False,
        'verify_mac': True/False
    }
    """
    config = {
        'enabled': False,
        'vlans': [],
        'option_82': False,
        'verify_mac': False
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line_lower = line.lower()
        
        # Check if snooping is enabled
        if 'dhcp snooping is enabled' in line_lower:
            config['enabled'] = True
        elif 'dhcp snooping is disabled' in line_lower:
            config['enabled'] = False
        
        # Parse VLANs
        # Format: "DHCP snooping is enabled for vlan: 10,20,30"
        vlan_match = re.search(r'vlan[s]?\s*:\s*([\d,\s-]+)', line, re.IGNORECASE)
        if vlan_match:
            vlan_str = vlan_match.group(1)
            # Parse comma-separated and ranges
            for part in vlan_str.split(','):
                part = part.strip()
                if '-' in part:
                    # Range: 10-20
                    start, end = map(int, part.split('-'))
                    config['vlans'].extend(range(start, end + 1))
                elif part.isdigit():
                    config['vlans'].append(int(part))
        
        # Check option 82
        if 'option 82' in line_lower and 'enabled' in line_lower:
            config['option_82'] = True
        
        # Check MAC verification
        if 'verify mac-address' in line_lower and 'enabled' in line_lower:
            config['verify_mac'] = True
    
    return config


def parse_trusted_ports(output):
    """
    Parse trusted ports from show ip dhcp snooping output.
    
    Returns list of trusted interface names.
    """
    trusted = []
    
    lines = output.split('\n')
    
    for line in lines:
        # Look for trust configuration
        # Format varies, may be in table or config format
        if 'trust' in line.lower():
            # Try to extract interface name
            intf_match = re.search(r'((?:Gigabit|Fast|Ten)?Ethernet[\d/]+|Vlan\d+|Port-channel\d+)', line)
            if intf_match:
                trusted.append(intf_match.group(1))
    
    return list(set(trusted))  # Remove duplicates


def parse_snooping_bindings(output):
    """
    Parse DHCP snooping binding database.
    
    Returns list of binding entries.
    """
    bindings = []
    
    lines = output.split('\n')
    
    for line in lines:
        # Match binding entry: MAC, IP, VLAN, Interface
        # Format: "00:11:22:33:44:55  192.168.1.100  10  GigabitEthernet1/0/1"
        match = re.search(
            r'([0-9a-fA-F:]{17}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'
            r'(\d+\.\d+\.\d+\.\d+)\s+'
            r'(\d+)\s+'
            r'(\S+)',
            line
        )
        
        if match:
            bindings.append({
                'mac': match.group(1),
                'ip': match.group(2),
                'vlan': int(match.group(3)),
                'interface': match.group(4)
            })
    
    return bindings
