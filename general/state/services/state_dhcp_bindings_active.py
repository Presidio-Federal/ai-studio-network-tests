"""
DHCP Bindings/Leases Active Validation Test

This test verifies that DHCP server has active client bindings/leases.

Requirements:
    - Device must have DHCP server capability
    - DHCP should be actively serving clients

Validates:
    - Active DHCP bindings exist
    - Leases are properly assigned
    - No duplicate IP assignments
    - Binding information is complete

Author: AI Studio Network Tests
Category: State Check - Services
Framework: PyATS
"""

import re
from datetime import datetime, timedelta
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_active_bindings_exist(device_params, test_config):
    """
    Verify DHCP server has active client bindings.
    
    This test checks that the DHCP server is actively serving clients
    and that bindings are properly maintained.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration (optional params)
    
    Test Configuration:
        min_bindings (int): Minimum number of active bindings (default: 1)
        check_duplicates (bool): Check for duplicate IP assignments (default: True)
        warn_expiring_soon (bool): Warn about leases expiring soon (default: True)
        expiring_threshold_hours (int): Hours until expiry to warn (default: 24)
    """
    min_bindings = test_config.get("min_bindings", 1)
    check_duplicates = test_config.get("check_duplicates", True)
    warn_expiring_soon = test_config.get("warn_expiring_soon", True)
    expiring_threshold_hours = test_config.get("expiring_threshold_hours", 24)
    
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
        # Execute show ip dhcp binding
        output = device.execute("show ip dhcp binding")
        
        # Parse DHCP bindings
        bindings = parse_dhcp_bindings(output)
        
        print(f"\n✓ Found {len(bindings)} active DHCP binding(s):")
        
        # Display bindings
        for binding in bindings:
            lease_info = f"Expires: {binding.get('expiry', 'Unknown')}" if binding.get('expiry') else "Automatic"
            print(f"  ✓ {binding['ip']} → {binding['mac']} ({binding['type']}, {lease_info})")
        
        # Check for duplicate IPs
        if check_duplicates and bindings:
            ip_list = [b['ip'] for b in bindings]
            duplicates = [ip for ip in ip_list if ip_list.count(ip) > 1]
            
            if duplicates:
                unique_dups = list(set(duplicates))
                print(f"\n✗ Found duplicate IP assignment(s):")
                for dup_ip in unique_dups:
                    dup_macs = [b['mac'] for b in bindings if b['ip'] == dup_ip]
                    print(f"  - {dup_ip}: assigned to {', '.join(dup_macs)}")
                assert False, f"Found {len(unique_dups)} duplicate IP assignment(s)"
        
        # Warn about expiring leases
        if warn_expiring_soon:
            expiring_soon = []
            for binding in bindings:
                if binding.get('expiry_datetime'):
                    hours_until_expiry = (binding['expiry_datetime'] - datetime.now()).total_seconds() / 3600
                    if 0 < hours_until_expiry < expiring_threshold_hours:
                        expiring_soon.append({
                            'ip': binding['ip'],
                            'mac': binding['mac'],
                            'hours': round(hours_until_expiry, 1)
                        })
            
            if expiring_soon:
                print(f"\n⚠ {len(expiring_soon)} lease(s) expiring within {expiring_threshold_hours} hours:")
                for exp in expiring_soon:
                    print(f"  - {exp['ip']} ({exp['mac']}): {exp['hours']} hours remaining")
        
        # Validate minimum bindings
        assert len(bindings) >= min_bindings, (
            f"Expected at least {min_bindings} active DHCP binding(s), found {len(bindings)}"
        )
        
        print(f"\n✓ DHCP server has {len(bindings)} active client binding(s)")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_dhcp_bindings(output):
    """
    Parse 'show ip dhcp binding' output.
    
    Returns list of dicts with binding information:
    [
        {
            'ip': '192.168.1.100',
            'mac': '0011.2233.4455',
            'type': 'Automatic',
            'expiry': 'Feb 06 2026 01:23 PM',
            'expiry_datetime': datetime object (if parseable)
        },
        ...
    ]
    """
    bindings = []
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Match binding line (format varies by IOS version)
        # Example: "192.168.1.100     0011.2233.4455     Feb 06 2026 01:23 PM    Automatic"
        # Example: "192.168.1.100     0011.2233.4455.66  Infinite                Automatic"
        
        # Pattern: IP, MAC, Expiry, Type
        match = re.match(
            r'(\d+\.\d+\.\d+\.\d+)\s+'
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{2})?)\s+'
            r'(.+?)\s+'
            r'(Automatic|Manual)',
            line
        )
        
        if match:
            ip = match.group(1)
            mac = match.group(2)
            expiry_str = match.group(3).strip()
            binding_type = match.group(4)
            
            binding = {
                'ip': ip,
                'mac': mac,
                'type': binding_type,
                'expiry': expiry_str if expiry_str.lower() != 'infinite' else None,
                'expiry_datetime': None
            }
            
            # Try to parse expiry datetime
            if expiry_str.lower() != 'infinite':
                try:
                    # Try common formats
                    for fmt in ['%b %d %Y %I:%M %p', '%b %d %Y %H:%M:%S']:
                        try:
                            binding['expiry_datetime'] = datetime.strptime(expiry_str, fmt)
                            break
                        except ValueError:
                            continue
                except:
                    pass
            
            bindings.append(binding)
    
    return bindings
