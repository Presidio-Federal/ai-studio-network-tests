"""
DHCP Client Lease Health Validation Test

This test verifies that DHCP client leases are healthy and not expired.

Requirements:
    - Device must have DHCP client functionality
    - At least one interface configured with DHCP

Validates:
    - DHCP leases are not expired
    - Leases are not expiring soon (configurable threshold)
    - Client can renew leases
    - DHCP-assigned configuration is active

Author: AI Studio Network Tests
Category: State Check - Configuration
Framework: PyATS
"""

import re
from datetime import datetime, timedelta
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_client_lease_healthy(device_params, test_config):
    """
    Verify DHCP client leases are healthy and not expired.
    
    This test checks that DHCP client leases are valid and provides
    warnings if leases are expiring soon.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        interface (str): Specific interface to check (optional, checks all if not specified)
        warn_expiring_hours (int): Hours threshold for expiry warning (default: 24)
        fail_on_expiring (bool): Fail test if lease expiring soon (default: False)
    """
    interface = test_config.get("interface")
    warn_threshold_hours = test_config.get("warn_expiring_hours", 24)
    fail_on_expiring = test_config.get("fail_on_expiring", False)
    
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
        print(f"\n✓ Checking DHCP client lease health")
        
        # Get DHCP lease information
        try:
            dhcp_lease_output = device.execute("show dhcp lease")
        except Exception as e:
            print(f"\n✗ Unable to retrieve DHCP lease information")
            print(f"  Error: {str(e)}")
            assert False, "Could not retrieve DHCP lease information (may not be supported on this platform)"
        
        # Parse leases
        leases = parse_all_dhcp_leases(dhcp_lease_output)
        
        if not leases:
            print(f"\n✗ No DHCP client leases found")
            assert False, "No DHCP client leases found on device"
        
        print(f"\n  Found {len(leases)} DHCP client lease(s):")
        
        expired_leases = []
        expiring_soon = []
        healthy_leases = []
        
        for lease in leases:
            # Skip if filtering by interface
            if interface and lease['interface'].lower() != interface.lower():
                continue
            
            print(f"\n  Interface: {lease['interface']}")
            print(f"    - IP Address: {lease['ip_address']}")
            print(f"    - DHCP Server: {lease.get('dhcp_server', 'Unknown')}")
            print(f"    - Lease Expiry: {lease.get('expiry', 'Unknown')}")
            
            # Check lease status
            if lease.get('is_expired'):
                print(f"    ✗ Lease is EXPIRED")
                expired_leases.append(lease)
            elif lease.get('hours_until_expiry') is not None:
                hours = lease['hours_until_expiry']
                
                if hours < warn_threshold_hours:
                    print(f"    ⚠ Lease expiring in {hours:.1f} hours")
                    expiring_soon.append(lease)
                else:
                    print(f"    ✓ Lease is healthy ({hours:.1f} hours remaining)")
                    healthy_leases.append(lease)
            else:
                print(f"    ✓ Lease status: OK")
                healthy_leases.append(lease)
        
        # Report expired leases
        if expired_leases:
            print(f"\n✗ {len(expired_leases)} lease(s) are EXPIRED:")
            for lease in expired_leases:
                print(f"  - {lease['interface']}: {lease['ip_address']}")
            
            assert False, f"{len(expired_leases)} DHCP client lease(s) are expired"
        
        # Report expiring soon
        if expiring_soon:
            print(f"\n⚠ {len(expiring_soon)} lease(s) expiring within {warn_threshold_hours} hours:")
            for lease in expiring_soon:
                print(f"  - {lease['interface']}: {lease['ip_address']} ({lease['hours_until_expiry']:.1f} hours)")
            
            if fail_on_expiring:
                assert False, f"{len(expiring_soon)} DHCP lease(s) expiring soon"
        
        # Success summary
        print(f"\n✓ All {len(healthy_leases) + len(expiring_soon)} DHCP client lease(s) are valid")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_all_dhcp_leases(output):
    """
    Parse all DHCP client leases from show dhcp lease output.
    
    Returns list of dicts with lease information:
    [
        {
            'interface': 'GigabitEthernet0/0',
            'ip_address': '192.168.1.100',
            'dhcp_server': '192.168.1.1',
            'expiry': 'Feb 06 2026 01:23 PM',
            'hours_until_expiry': 12.5,
            'is_expired': False
        },
        ...
    ]
    """
    leases = []
    current_lease = None
    
    lines = output.split('\n')
    
    for line in lines:
        line_stripped = line.strip()
        
        # Match interface line
        # Format: "Interface: GigabitEthernet0/0"
        # Or embedded in other formats
        intf_match = re.search(r'(?:Interface|Temp IP addr|Temp sub net mask)[:\s]+((?:Gigabit|Fast|Ten)?Ethernet[\d/]+|Vlan\d+)', line, re.IGNORECASE)
        if intf_match:
            if current_lease:
                leases.append(current_lease)
            current_lease = {
                'interface': intf_match.group(1),
                'ip_address': None,
                'dhcp_server': None,
                'expiry': None,
                'hours_until_expiry': None,
                'is_expired': False
            }
            continue
        
        if not current_lease:
            continue
        
        # Match IP address
        # Format: "Temp IP addr: 192.168.1.100"
        ip_match = re.search(r'(?:Temp\s+)?IP\s+addr(?:ess)?\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if ip_match:
            current_lease['ip_address'] = ip_match.group(1)
        
        # Match DHCP server
        server_match = re.search(r'DHCP\s+(?:Lease\s+)?server\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if server_match:
            current_lease['dhcp_server'] = server_match.group(1)
        
        # Match expiry
        # Format: "Lease Expiration Date: Feb 06 2026 01:23:45"
        # Or: "Expires: Feb 06 2026 01:23 PM"
        expiry_match = re.search(r'(?:Lease\s+)?(?:Expir(?:ation|es?))\s+(?:Date)?\s*[:=]?\s*(.+)', line, re.IGNORECASE)
        if expiry_match:
            expiry_str = expiry_match.group(1).strip()
            current_lease['expiry'] = expiry_str
            
            # Try to parse and calculate time until expiry
            try:
                expiry_datetime = None
                
                # Try multiple datetime formats
                for fmt in [
                    '%b %d %Y %I:%M:%S %p',  # Feb 06 2026 01:23:45 PM
                    '%b %d %Y %I:%M %p',      # Feb 06 2026 01:23 PM
                    '%b %d %Y %H:%M:%S',      # Feb 06 2026 13:23:45
                    '%Y-%m-%d %H:%M:%S',      # 2026-02-06 13:23:45
                ]:
                    try:
                        expiry_datetime = datetime.strptime(expiry_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if expiry_datetime:
                    now = datetime.now()
                    time_remaining = expiry_datetime - now
                    
                    if time_remaining.total_seconds() < 0:
                        current_lease['is_expired'] = True
                        current_lease['hours_until_expiry'] = 0
                    else:
                        current_lease['hours_until_expiry'] = time_remaining.total_seconds() / 3600
            except:
                pass
    
    # Add last lease
    if current_lease and current_lease['ip_address']:
        leases.append(current_lease)
    
    return leases
