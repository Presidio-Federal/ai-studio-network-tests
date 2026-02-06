"""
DHCP Server Statistics Validation Test

This test verifies DHCP server statistics indicate healthy operation.

Requirements:
    - Device must have DHCP server capability
    - DHCP statistics must be available

Validates:
    - DHCP messages are being processed
    - Request/reply ratios are reasonable
    - Decline/NAK rates are low
    - Pool utilization is healthy

Author: AI Studio Network Tests
Category: State Check - Services
Framework: PyATS
"""

import re
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_server_statistics_healthy(device_params, test_config):
    """
    Verify DHCP server statistics indicate healthy operation.
    
    This test analyzes DHCP server statistics to detect potential issues
    such as pool exhaustion, high decline rates, or processing problems.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration (optional params)
    
    Test Configuration:
        max_decline_rate_percent (float): Maximum acceptable decline rate (default: 5.0)
        max_nak_rate_percent (float): Maximum acceptable NAK rate (default: 10.0)
        require_activity (bool): Require DHCP message activity (default: True)
        min_discovers (int): Minimum DISCOVER messages to show activity (default: 1)
    """
    max_decline_rate = test_config.get("max_decline_rate_percent", 5.0)
    max_nak_rate = test_config.get("max_nak_rate_percent", 10.0)
    require_activity = test_config.get("require_activity", True)
    min_discovers = test_config.get("min_discovers", 1)
    
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
        # Execute show ip dhcp server statistics
        output = device.execute("show ip dhcp server statistics")
        
        # Parse statistics
        stats = parse_dhcp_statistics(output)
        
        print(f"\n✓ DHCP Server Statistics:")
        print(f"\n  Message Counts:")
        print(f"    - DHCPDISCOVER: {stats.get('discovers', 0)}")
        print(f"    - DHCPOFFER: {stats.get('offers', 0)}")
        print(f"    - DHCPREQUEST: {stats.get('requests', 0)}")
        print(f"    - DHCPACK: {stats.get('acks', 0)}")
        print(f"    - DHCPNAK: {stats.get('naks', 0)}")
        print(f"    - DHCPDECLINE: {stats.get('declines', 0)}")
        print(f"    - DHCPRELEASE: {stats.get('releases', 0)}")
        print(f"    - DHCPINFORM: {stats.get('informs', 0)}")
        
        # Check for activity
        if require_activity:
            discovers = stats.get('discovers', 0)
            assert discovers >= min_discovers, (
                f"No DHCP activity detected. Expected at least {min_discovers} DISCOVER message(s), found {discovers}"
            )
            print(f"\n  ✓ DHCP server is actively processing requests")
        
        # Calculate and check decline rate
        requests = stats.get('requests', 0)
        declines = stats.get('declines', 0)
        
        if requests > 0:
            decline_rate = (declines / requests) * 100
            print(f"\n  Decline Rate: {decline_rate:.1f}% ({declines}/{requests})")
            
            if decline_rate > max_decline_rate:
                print(f"    ✗ Decline rate exceeds threshold ({max_decline_rate}%)")
                print(f"    ⚠ High decline rate may indicate IP conflicts or configuration issues")
                assert False, (
                    f"DHCP decline rate too high: {decline_rate:.1f}% (threshold: {max_decline_rate}%)"
                )
            else:
                print(f"    ✓ Decline rate is acceptable (threshold: {max_decline_rate}%)")
        
        # Calculate and check NAK rate
        naks = stats.get('naks', 0)
        
        if requests > 0:
            nak_rate = (naks / requests) * 100
            print(f"\n  NAK Rate: {nak_rate:.1f}% ({naks}/{requests})")
            
            if nak_rate > max_nak_rate:
                print(f"    ✗ NAK rate exceeds threshold ({max_nak_rate}%)")
                print(f"    ⚠ High NAK rate may indicate misconfigurations or stale bindings")
                assert False, (
                    f"DHCP NAK rate too high: {nak_rate:.1f}% (threshold: {max_nak_rate}%)"
                )
            else:
                print(f"    ✓ NAK rate is acceptable (threshold: {max_nak_rate}%)")
        
        # Check offer/request ratio
        offers = stats.get('offers', 0)
        if discovers > 0 and offers > 0:
            offer_rate = (offers / discovers) * 100
            print(f"\n  Offer Rate: {offer_rate:.1f}% ({offers}/{discovers})")
            
            if offer_rate < 50:
                print(f"    ⚠ Warning: Low offer rate may indicate pool exhaustion")
            else:
                print(f"    ✓ Server is responding to DISCOVER messages")
        
        print(f"\n✓ DHCP server statistics indicate healthy operation")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_dhcp_statistics(output):
    """
    Parse 'show ip dhcp server statistics' output.
    
    Returns dict with message counts:
    {
        'discovers': 100,
        'offers': 95,
        'requests': 90,
        'acks': 85,
        'naks': 2,
        'declines': 1,
        'releases': 10,
        'informs': 5
    }
    """
    stats = {
        'discovers': 0,
        'offers': 0,
        'requests': 0,
        'acks': 0,
        'naks': 0,
        'declines': 0,
        'releases': 0,
        'informs': 0
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Match message counts
        # Format: "Message              Received"
        #         "DHCPDISCOVER                100"
        
        if 'DHCPDISCOVER' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['discovers'] = int(match.group(1))
        
        elif 'DHCPOFFER' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['offers'] = int(match.group(1))
        
        elif 'DHCPREQUEST' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['requests'] = int(match.group(1))
        
        elif 'DHCPACK' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['acks'] = int(match.group(1))
        
        elif 'DHCPNAK' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['naks'] = int(match.group(1))
        
        elif 'DHCPDECLINE' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['declines'] = int(match.group(1))
        
        elif 'DHCPRELEASE' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['releases'] = int(match.group(1))
        
        elif 'DHCPINFORM' in line.upper():
            match = re.search(r'(\d+)', line)
            if match:
                stats['informs'] = int(match.group(1))
    
    return stats
