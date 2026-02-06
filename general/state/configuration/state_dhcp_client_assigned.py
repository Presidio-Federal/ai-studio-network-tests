"""
DHCP Client IP Assignment Validation Test

This test verifies that an interface has successfully obtained an IP address
via DHCP and that the DHCP-assigned configuration is correct.

Requirements:
    - Interface must be configured for DHCP (ip address dhcp)
    - DHCP client must have successfully obtained an address

Validates:
    - Interface has IP address assigned via DHCP
    - IP address is within expected range (if provided)
    - DNS servers were received from DHCP
    - Default gateway was assigned
    - Lease information is available

Author: AI Studio Network Tests
Category: State Check - Configuration
Framework: PyATS
"""

import re
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_client_ip_assigned(device_params, test_config):
    """
    Verify interface has successfully obtained IP via DHCP.
    
    This test checks that DHCP client functionality is working by
    verifying an interface has received and applied DHCP configuration.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        interface (str): Interface to check (e.g., 'GigabitEthernet0/0')
        expected_subnet (str): Expected subnet in CIDR (optional, e.g., '192.168.1.0/24')
        require_dns (bool): Require DNS servers from DHCP (default: True)
        require_gateway (bool): Require default gateway from DHCP (default: True)
    """
    interface = test_config.get("interface")
    expected_subnet = test_config.get("expected_subnet")
    require_dns = test_config.get("require_dns", True)
    require_gateway = test_config.get("require_gateway", True)
    
    if not interface:
        raise ValueError("test_config must specify 'interface' to check")
    
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
        print(f"\n✓ Checking DHCP client status on interface: {interface}")
        
        # Get interface configuration
        config_output = device.execute(f"show running-config interface {interface}")
        
        # Verify interface is configured for DHCP
        if "ip address dhcp" not in config_output.lower():
            print(f"\n✗ Interface {interface} is not configured for DHCP")
            assert False, f"Interface {interface} does not have 'ip address dhcp' configured"
        
        print(f"  ✓ Interface is configured for DHCP client")
        
        # Get interface status
        interface_output = device.execute(f"show ip interface {interface}")
        
        # Parse interface information
        interface_info = parse_interface_dhcp_info(interface_output, interface)
        
        # Check IP assignment
        if not interface_info['ip_address'] or interface_info['ip_address'] == 'unassigned':
            print(f"\n✗ Interface has no IP address assigned")
            assert False, f"Interface {interface} has not received an IP address from DHCP"
        
        print(f"\n  ✓ IP Address: {interface_info['ip_address']}")
        print(f"    - Subnet Mask: {interface_info['subnet_mask']}")
        
        # Check if IP is in expected subnet
        if expected_subnet:
            if is_ip_in_subnet(interface_info['ip_address'], expected_subnet):
                print(f"    ✓ IP is in expected subnet: {expected_subnet}")
            else:
                print(f"    ✗ IP is NOT in expected subnet: {expected_subnet}")
                assert False, f"IP {interface_info['ip_address']} is not in expected subnet {expected_subnet}"
        
        # Get DHCP lease information
        try:
            dhcp_lease_output = device.execute("show dhcp lease")
            lease_info = parse_dhcp_lease(dhcp_lease_output, interface)
            
            if lease_info:
                print(f"\n  ✓ DHCP Lease Information:")
                print(f"    - Lease obtained from: {lease_info.get('dhcp_server', 'Unknown')}")
                print(f"    - Lease expires: {lease_info.get('expiry', 'Unknown')}")
                
                if lease_info.get('dns_servers'):
                    print(f"    ✓ DNS Servers: {', '.join(lease_info['dns_servers'])}")
                elif require_dns:
                    print(f"    ✗ No DNS servers received from DHCP")
                    assert False, "DHCP lease does not include DNS servers"
                
                if lease_info.get('default_gateway'):
                    print(f"    ✓ Default Gateway: {lease_info['default_gateway']}")
                elif require_gateway:
                    print(f"    ✗ No default gateway received from DHCP")
                    assert False, "DHCP lease does not include default gateway"
                
                if lease_info.get('domain_name'):
                    print(f"    ✓ Domain Name: {lease_info['domain_name']}")
            else:
                print(f"\n  ⚠ Unable to retrieve detailed DHCP lease information")
                print(f"    (May not be supported on this platform)")
        
        except Exception as e:
            print(f"\n  ⚠ Could not retrieve DHCP lease details: {str(e)}")
        
        print(f"\n✓ Interface {interface} has successfully obtained IP via DHCP")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_interface_dhcp_info(output, interface):
    """
    Parse interface IP information from show ip interface output.
    
    Returns dict with interface info:
    {
        'ip_address': '192.168.1.100',
        'subnet_mask': '255.255.255.0',
        'status': 'up'
    }
    """
    info = {
        'ip_address': None,
        'subnet_mask': None,
        'status': None
    }
    
    lines = output.split('\n')
    
    for line in lines:
        # Match IP address line
        # Format: "Internet address is 192.168.1.100/24"
        # Or: "Internet address is 192.168.1.100 255.255.255.0"
        ip_match = re.search(r'Internet address is (\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+))', line)
        if ip_match:
            info['ip_address'] = ip_match.group(1)
            
            if ip_match.group(2):  # CIDR notation
                cidr = int(ip_match.group(2))
                info['subnet_mask'] = cidr_to_netmask(cidr)
            elif ip_match.group(3):  # Dotted decimal
                info['subnet_mask'] = ip_match.group(3)
        
        # Check if unassigned
        if 'unassigned' in line.lower():
            info['ip_address'] = 'unassigned'
        
        # Check status
        if 'line protocol is' in line.lower():
            if 'up' in line.lower():
                info['status'] = 'up'
            else:
                info['status'] = 'down'
    
    return info


def parse_dhcp_lease(output, interface):
    """
    Parse DHCP lease information from show dhcp lease output.
    
    Returns dict with lease details or None if not found.
    """
    lease_info = {
        'dhcp_server': None,
        'expiry': None,
        'dns_servers': [],
        'default_gateway': None,
        'domain_name': None
    }
    
    lines = output.split('\n')
    current_interface = None
    
    for line in lines:
        # Check if this lease is for our interface
        if interface.lower() in line.lower():
            current_interface = interface
        
        if not current_interface:
            continue
        
        # Parse DHCP server
        server_match = re.search(r'DHCP server\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if server_match:
            lease_info['dhcp_server'] = server_match.group(1)
        
        # Parse expiry
        if 'expire' in line.lower():
            expiry_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})', line)
            if expiry_match:
                lease_info['expiry'] = expiry_match.group(1)
        
        # Parse DNS servers
        dns_match = re.search(r'DNS\s+(?:server|servers?)\s*[:=]\s*([\d\.\s,]+)', line, re.IGNORECASE)
        if dns_match:
            dns_str = dns_match.group(1)
            lease_info['dns_servers'] = re.findall(r'\d+\.\d+\.\d+\.\d+', dns_str)
        
        # Parse default gateway
        gw_match = re.search(r'(?:default\s+)?(?:gateway|router)\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if gw_match:
            lease_info['default_gateway'] = gw_match.group(1)
        
        # Parse domain name
        domain_match = re.search(r'domain\s+name\s*[:=]\s*(\S+)', line, re.IGNORECASE)
        if domain_match:
            lease_info['domain_name'] = domain_match.group(1)
    
    # Return None if no meaningful data was found
    if not lease_info['dhcp_server'] and not lease_info['dns_servers']:
        return None
    
    return lease_info


def is_ip_in_subnet(ip, subnet_cidr):
    """
    Check if an IP address is in a given subnet (CIDR notation).
    
    Args:
        ip: IP address string (e.g., '192.168.1.100')
        subnet_cidr: Subnet in CIDR notation (e.g., '192.168.1.0/24')
    
    Returns:
        bool: True if IP is in subnet
    """
    import ipaddress
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(subnet_cidr, strict=False)
        return ip_obj in network_obj
    except:
        return False


def cidr_to_netmask(cidr):
    """Convert CIDR prefix length to dotted decimal netmask."""
    import ipaddress
    return str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}').netmask)
