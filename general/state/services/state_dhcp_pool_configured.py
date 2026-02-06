"""
DHCP Pool Configuration Validation Test

This test verifies that DHCP pools are properly configured on the device.

Requirements:
    - Device must have DHCP server capability
    - At least one DHCP pool should be configured

Validates:
    - DHCP pools exist
    - Pools have network/subnet defined
    - Default router (gateway) is configured
    - DNS servers are configured
    - Pool configuration is complete

Author: AI Studio Network Tests
Category: State Check - Services
Framework: PyATS
"""

import re
from pyats.topology import loader
from genie.testbed import load as genie_loader


def test_dhcp_pools_exist_and_configured(device_params, test_config):
    """
    Verify DHCP pools are configured with required parameters.
    
    This test checks that DHCP pools exist and contain the minimum
    required configuration for proper operation.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration (optional params)
    
    Test Configuration:
        min_pools (int): Minimum number of pools required (default: 1)
        require_dns (bool): Require DNS servers in pools (default: True)
        require_gateway (bool): Require default router (default: True)
    """
    min_pools = test_config.get("min_pools", 1)
    require_dns = test_config.get("require_dns", True)
    require_gateway = test_config.get("require_gateway", True)
    
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
        # Execute show ip dhcp pool
        output = device.execute("show ip dhcp pool")
        
        # Parse DHCP pools
        pools = parse_dhcp_pools(output)
        
        print(f"\n✓ Found {len(pools)} DHCP pool(s):")
        
        # Display each pool's configuration
        config_issues = []
        
        for pool in pools:
            print(f"\n  Pool: {pool['name']}")
            print(f"    - Network: {pool.get('network', 'Not configured')}")
            
            if pool.get('default_router'):
                print(f"    ✓ Default router: {pool['default_router']}")
            else:
                print(f"    ✗ Default router: Not configured")
                if require_gateway:
                    config_issues.append(f"Pool '{pool['name']}' has no default router")
            
            if pool.get('dns_servers'):
                print(f"    ✓ DNS servers: {', '.join(pool['dns_servers'])}")
            else:
                print(f"    ✗ DNS servers: Not configured")
                if require_dns:
                    config_issues.append(f"Pool '{pool['name']}' has no DNS servers")
            
            if pool.get('domain_name'):
                print(f"    ✓ Domain name: {pool['domain_name']}")
            
            if pool.get('lease_time'):
                print(f"    ✓ Lease time: {pool['lease_time']}")
        
        # Validate minimum pools
        assert len(pools) >= min_pools, (
            f"Expected at least {min_pools} DHCP pool(s), found {len(pools)}"
        )
        
        # Validate all pools have networks defined
        for pool in pools:
            assert pool.get('network'), (
                f"Pool '{pool['name']}' has no network/subnet configured"
            )
        
        # Check for configuration issues
        if config_issues:
            print(f"\n✗ Configuration issues found:")
            for issue in config_issues:
                print(f"  - {issue}")
            assert False, f"Found {len(config_issues)} DHCP pool configuration issue(s)"
        
        print(f"\n✓ All {len(pools)} DHCP pool(s) are properly configured")
        
    finally:
        if device.is_connected():
            device.disconnect()


def parse_dhcp_pools(output):
    """
    Parse 'show ip dhcp pool' output.
    
    Returns list of dicts with pool information:
    [
        {
            'name': 'POOL_NAME',
            'network': '192.168.1.0/24',
            'default_router': '192.168.1.1',
            'dns_servers': ['8.8.8.8', '8.8.4.4'],
            'domain_name': 'example.com',
            'lease_time': '1 day'
        },
        ...
    ]
    """
    pools = []
    current_pool = None
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Match pool name: "Pool POOL_NAME :"
        pool_match = re.match(r'^Pool\s+(\S+)\s*:', line)
        if pool_match:
            if current_pool:
                pools.append(current_pool)
            current_pool = {
                'name': pool_match.group(1),
                'network': None,
                'default_router': None,
                'dns_servers': [],
                'domain_name': None,
                'lease_time': None
            }
            continue
        
        if not current_pool:
            continue
        
        # Match network: "Subnet size (first/last)   : 254"
        # Or: "Network               : 192.168.1.0  Mask : 255.255.255.0"
        network_match = re.search(r'Network\s*:\s*(\d+\.\d+\.\d+\.\d+)\s+(?:Mask|mask)\s*:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if network_match:
            ip = network_match.group(1)
            mask = network_match.group(2)
            cidr = netmask_to_cidr(mask)
            current_pool['network'] = f"{ip}/{cidr}"
            continue
        
        # Match default router: "Default router         : 192.168.1.1"
        router_match = re.search(r'Default router\s*:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if router_match:
            current_pool['default_router'] = router_match.group(1)
            continue
        
        # Match DNS servers: "DNS server             : 8.8.8.8  8.8.4.4"
        dns_match = re.search(r'DNS server\s*:\s*([\d\.\s]+)', line)
        if dns_match:
            dns_ips = re.findall(r'\d+\.\d+\.\d+\.\d+', dns_match.group(1))
            current_pool['dns_servers'] = dns_ips
            continue
        
        # Match domain name: "Domain name            : example.com"
        domain_match = re.search(r'Domain name\s*:\s*(\S+)', line)
        if domain_match:
            current_pool['domain_name'] = domain_match.group(1)
            continue
        
        # Match lease time: "Lease time             : 1 Days 0 Hours 0 Minutes"
        lease_match = re.search(r'Lease time\s*:\s*(.+)', line)
        if lease_match:
            current_pool['lease_time'] = lease_match.group(1).strip()
            continue
    
    # Add last pool
    if current_pool:
        pools.append(current_pool)
    
    return pools


def netmask_to_cidr(netmask):
    """Convert netmask to CIDR notation."""
    return sum([bin(int(octet)).count('1') for octet in netmask.split('.')])
