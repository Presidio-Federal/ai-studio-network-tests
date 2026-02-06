"""
Gateway Reachability State Check
Learns default gateway from routing table and verifies it's reachable via ping.

This test uses PyATS to learn the routing table and automatically tests gateway reachability.
"""

import pytest
from pyats.topology import loader
from genie.libs.parser.utils.common import ParserNotFound


def test_default_gateway_reachable(device_params, test_config):
    """
    Verify default gateway is reachable.
    
    Learns the default route (0.0.0.0/0) from the routing table and pings the next-hop.
    """
    # Build PyATS testbed
    testbed_dict = {
        "devices": {
            device_params["device_name"]: {
                "type": device_params["device_type"],
                "os": device_params["device_type"].replace("cisco_", ""),
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"],
                        "port": device_params["port"],
                    }
                },
                "credentials": {
                    "default": {
                        "username": device_params["username"],
                        "password": device_params["password"],
                    },
                    "enable": {
                        "password": device_params.get("enable_password", device_params["password"])
                    }
                }
            }
        }
    }
    
    testbed = loader.load(testbed_dict)
    device = testbed.devices[device_params["device_name"]]
    device.connect()
    
    try:
        # Learn routing table
        try:
            routing = device.learn("routing")
        except ParserNotFound:
            pytest.skip("Routing parser not available for this device type")
        
        # Find default route (0.0.0.0/0)
        default_gateways = []
        
        for vrf_name, vrf_data in routing.info.get("vrf", {}).items():
            for af_name, af_data in vrf_data.get("address_family", {}).items():
                if af_name not in ["ipv4", "ipv4 unicast"]:
                    continue
                    
                routes = af_data.get("routes", {})
                if "0.0.0.0/0" in routes:
                    route = routes["0.0.0.0/0"]
                    
                    # Get next hop
                    for next_hop_idx, next_hop_data in route.get("next_hop", {}).get("next_hop_list", {}).items():
                        next_hop_ip = next_hop_data.get("next_hop")
                        if next_hop_ip and next_hop_ip != "0.0.0.0":
                            default_gateways.append({
                                "vrf": vrf_name,
                                "next_hop": next_hop_ip,
                                "interface": next_hop_data.get("outgoing_interface")
                            })
        
        # Validate we found at least one default gateway
        assert len(default_gateways) > 0, (
            "No default gateway found in routing table. "
            "Device may not have a default route configured."
        )
        
        # Test reachability for each gateway
        failed_gateways = []
        
        for gateway in default_gateways:
            next_hop = gateway["next_hop"]
            
            # Execute ping
            ping_cmd = f"ping {next_hop} repeat 5"
            output = device.execute(ping_cmd)
            
            # Parse success rate (Cisco format: "Success rate is 100 percent")
            import re
            success_match = re.search(r"Success rate is (\d+) percent", output)
            
            if success_match:
                success_rate = int(success_match.group(1))
                if success_rate < 100:
                    failed_gateways.append({
                        "gateway": next_hop,
                        "vrf": gateway["vrf"],
                        "interface": gateway["interface"],
                        "success_rate": success_rate
                    })
            else:
                # Could not parse - assume failure
                failed_gateways.append({
                    "gateway": next_hop,
                    "vrf": gateway["vrf"],
                    "interface": gateway["interface"],
                    "success_rate": 0,
                    "note": "Could not parse ping output"
                })
        
        # Assert all gateways are reachable
        assert len(failed_gateways) == 0, (
            f"Found {len(failed_gateways)} unreachable gateway(s):\n" +
            "\n".join([
                f"    - {gw['gateway']} (VRF: {gw['vrf']}, Interface: {gw['interface']}): "
                f"{gw['success_rate']}% success"
                for gw in failed_gateways
            ])
        )
        
    finally:
        device.disconnect()


def test_learned_neighbors_reachable(device_params, test_config):
    """
    Verify all directly connected neighbors (from ARP/CDP/LLDP) are reachable.
    
    Learns neighbors and tests reachability to each.
    """
    # Build PyATS testbed
    testbed_dict = {
        "devices": {
            device_params["device_name"]: {
                "type": device_params["device_type"],
                "os": device_params["device_type"].replace("cisco_", ""),
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"],
                        "port": device_params["port"],
                    }
                },
                "credentials": {
                    "default": {
                        "username": device_params["username"],
                        "password": device_params["password"],
                    },
                    "enable": {
                        "password": device_params.get("enable_password", device_params["password"])
                    }
                }
            }
        }
    }
    
    testbed = loader.load(testbed_dict)
    device = testbed.devices[device_params["device_name"]]
    device.connect()
    
    try:
        # Learn ARP table
        try:
            arp = device.learn("arp")
        except ParserNotFound:
            pytest.skip("ARP parser not available for this device type")
        
        # Extract unique neighbor IPs
        neighbor_ips = set()
        
        for interface_name, interface_data in arp.info.get("interfaces", {}).items():
            for ip, entry in interface_data.get("ipv4", {}).get("neighbors", {}).items():
                if ip and ip != "0.0.0.0":
                    neighbor_ips.add(ip)
        
        # Must have at least one neighbor
        assert len(neighbor_ips) > 0, "No ARP neighbors found"
        
        # Test reachability
        failed_neighbors = []
        
        for neighbor_ip in neighbor_ips:
            ping_cmd = f"ping {neighbor_ip} repeat 3"
            output = device.execute(ping_cmd)
            
            import re
            success_match = re.search(r"Success rate is (\d+) percent", output)
            
            if success_match:
                success_rate = int(success_match.group(1))
                if success_rate < 80:  # Allow some packet loss for neighbors
                    failed_neighbors.append({
                        "neighbor": neighbor_ip,
                        "success_rate": success_rate
                    })
            else:
                failed_neighbors.append({
                    "neighbor": neighbor_ip,
                    "success_rate": 0
                })
        
        # Assert most neighbors are reachable
        assert len(failed_neighbors) == 0, (
            f"Found {len(failed_neighbors)} unreachable neighbor(s):\n" +
            "\n".join([
                f"    - {n['neighbor']}: {n['success_rate']}% success"
                for n in failed_neighbors
            ])
        )
        
    finally:
        device.disconnect()
