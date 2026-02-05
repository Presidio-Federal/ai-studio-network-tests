"""
Connectivity Test - Ping Validation
Tests network reachability with 100% success requirement.

This test can be loaded and executed by the pyats_run_tests tool.
"""

import pytest
import re
from netmiko import ConnectHandler


def test_ping_connectivity_100_percent(device_params, test_config):
    """
    Test that ping achieves 100% success rate.
    
    Args:
        device_params: Dict with connection parameters (host, port, username, password, device_type)
        test_config: Dict with test-specific config (target_ip, count)
    """
    # Extract parameters
    target_ip = test_config.get('target_ip')
    count = test_config.get('count', 5)
    
    assert target_ip, "target_ip is required in test_config"
    
    # Connect to device
    device = ConnectHandler(**device_params)
    
    # Build ping command based on device type
    device_type = device_params['device_type']
    if device_type.startswith("cisco"):
        ping_command = f"ping {target_ip} repeat {count}"
    elif device_type.startswith("juniper"):
        ping_command = f"ping {target_ip} count {count}"
    elif device_type.startswith("arista"):
        ping_command = f"ping {target_ip} repeat {count}"
    else:
        ping_command = f"ping {target_ip} count {count}"
    
    # Execute ping
    output = device.send_command(ping_command, read_timeout=30)
    
    # Disconnect
    device.disconnect()
    
    # Parse results
    parsed = parse_ping_output(output, device_type)
    
    # Assert 100% success
    assert parsed['success_rate'] == 100.0, (
        f"Expected 100% success rate, got {parsed['success_rate']}% "
        f"({parsed['received']}/{parsed['transmitted']} packets)"
    )
    
    # Optional: Warn about high latency
    if parsed.get('avg_rtt') and parsed['avg_rtt'] > 100:
        pytest.warnings.warn(
            UserWarning(f"High latency: {parsed['avg_rtt']}ms average RTT")
        )


def parse_ping_output(output: str, device_type: str) -> dict:
    """Parse ping output to extract statistics."""
    parsed = {
        "transmitted": 0,
        "received": 0,
        "packet_loss": 0,
        "success_rate": 0.0,
        "min_rtt": None,
        "avg_rtt": None,
        "max_rtt": None
    }
    
    try:
        if device_type.startswith("cisco"):
            # Cisco format: "Success rate is 100 percent (5/5)"
            success_match = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", output)
            if success_match:
                parsed["success_rate"] = float(success_match.group(1))
                parsed["received"] = int(success_match.group(2))
                parsed["transmitted"] = int(success_match.group(3))
                parsed["packet_loss"] = 100 - parsed["success_rate"]
            
            # RTT: "round-trip min/avg/max = 1/2/4 ms"
            rtt_match = re.search(r"round-trip min/avg/max = (\d+)/(\d+)/(\d+)", output)
            if rtt_match:
                parsed["min_rtt"] = int(rtt_match.group(1))
                parsed["avg_rtt"] = int(rtt_match.group(2))
                parsed["max_rtt"] = int(rtt_match.group(3))
                
        elif device_type.startswith("juniper"):
            # Juniper format: "5 packets transmitted, 5 packets received, 0% packet loss"
            stats_match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received, (\d+(?:\.\d+)?)% packet loss", output)
            if stats_match:
                parsed["transmitted"] = int(stats_match.group(1))
                parsed["received"] = int(stats_match.group(2))
                parsed["packet_loss"] = float(stats_match.group(3))
                parsed["success_rate"] = 100 - parsed["packet_loss"]
            
            # RTT: "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.123 ms"
            rtt_match = re.search(r"round-trip min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)", output)
            if rtt_match:
                parsed["min_rtt"] = float(rtt_match.group(1))
                parsed["avg_rtt"] = float(rtt_match.group(2))
                parsed["max_rtt"] = float(rtt_match.group(3))
        
        else:
            # Generic Unix-like format
            stats_match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received, (\d+(?:\.\d+)?)% packet loss", output)
            if stats_match:
                parsed["transmitted"] = int(stats_match.group(1))
                parsed["received"] = int(stats_match.group(2))
                parsed["packet_loss"] = float(stats_match.group(3))
                parsed["success_rate"] = 100 - parsed["packet_loss"]
            
            rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output)
            if rtt_match:
                parsed["min_rtt"] = float(rtt_match.group(1))
                parsed["avg_rtt"] = float(rtt_match.group(2))
                parsed["max_rtt"] = float(rtt_match.group(3))
    
    except Exception:
        pass
    
    return parsed
