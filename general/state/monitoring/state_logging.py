"""
Logging Destination Reachability State Check
Learns configured logging destinations and verifies they're reachable.

This test uses PyATS to learn logging configuration and tests syslog server connectivity.
"""

import pytest
from pyats.topology import loader
from genie.libs.parser.utils.common import ParserNotFound


def test_logging_destinations_reachable(device_params, test_config):
    """
    Verify all configured logging destinations are reachable.
    
    Learns logging configuration and tests reachability to syslog servers.
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
        # Learn logging configuration
        try:
            logging_config = device.learn("logging")
        except ParserNotFound:
            pytest.skip("Logging parser not available for this device type")
        
        # Extract logging server IPs
        logging_servers = []
        
        # Get servers from logging info
        servers_dict = logging_config.info.get("logs", {}).get("logging", {}).get("server", {})
        
        for server_ip, server_data in servers_dict.items():
            logging_servers.append({
                "server": server_ip,
                "transport": server_data.get("transport", "udp"),
                "port": server_data.get("port", 514)
            })
        
        # Must have at least one logging server configured
        assert len(logging_servers) > 0, (
            "No logging servers configured. "
            "Device should have at least one syslog destination."
        )
        
        # Test reachability for each server
        failed_servers = []
        
        for server in logging_servers:
            server_ip = server["server"]
            
            # Execute ping
            ping_cmd = f"ping {server_ip} repeat 5"
            output = device.execute(ping_cmd)
            
            # Parse success rate
            import re
            success_match = re.search(r"Success rate is (\d+) percent", output)
            
            if success_match:
                success_rate = int(success_match.group(1))
                if success_rate < 100:
                    failed_servers.append({
                        "server": server_ip,
                        "transport": server["transport"],
                        "port": server["port"],
                        "success_rate": success_rate
                    })
            else:
                failed_servers.append({
                    "server": server_ip,
                    "transport": server["transport"],
                    "port": server["port"],
                    "success_rate": 0,
                    "note": "Could not parse ping output"
                })
        
        # Assert all logging servers are reachable
        assert len(failed_servers) == 0, (
            f"Found {len(failed_servers)} unreachable logging server(s):\n" +
            "\n".join([
                f"    - {srv['server']}:{srv['port']}: {srv['success_rate']}% success"
                for srv in failed_servers
            ])
        )
        
    finally:
        device.disconnect()


def test_logging_enabled(device_params, test_config):
    """
    Verify logging is enabled on the device.
    
    Checks that logging is configured and active.
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
        # Learn logging configuration
        try:
            logging_config = device.learn("logging")
        except ParserNotFound:
            pytest.skip("Logging parser not available for this device type")
        
        # Check if logging is enabled
        logs_info = logging_config.info.get("logs", {})
        
        # Verify logging has configuration
        assert logs_info, "Logging is not configured on device"
        
        # Check for at least one destination (server, buffer, or console)
        has_server = bool(logs_info.get("logging", {}).get("server"))
        has_buffer = logs_info.get("logging", {}).get("buffer_logging") == "enabled"
        has_console = logs_info.get("console_logging") == "enabled"
        
        assert has_server or has_buffer or has_console, (
            "No active logging destinations found. "
            "Device should have at least one logging destination (server, buffer, or console)."
        )
        
    finally:
        device.disconnect()
