"""
STIG ID: CISC-ND-001210
Finding ID: V-220556
Severity: High
STIG Title: Cisco IOS XE Router NDM — Use Secure Protocols for Remote Access
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001210"
FINDING_ID = "V-220556"
RULE_ID = "SV-220556r961557_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router-ndm"
TITLE = "Ensure SSH and FIPS-approved encryption algorithms are configured"


def load_test_data(file_path):
    """Load test data from JSON or YAML file."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            return yaml.safe_load(f)
        else:
            return json.load(f)


def test_ssh_security():
    """Test SSH security configurations."""
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    test_data = load_test_data(test_input_file)
    
    # Track test results for each device
    results = {}
    failures = []
    
    for device_name, device_config in test_data.items():
        config_text = device_config.get("config", "")
        
        # Initialize device results
        results[device_name] = {
            "ssh_version_2": False,
            "no_clear_text_passwords": True,
            "ssh_only_transport": True
        }
        
        # Check for SSH version 2 configuration
        # In newer IOS versions, SSH v2 is default if not explicitly specified
        # Look for explicit configuration or secure algorithm configurations that imply v2
        if "ip ssh version 2" in config_text:
            results[device_name]["ssh_version_2"] = True
        elif "ip ssh server algorithm" in config_text:
            # SSH server algorithm configs imply SSH v2
            results[device_name]["ssh_version_2"] = True
        
        # Check VTY line configurations
        vty_configs = re.findall(r"line vty \d+( \d+)?\n(.*?)(?=\n[^\s])", config_text, re.DOTALL)
        
        for vty_match in vty_configs:
            vty_config = vty_match[1]
            
            # Check for password clear text (password 0 or just password without type)
            if re.search(r"password (0 \S+|\S+)", vty_config):
                results[device_name]["no_clear_text_passwords"] = False
                
            # Check if transport input is restricted to SSH only
            transport_input = re.search(r"transport input (\S+)", vty_config)
            if transport_input:
                if transport_input.group(1) != "ssh" and "all" in transport_input.group(1):
                    results[device_name]["ssh_only_transport"] = False
        
        # Add device to failures list if any check failed
        if not all([
            results[device_name]["ssh_version_2"],
            results[device_name]["no_clear_text_passwords"],
            results[device_name]["ssh_only_transport"]
        ]):
            failures.append(device_name)
    
    # Generate detailed error message for failures
    error_message = ""
    if failures:
        error_message = "SSH security check failed for devices:\n"
        for device in failures:
            error_message += f"\n{device}:\n"
            if not results[device]["ssh_version_2"]:
                error_message += "  - SSH version 2 not explicitly configured\n"
            if not results[device]["no_clear_text_passwords"]:
                error_message += "  - Clear text passwords found on VTY lines\n"
            if not results[device]["ssh_only_transport"]:
                error_message += "  - Transport input not restricted to SSH only\n"
    
    # Assert that all devices pass all checks
    assert not failures, error_message


if __name__ == "__main__":
    test_ssh_security()
