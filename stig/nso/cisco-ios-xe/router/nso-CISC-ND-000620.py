"""
STIG ID: CISC-ND-000620
Finding ID: V-215687
Severity: High
STIG Title: The Cisco router must only store cryptographic representations of passwords
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000620"
FINDING_ID = "V-215687"
RULE_ID = "SV-215687r991830_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router-ndm"
TITLE = "The Cisco router must only store cryptographic representations of passwords"


def load_test_data(file_path):
    """Load test data from JSON or YAML file."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle both formats:
    # Format 1: {device_name: {tailf-ncs:config: {...}}} - wrapped
    # Format 2: {tailf-ned-cisco-ios:hostname: ..., tailf-ned-cisco-ios:service: ...} - direct NSO config
    
    # Check if this is a direct NSO config (has tailf-ned-cisco-ios keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        # Direct NSO config - wrap it with a device name
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        # Wrap in expected format
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_password_encryption_enabled():
    """
    Test that password encryption is enabled on all devices.
    
    STIG V-215687 (CISC-ND-000620) requires that Cisco routers must only store
    cryptographic representations of passwords. This is validated by checking
    for the presence of the "password-encryption" service in the configuration.
    """
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    devices = load_test_data(test_input_file)
    
    # Dictionary to store results
    results = {}
    
    # Check each device configuration
    for device_name, config in devices.items():
        try:
            # Check if password encryption is enabled
            # Path: tailf-ncs:config -> tailf-ned-cisco-ios:service -> password-encryption
            service_config = config.get('tailf-ncs:config', {}).get('tailf-ned-cisco-ios:service', {})
            password_encryption_enabled = 'password-encryption' in service_config
            
            results[device_name] = {
                'password_encryption_enabled': password_encryption_enabled,
                'compliant': password_encryption_enabled
            }
            
            # Assert that password encryption is enabled
            assert password_encryption_enabled, f"Password encryption is not enabled on {device_name}"
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking password encryption on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print("  Password encryption service is not enabled")


if __name__ == "__main__":
    test_password_encryption_enabled()
