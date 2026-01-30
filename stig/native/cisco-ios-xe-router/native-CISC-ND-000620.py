"""
STIG ID: CISC-ND-000620
Finding ID: V-215687
Rule ID: SV-215687r991830_rule
Severity: CAT II (High)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must only store cryptographic representations of passwords.

Discussion:
Passwords need to be protected at all times, and encryption is the standard method for 
protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., 
clear text) and easily compromised.

Check Text:
Review the device configuration to verify that the password encryption command has been 
configured.

service password-encryption

If the device is not configured to encrypt passwords, this is a finding.

Fix Text:
Configure the device to encrypt passwords as shown in the example below.

SW1(config)# service password-encryption
SW1(config)# end

References:
CCI: CCI-000196
NIST SP 800-53 :: IA-5 (1) (c)
NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
NIST SP 800-53 Revision 5 :: IA-5 (1) (c)
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
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "The Cisco router must only store cryptographic representations of passwords"


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle multiple formats for native data:
    # Format 1: {device_name: {tailf-ncs:config: {...}}} - wrapped with device name
    # Format 2: {tailf-ncs:config: {tailf-ned-cisco-ios:...}} - direct config wrapper
    # Format 3: {tailf-ned-cisco-ios:hostname: ..., ...} - unwrapped config
    
    # Check if this is wrapped in tailf-ncs:config at top level
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        # Direct config - extract hostname and wrap
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    # Check if this is unwrapped (tailf-ned-cisco-ios keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        # Unwrapped config - wrap it
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    # Otherwise assume it's already properly formatted
    return data


def test_password_encryption_enabled():
    """
    Test that password encryption is enabled on all devices.
    
    STIG V-215687 (CISC-ND-000620) requires that Cisco routers must only store
    cryptographic representations of passwords. This is validated by checking
    for the presence of the "password-encryption" service in the configuration.
    
    Native extraction method: Tests against native API/CLI JSON output.
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
    for device_name, device_data in devices.items():
        try:
            # Navigate to service configuration
            # Path: tailf-ncs:config -> tailf-ned-cisco-ios:service -> password-encryption
            config = device_data.get('tailf-ncs:config', {})
            service_config = config.get('tailf-ned-cisco-ios:service', {})
            
            # Check if password-encryption key exists
            password_encryption_enabled = 'password-encryption' in service_config
            
            results[device_name] = {
                'password_encryption_enabled': password_encryption_enabled,
                'compliant': password_encryption_enabled
            }
            
            # Assert that password encryption is enabled
            if not password_encryption_enabled:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n"
                    f"  - Password encryption is NOT enabled\n\n"
                    f"Required configuration:\n"
                    f"  SW1(config)# service password-encryption\n\n"
                    f"Finding: Passwords are stored in clear text and can be easily compromised.\n"
                    f"Risk: Unauthorized access if configuration is exposed."
                )
                assert False, error_message
            
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
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Password encryption is enabled")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  ✗ Password encryption is NOT enabled")


if __name__ == "__main__":
    test_password_encryption_enabled()
