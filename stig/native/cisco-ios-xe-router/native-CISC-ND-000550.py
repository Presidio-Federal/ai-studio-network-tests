"""
STIG ID: CISC-ND-000550
Finding ID: V-215681
Rule ID: SV-215681r991820_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96071; SV-105209

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to enforce a minimum 15-character password length.

Discussion:
Password complexity, or strength, is a measure of the effectiveness of a password in resisting 
attempts at guessing and brute-force attacks. Password length is one factor of several that helps 
to determine strength and how long it takes to crack a password.

The use of more characters in a password helps to exponentially increase the time and/or resources 
required to compromise the password. Passwords with fewer characters are more susceptible to 
brute-force attacks. A minimum 15-character password length significantly increases the difficulty 
of password-guessing attacks while still being manageable for users.

The AAA common-criteria policy allows configuration of password composition rules including minimum 
length requirements that are enforced when users set or change passwords.

Check Text:
Review the router configuration to verify that it enforces a minimum 15-character password length.

aaa common-criteria policy PASSWORD_POLICY
  min-length 15

If the router is not configured to enforce a minimum 15-character password length, this is a finding.

Fix Text:
Configure the Cisco router to enforce a minimum 15-character password length as shown in the 
example below.

R1(config)# aaa common-criteria policy PASSWORD_POLICY
R1(config-cc-policy)# min-length 15
R1(config-cc-policy)# exit
R1(config)# end

References:
CCI: CCI-004066
NIST SP 800-53 Revision 5 :: IA-5 (1) (h)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000550"
FINDING_ID = "V-215681"
RULE_ID = "SV-215681r991820_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must enforce minimum 15-character password length"

MIN_PASSWORD_LENGTH = 15


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle multiple formats
    # Native IOS-XE format: Cisco-IOS-XE-native:native
    if isinstance(data, dict) and 'Cisco-IOS-XE-native:native' in data:
        config = data['Cisco-IOS-XE-native:native']
        device_name = config.get('hostname', 'unknown-device')
        return {device_name: {'config': config}}
    
    # NSO wrapped format: tailf-ncs:config
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'config': config, 'format': 'nso'}}
    
    # Direct NSO format
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'config': data, 'format': 'nso'}}
    
    return data


def test_password_minimum_length():
    """
    Test that AAA common-criteria policy enforces minimum 15-character password length.
    
    STIG V-215681 (CISC-ND-000550) requires that the router enforces a minimum 15-character 
    password length to protect against brute-force attacks. Longer passwords exponentially 
    increase the difficulty of password-guessing attacks.
    
    The test validates that:
    1. AAA common-criteria policy is configured
    2. Minimum password length is set to at least 15 characters
    
    This ensures passwords are sufficiently complex to resist attack attempts.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('config', {})
            data_format = device_data.get('format', 'native')
            
            # Initialize compliance flags
            policy_configured = False
            policy_name = None
            min_length = None
            min_length_compliant = False
            
            # Check AAA common-criteria policy configuration
            if data_format == 'native':
                # Native format: aaa -> Cisco-IOS-XE-aaa:common-criteria[]
                aaa_config = config.get('aaa', {})
                common_criteria = aaa_config.get('Cisco-IOS-XE-aaa:common-criteria', [])
            else:
                # NSO format: tailf-ned-cisco-ios:aaa -> common-criteria-policy[]
                aaa_config = config.get('tailf-ned-cisco-ios:aaa', {})
                common_criteria = aaa_config.get('common-criteria-policy', [])
            
            if common_criteria and isinstance(common_criteria, list) and len(common_criteria) > 0:
                policy_configured = True
                
                # Get the first (typically only) policy
                policy = common_criteria[0]
                policy_name = policy.get('policy', '') or policy.get('name', '')
                min_length = policy.get('min-length')
                
                if min_length is not None:
                    min_length_compliant = (min_length >= MIN_PASSWORD_LENGTH)
            
            # Overall compliance
            overall_compliant = policy_configured and min_length_compliant
            
            results[device_name] = {
                'policy_configured': policy_configured,
                'policy_name': policy_name,
                'min_length': min_length,
                'min_length_compliant': min_length_compliant,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not policy_configured:
                    error_parts.append("  ✗ AAA common-criteria policy is NOT configured")
                else:
                    if min_length is None:
                        error_parts.append(f"  ✗ Policy '{policy_name}' does NOT have min-length configured")
                    elif not min_length_compliant:
                        error_parts.append(f"  ✗ Policy '{policy_name}' min-length is {min_length} (requires ≥ {MIN_PASSWORD_LENGTH})")
                        error_parts.append(f"    Current: {min_length} characters")
                        error_parts.append(f"    Required: {MIN_PASSWORD_LENGTH} characters")
                
                error_parts.append("\nPassword length requirement is NOT sufficient!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# aaa common-criteria policy PASSWORD_POLICY")
                error_parts.append("  R1(config-cc-policy)# min-length 15")
                error_parts.append("  R1(config-cc-policy)# exit")
                error_parts.append("  R1(config)# end")
                error_parts.append("\nNote: 15-character minimum significantly increases password strength")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking password length policy on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Required Minimum Length: {MIN_PASSWORD_LENGTH} characters")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ AAA common-criteria policy '{result['policy_name']}' configured")
            print(f"  ✓ Minimum password length: {result['min_length']} characters")
            print(f"  ✓ Password length requirement satisfied (≥ {MIN_PASSWORD_LENGTH})")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Policy configured: {'✓' if result.get('policy_configured') else '✗'}")
                if result.get('policy_name'):
                    print(f"  Policy name: {result['policy_name']}")
                if result.get('min_length') is not None:
                    print(f"  Min length: {result['min_length']} characters (requires {MIN_PASSWORD_LENGTH})")


if __name__ == "__main__":
    test_password_minimum_length()
