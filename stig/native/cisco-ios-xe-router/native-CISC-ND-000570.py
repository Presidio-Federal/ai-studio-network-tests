"""
STIG ID: CISC-ND-000570
Finding ID: V-215682
Rule ID: SV-215682r991823_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96073; SV-105211

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to enforce password complexity by requiring that 
at least one uppercase character be used.

Discussion:
Use of a complex password helps to increase the time and resources required to compromise the 
password. Password complexity, or strength, is a measure of the effectiveness of a password in 
resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. 
The more complex the password, the greater the number of possible combinations that need to be 
tested before the password is compromised. Requiring at least one uppercase character increases 
the character space and makes password attacks more difficult.

Check Text:
Review the router configuration to verify that it enforces password complexity by requiring that 
at least one uppercase character be used.

aaa common-criteria policy PASSWORD_POLICY
  upper-case 1

If the router is not configured to enforce password complexity by requiring that at least one 
uppercase character be used, this is a finding.

Fix Text:
Configure the Cisco router to enforce password complexity by requiring that at least one uppercase 
character be used as shown in the example below.

R1(config)# aaa common-criteria policy PASSWORD_POLICY
R1(config-cc-policy)# upper-case 1
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

STIG_ID = "CISC-ND-000570"
FINDING_ID = "V-215682"
RULE_ID = "SV-215682r991823_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must enforce password complexity requiring at least one uppercase character"

MIN_UPPERCASE_REQUIRED = 1


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


def test_password_uppercase_requirement():
    """
    Test that AAA common-criteria policy enforces at least one uppercase character in passwords.
    
    STIG V-215682 (CISC-ND-000570) requires that the router enforces password complexity 
    by requiring at least one uppercase character. This increases the character space and 
    makes brute-force attacks more difficult.
    
    The test validates that:
    1. AAA common-criteria policy is configured
    2. Upper-case requirement is set to at least 1
    
    This ensures passwords have sufficient complexity to resist attack attempts.
    
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
            upper_case = None
            upper_case_compliant = False
            
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
                upper_case = policy.get('upper-case')
                
                if upper_case is not None:
                    upper_case_compliant = (upper_case >= MIN_UPPERCASE_REQUIRED)
            
            # Overall compliance
            overall_compliant = policy_configured and upper_case_compliant
            
            results[device_name] = {
                'policy_configured': policy_configured,
                'policy_name': policy_name,
                'upper_case': upper_case,
                'upper_case_compliant': upper_case_compliant,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not policy_configured:
                    error_parts.append("  ✗ AAA common-criteria policy is NOT configured")
                else:
                    if upper_case is None:
                        error_parts.append(f"  ✗ Policy '{policy_name}' does NOT have upper-case configured")
                    elif not upper_case_compliant:
                        error_parts.append(f"  ✗ Policy '{policy_name}' upper-case is {upper_case} (requires ≥ {MIN_UPPERCASE_REQUIRED})")
                        error_parts.append(f"    Current: {upper_case} uppercase character(s)")
                        error_parts.append(f"    Required: {MIN_UPPERCASE_REQUIRED} uppercase character(s)")
                
                error_parts.append("\nPassword complexity requirement for uppercase is NOT configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# aaa common-criteria policy PASSWORD_POLICY")
                error_parts.append("  R1(config-cc-policy)# upper-case 1")
                error_parts.append("  R1(config-cc-policy)# exit")
                error_parts.append("  R1(config)# end")
                error_parts.append("\nNote: Requiring uppercase characters increases password strength")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking password uppercase policy on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Required Uppercase Characters: {MIN_UPPERCASE_REQUIRED}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ AAA common-criteria policy '{result['policy_name']}' configured")
            print(f"  ✓ Upper-case requirement: {result['upper_case']} character(s)")
            print(f"  ✓ Password uppercase complexity requirement satisfied")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Policy configured: {'✓' if result.get('policy_configured') else '✗'}")
                if result.get('policy_name'):
                    print(f"  Policy name: {result['policy_name']}")
                if result.get('upper_case') is not None:
                    print(f"  Upper-case: {result['upper_case']} (requires {MIN_UPPERCASE_REQUIRED})")


if __name__ == "__main__":
    test_password_uppercase_requirement()
