"""
HIPAA ID: HIPAA-AC-001
Rule: Unique User Identification
Severity: High
Classification: HIPAA Security Rule § 164.312(a)(2)(i)

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The network device must be configured to enforce unique user identification.

Discussion:
HIPAA Security Rule requires unique user identification to ensure that all users 
accessing electronic protected health information (ePHI) can be individually identified. 
This requirement ensures accountability and enables audit trails for access to ePHI 
through network infrastructure devices.

Shared accounts prevent the ability to track individual user actions and violate the 
principle of individual accountability required by HIPAA. Each person with access must 
be uniquely identifiable to support forensic analysis and compliance auditing.

Check Text:
Review the router configuration to verify that user accounts are configured individually 
and no shared or group accounts exist. The configuration should show individual username 
entries:

username admin privilege 15 secret 9 <hash>
username networkadmin privilege 15 secret 9 <hash>

Generic or shared account names such as "operator", "admin_shared", "team", or similar 
indicate non-compliance.

If shared accounts are in use or individual user accounts are not configured, this is a finding.

Fix Text:
Configure individual user accounts for each person requiring access:

R1(config)# username john.doe privilege 15 secret MySecureP@ssw0rd
R1(config)# username jane.smith privilege 10 secret AnotherP@ssw0rd
R1(config)# end

Remove any shared or generic accounts.

References:
HIPAA Security Rule: § 164.312(a)(2)(i) - Unique User Identification
NIST SP 800-53 Rev 5: AC-2 (Account Management), IA-2 (Identification and Authentication)
45 CFR 164.312(a)(2)(i)
"""

import os
import json
import yaml
import pytest
import re

HIPAA_ID = "HIPAA-AC-001"
RULE_TITLE = "Unique User Identification"
SEVERITY = "High"
CATEGORY = "HIPAA"
FRAMEWORK = "HIPAA Security Rule"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
HIPAA_REFERENCE = "45 CFR § 164.312(a)(2)(i)"

# Suspicious account names that might indicate shared accounts
SHARED_ACCOUNT_PATTERNS = [
    r'^admin$',
    r'^operator$',
    r'^team',
    r'^shared',
    r'^group',
    r'^common',
    r'^backup',
    r'^emergency',
    r'^test',
    r'^temp',
    r'^cisco$',
    r'^root$',
]


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
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def is_likely_shared_account(username):
    """Check if username matches patterns that suggest a shared account."""
    username_lower = username.lower()
    for pattern in SHARED_ACCOUNT_PATTERNS:
        if re.match(pattern, username_lower):
            return True
    return False


def test_unique_user_identification():
    """
    Test that unique user identification is enforced through individual user accounts.
    
    HIPAA § 164.312(a)(2)(i) requires unique user identification to ensure individual 
    accountability when accessing systems that store, process, or transmit ePHI.
    
    The test validates that:
    1. Local user accounts are configured
    2. User accounts appear to be individual (not shared/generic names)
    3. Multiple user accounts exist (not just one administrator)
    
    This ensures compliance with HIPAA's requirement for individual user accountability.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            users_configured = False
            user_count = 0
            individual_accounts = True
            suspicious_accounts = []
            user_list = []
            
            # Check for username configuration
            # Path: username[]
            usernames = config.get('tailf-ned-cisco-ios:username', [])
            
            if usernames and isinstance(usernames, list):
                users_configured = True
                user_count = len(usernames)
                
                # Check each username for compliance
                for user in usernames:
                    username = user.get('name', '')
                    user_list.append(username)
                    
                    # Check if username suggests shared account
                    if is_likely_shared_account(username):
                        individual_accounts = False
                        suspicious_accounts.append(username)
            
            # Compliance checks
            has_multiple_users = user_count >= 2
            no_suspicious_accounts = len(suspicious_accounts) == 0
            
            # Overall compliance
            overall_compliant = (
                users_configured and
                has_multiple_users and
                no_suspicious_accounts
            )
            
            results[device_name] = {
                'users_configured': users_configured,
                'user_count': user_count,
                'has_multiple_users': has_multiple_users,
                'individual_accounts': individual_accounts,
                'suspicious_accounts': suspicious_accounts,
                'user_list': user_list,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with HIPAA {HIPAA_ID}:"]
                
                if not users_configured:
                    error_parts.append("  ✗ No local user accounts are configured")
                elif not has_multiple_users:
                    error_parts.append(f"  ✗ Only {user_count} user account(s) configured (minimum 2 expected)")
                    error_parts.append(f"    Current users: {', '.join(user_list)}")
                
                if suspicious_accounts:
                    error_parts.append(f"  ✗ Potential shared/generic accounts detected:")
                    for account in suspicious_accounts:
                        error_parts.append(f"    - {account}")
                
                error_parts.append("\nHIPAA requires unique user identification for accountability!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# username john.doe privilege 15 secret <password>")
                error_parts.append("  R1(config)# username jane.smith privilege 10 secret <password>")
                error_parts.append("  R1(config)# end")
                error_parts.append("\nEach person must have a uniquely identifiable account.")
                error_parts.append("Remove shared accounts like 'admin', 'operator', 'team', etc.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking user accounts on {device_name}: {e}"
    
    # Print summary
    print("\nHIPAA Compliance Summary:")
    print(f"HIPAA ID: {HIPAA_ID}")
    print(f"Rule: {RULE_TITLE}")
    print(f"Reference: {HIPAA_REFERENCE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ {result['user_count']} individual user accounts configured")
            print(f"  ✓ Users: {', '.join(result['user_list'])}")
            print(f"  ✓ No suspicious shared accounts detected")
            print(f"  ✓ HIPAA unique user identification requirement satisfied")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Users configured: {'✓' if result.get('users_configured') else '✗'}")
                print(f"  User count: {result.get('user_count', 0)}")
                if result.get('user_list'):
                    print(f"  Current users: {', '.join(result['user_list'])}")
                if result.get('suspicious_accounts'):
                    print(f"  Suspicious accounts: {', '.join(result['suspicious_accounts'])}")


if __name__ == "__main__":
    test_unique_user_identification()
