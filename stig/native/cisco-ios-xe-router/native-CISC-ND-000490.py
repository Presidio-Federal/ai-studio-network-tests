"""
STIG ID: CISC-ND-000490
Finding ID: V-215679
Rule ID: SV-215679r1051115_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96061; SV-105199

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured with only one local account to be used as the 
account of last resort in the event the authentication server is unavailable.

Discussion:
It is important to have a single local account configured as the account of last resort to 
provide access to the device in case the centralized authentication server (e.g., TACACS+, RADIUS) 
is unavailable. This ensures that administrators can still access the device during an outage of 
the authentication infrastructure.

However, having multiple local accounts increases the attack surface and makes it difficult to 
track access when the authentication server is unavailable. Therefore, only one local account 
should be configured specifically for emergency access.

The AAA authentication configuration should be set to use the centralized authentication server 
first, with the local account as a fallback (e.g., "aaa authentication login default group tacacs+ local").

Check Text:
Review the router configuration to verify that only one local account exists and it is configured 
as the account of last resort.

Step 1: Verify only one local account is configured:

username admin privilege 15 secret 9 <hash>

Step 2: Verify AAA authentication is configured to use the authentication server first, then 
fallback to local:

aaa new-model
aaa authentication login default group tacacs+ local

If the router is not configured with only one local account to be used as the account of last 
resort in the event the authentication server is unavailable, this is a finding.

Fix Text:
Step 1: Configure a local account as shown in the example below.

R2(config)# username admin privilege 15 secret <password>

Step 2: Configure the authentication order to use the local account if the authentication server 
is not reachable as shown in the following example:

R2(config)# aaa authentication login default group tacacs+ local
R2(config)# end

Note: Remove any additional local accounts that are not needed for last resort access.

References:
CCI: CCI-001358, CCI-002111
NIST SP 800-53 :: AC-2 (7) (a)
NIST SP 800-53 Revision 4 :: AC-2 (7) (a), AC-2 a
NIST SP 800-53 Revision 5 :: AC-2 (7) (a)
NIST SP 800-53A :: AC-2 (7).1 (i)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000490"
FINDING_ID = "V-215679"
RULE_ID = "SV-215679r1051115_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must have only one local account as account of last resort"


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


def check_aaa_authentication_fallback(aaa_config, data_format='native'):
    """
    Check if AAA authentication has local fallback configured.
    Returns: (has_aaa_new_model, has_login_auth, has_local_fallback, auth_methods)
    """
    has_aaa_new_model = False
    has_login_auth = False
    has_local_fallback = False
    auth_methods = []
    
    if not aaa_config:
        return False, False, False, []
    
    if data_format == 'native':
        # Check for aaa new-model (can be a list with [None])
        new_model = aaa_config.get('Cisco-IOS-XE-aaa:new-model')
        has_aaa_new_model = new_model is not None
        
        # Check authentication login
        authentication = aaa_config.get('Cisco-IOS-XE-aaa:authentication', {})
        login_configs = authentication.get('login', [])
        
        for login_config in login_configs:
            if isinstance(login_config, dict):
                name = login_config.get('name', '')
                if name == 'default':
                    has_login_auth = True
                    
                    # Check for group (tacacs+/radius) with local fallback
                    # Can have 'a1' (first method), 'a2' (second method), etc.
                    a1 = login_config.get('a1', {})
                    a2 = login_config.get('a2', {})
                    
                    # Check if group authentication is first
                    if 'group' in a1:
                        auth_methods.append(f"group {a1.get('group', '')}")
                    
                    # Check if local is second (fallback)
                    if a2:
                        if 'local' in a2 or a2.get('local') is not None:
                            auth_methods.append('local')
                            has_local_fallback = True
                        elif 'local-case' in a2:
                            auth_methods.append('local-case')
                            has_local_fallback = True
    
    else:  # NSO format
        # Check for aaa new-model
        new_model = aaa_config.get('new-model')
        has_aaa_new_model = new_model is not None
        
        # Check authentication login
        authentication = aaa_config.get('authentication', {})
        login_configs = authentication.get('login', [])
        
        for login_config in login_configs:
            if isinstance(login_config, dict):
                name = login_config.get('name', '')
                if name == 'default':
                    has_login_auth = True
                    
                    # Check for group with local fallback
                    if 'group' in login_config:
                        auth_methods.append('group')
                    
                    if 'local' in login_config or login_config.get('local') is not None:
                        auth_methods.append('local')
                        has_local_fallback = True
    
    return has_aaa_new_model, has_login_auth, has_local_fallback, auth_methods


def test_last_resort_account():
    """
    Test that only one local account is configured as the account of last resort.
    
    STIG V-215679 (CISC-ND-000490) requires that the router has only one local account 
    configured to be used when the authentication server is unavailable. This ensures:
    1. Emergency access is available during authentication server outages
    2. Attack surface is minimized (not multiple local accounts)
    3. Accountability is maintained (one designated last resort account)
    
    The test validates that:
    1. Only one local username account exists
    2. AAA new-model is configured
    3. AAA authentication login uses group authentication with local fallback
    
    This ensures proper last resort account configuration.
    
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
            local_account_count = 0
            local_accounts = []
            aaa_new_model = False
            aaa_login_configured = False
            local_fallback_configured = False
            auth_methods = []
            
            # Check username configuration
            if data_format == 'native':
                usernames = config.get('username', [])
                aaa_config = config.get('aaa', {})
            else:
                usernames = config.get('tailf-ned-cisco-ios:username', [])
                aaa_config = config.get('tailf-ned-cisco-ios:aaa', {})
            
            if usernames and isinstance(usernames, list):
                local_account_count = len(usernames)
                for user in usernames:
                    username = user.get('name', '')
                    privilege = user.get('privilege', 'N/A')
                    local_accounts.append(f"{username} (privilege {privilege})")
            
            # Check AAA configuration
            aaa_new_model, aaa_login_configured, local_fallback_configured, auth_methods = \
                check_aaa_authentication_fallback(aaa_config, data_format)
            
            # Compliance checks
            has_one_account = (local_account_count == 1)
            has_proper_aaa = (aaa_new_model and aaa_login_configured and local_fallback_configured)
            
            # Overall compliance
            overall_compliant = has_one_account and has_proper_aaa
            
            results[device_name] = {
                'local_account_count': local_account_count,
                'local_accounts': local_accounts,
                'has_one_account': has_one_account,
                'aaa_new_model': aaa_new_model,
                'aaa_login_configured': aaa_login_configured,
                'local_fallback_configured': local_fallback_configured,
                'auth_methods': auth_methods,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not has_one_account:
                    if local_account_count == 0:
                        error_parts.append("  ✗ NO local accounts configured")
                        error_parts.append("    (At least one account needed for last resort access)")
                    else:
                        error_parts.append(f"  ✗ {local_account_count} local accounts configured (must be exactly 1)")
                        error_parts.append("    Current local accounts:")
                        for account in local_accounts:
                            error_parts.append(f"      - {account}")
                        error_parts.append("    (Only ONE account should exist as last resort)")
                
                if not aaa_new_model:
                    error_parts.append("  ✗ AAA new-model is NOT configured")
                
                if not aaa_login_configured:
                    error_parts.append("  ✗ AAA authentication login default is NOT configured")
                elif not local_fallback_configured:
                    error_parts.append("  ✗ AAA authentication does NOT have local fallback")
                    if auth_methods:
                        error_parts.append(f"    Current methods: {', '.join(auth_methods)}")
                    error_parts.append("    (Must end with 'local' as fallback)")
                
                error_parts.append("\nAccount of last resort is NOT properly configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  Step 1: Configure ONE local account:")
                error_parts.append("    R2(config)# username admin privilege 15 secret <password>")
                error_parts.append("")
                error_parts.append("  Step 2: Configure AAA with local fallback:")
                error_parts.append("    R2(config)# aaa new-model")
                error_parts.append("    R2(config)# aaa authentication login default group tacacs+ local")
                error_parts.append("    R2(config)# end")
                error_parts.append("")
                error_parts.append("  Note: Remove any extra local accounts - only one should exist")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking last resort account on {device_name}: {e}"
    
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
            print(f"  ✓ Exactly 1 local account configured: {result['local_accounts'][0]}")
            print(f"  ✓ AAA new-model configured")
            print(f"  ✓ AAA authentication login configured")
            print(f"  ✓ Local fallback configured: {', '.join(result['auth_methods'])}")
            print(f"  ✓ Account of last resort properly configured")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Local accounts: {result.get('local_account_count', 0)}")
                if result.get('local_accounts'):
                    for account in result['local_accounts']:
                        print(f"    - {account}")
                print(f"  AAA new-model: {'✓' if result.get('aaa_new_model') else '✗'}")
                print(f"  AAA login auth: {'✓' if result.get('aaa_login_configured') else '✗'}")
                print(f"  Local fallback: {'✓' if result.get('local_fallback_configured') else '✗'}")
                if result.get('auth_methods'):
                    print(f"  Auth methods: {', '.join(result['auth_methods'])}")


if __name__ == "__main__":
    test_last_resort_account()
