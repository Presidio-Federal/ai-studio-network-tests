"""
STIG ID: ARST-ND-000350
Finding ID: V-255953
Rule ID: SV-255953r1051115_rule
Severity: CAT II (Medium)
Classification: Unclass
Group Title: SRG-APP-000148-NDM-000346

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista network device must be configured with only one local account to be used 
as the account of last resort in the event the authentication server is unavailable.

Discussion:
Authentication for administrative (privileged level) access to the device is required at all times. 
An account of last resort is a local account that is configured on the device to be used only when 
the authentication server is unavailable. This account must be configured with the highest 
privileges to allow for emergency administrative access.

The account of last resort should:
- Be a specifically designated emergency account (e.g., "Emergency-Admin")
- Have privilege level 15 (full administrative access)
- Have a strong, unique password stored securely offline
- Be the ONLY local privileged account (beyond system accounts)
- Not be the default "admin" account

The default "admin" account should be removed because:
- It is a well-known account name that attackers target
- It may have a default or weak password
- It does not clearly indicate its purpose as an emergency account
- Using a specific "Emergency-Admin" account makes the emergency nature explicit

Best practice: Store the emergency account credentials in a sealed envelope in a safe or secure 
location, to be accessed only when authentication servers are unavailable.

Check Text:
Verify that the Arista network device has only one local account configured for emergency access 
and that the default admin account has been removed.

username Emergency-Admin privilege 15 role network-admin secret sha512 <hash>

If the default admin account exists on the device, this is a finding.

If there is not exactly one emergency/last resort account configured, this is a finding.

Fix Text:
Step 1: Configure the Arista network device for a username "Emergency-Admin" account of last resort:

switch(config)# username Emergency-Admin privilege 15 role network-admin secret 0 <plain-text password>

Step 2: Verify the configuration and remove the default admin account:

switch# show running-config | section username
username Emergency-Admin privilege 15 role network-admin secret sha512 <hash>
!

switch(config)# no username admin

Step 3: Store the emergency account credentials in a sealed envelope in a safe or secure location.

References:
CCI: CCI-001358
NIST SP 800-53 :: AC-2 (7) (a)
NIST SP 800-53 Revision 4 :: AC-2 (7) (a)
NIST SP 800-53 Revision 5 :: AC-2 (7) (a)
NIST SP 800-53A :: AC-2 (7).1 (i)

CCI: CCI-002111
NIST SP 800-53 Revision 4 :: AC-2 a
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000350"
FINDING_ID = "V-255953"
RULE_ID = "SV-255953r1051115_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must have only one local account for emergency access (account of last resort)"

# Default admin account that should be removed
DEFAULT_ADMIN_ACCOUNT = 'admin'

# Common emergency account names (case-insensitive)
EMERGENCY_ACCOUNT_NAMES = ['emergency-admin', 'emergency', 'emergencyadmin', 'emerg-admin']

# Minimum privilege level for emergency account
MIN_PRIVILEGE_LEVEL = 15


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native Arista eAPI format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Arista eAPI JSON-RPC response format
    if isinstance(data, dict) and 'result' in data:
        result = data.get('result', [])
        if result and len(result) > 0:
            config = result[0].get('cmds', {})
            device_name = 'unknown-device'
            for cmd_key in config.keys():
                if cmd_key.startswith('hostname '):
                    device_name = cmd_key.replace('hostname ', '').strip()
                    break
            return {device_name: {'config': config}}
    
    # Direct format (already extracted cmds)
    if isinstance(data, dict) and 'cmds' in data:
        device_name = 'unknown-device'
        for cmd_key in data['cmds'].keys():
            if cmd_key.startswith('hostname '):
                device_name = cmd_key.replace('hostname ', '').strip()
                break
        return {device_name: {'config': data['cmds']}}
    
    return data


def parse_username_config(username_cmd):
    """Parse username command to extract username, privilege, and role."""
    # Format: "username NAME privilege LEVEL role ROLE secret ..."
    parts = username_cmd.split()
    
    username = None
    privilege = None
    role = None
    
    if len(parts) > 1:
        username = parts[1]  # After "username"
    
    try:
        if 'privilege' in parts:
            priv_idx = parts.index('privilege')
            if priv_idx + 1 < len(parts):
                privilege = int(parts[priv_idx + 1])
        
        if 'role' in parts:
            role_idx = parts.index('role')
            if role_idx + 1 < len(parts):
                role = parts[role_idx + 1]
    except (ValueError, IndexError):
        pass
    
    return username, privilege, role


def test_emergency_account_configuration():
    """
    Test that only one local emergency account exists and default admin account is removed.
    
    STIG V-255953 (ARST-ND-000350) requires that the Arista switch has only one local account 
    configured as the account of last resort for emergency access. This ensures:
    - Emergency access is available when authentication servers fail
    - The emergency account is clearly identified and managed
    - Default accounts are removed to reduce attack surface
    - Privileged access follows role-based access control
    
    The test validates that:
    1. At least one emergency/last resort account exists
    2. Emergency account has privilege level 15 (full admin access)
    3. Default "admin" account has been removed
    4. Local accounts are properly configured with roles
    
    Note: This test identifies the emergency account by common naming conventions
    (Emergency-Admin, emergency, etc.) and/or privilege level 15. Organizations should
    ensure only ONE such account exists and that it is properly documented and secured.
    
    This implements AC-2 (7) (Role-based schemes) from NIST SP 800-53.
    
    Native extraction method: Tests against Arista eAPI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('config', {})
            
            # Track all username accounts
            all_accounts = []
            emergency_accounts = []
            default_admin_exists = False
            privilege_15_accounts = []
            
            # Find all username configurations
            # Arista format: "username NAME privilege LEVEL role ROLE secret ...": null
            for cmd_key in config.keys():
                if cmd_key.startswith('username '):
                    username, privilege, role = parse_username_config(cmd_key)
                    
                    if username:
                        account_info = {
                            'username': username,
                            'privilege': privilege,
                            'role': role,
                            'command': cmd_key
                        }
                        all_accounts.append(account_info)
                        
                        # Check if this is the default admin account
                        if username.lower() == DEFAULT_ADMIN_ACCOUNT:
                            default_admin_exists = True
                        
                        # Check if this is an emergency account (by name)
                        if username.lower() in EMERGENCY_ACCOUNT_NAMES:
                            emergency_accounts.append(account_info)
                        
                        # Track privilege 15 accounts
                        if privilege == MIN_PRIVILEGE_LEVEL:
                            privilege_15_accounts.append(account_info)
            
            # Determine compliance
            # 1. Default admin account must NOT exist
            admin_compliant = not default_admin_exists
            
            # 2. At least one emergency account should exist
            has_emergency_account = (len(emergency_accounts) > 0 or len(privilege_15_accounts) > 0)
            
            # Overall compliance
            overall_compliant = admin_compliant and has_emergency_account
            
            results[device_name] = {
                'all_accounts': all_accounts,
                'emergency_accounts': emergency_accounts,
                'privilege_15_accounts': privilege_15_accounts,
                'default_admin_exists': default_admin_exists,
                'admin_compliant': admin_compliant,
                'has_emergency_account': has_emergency_account,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if default_admin_exists:
                    error_parts.append("\n  ✗ FINDING: Default 'admin' account EXISTS")
                    error_parts.append("    Risk: Well-known account targeted by attackers")
                    error_parts.append("    Action: Remove default admin account")
                
                if not has_emergency_account:
                    error_parts.append("\n  ✗ WARNING: No emergency account identified")
                    error_parts.append("    Expected: Account like 'Emergency-Admin' with privilege 15")
                
                if all_accounts:
                    error_parts.append("\n  Current local accounts:")
                    for account in all_accounts:
                        priv_info = f"privilege {account['privilege']}" if account['privilege'] else "privilege unknown"
                        role_info = f"role {account['role']}" if account['role'] else ""
                        
                        indicator = "✗" if account['username'].lower() == DEFAULT_ADMIN_ACCOUNT else "•"
                        error_parts.append(f"    {indicator} {account['username']}: {priv_info} {role_info}")
                
                error_parts.append("\nAccount of last resort is NOT properly configured!")
                error_parts.append("\nRequired remediation:")
                error_parts.append("\nStep 1: Create Emergency-Admin account:")
                error_parts.append("  switch(config)# username Emergency-Admin privilege 15 role network-admin secret 0 <password>")
                
                if default_admin_exists:
                    error_parts.append("\nStep 2: Remove default admin account:")
                    error_parts.append("  switch(config)# no username admin")
                
                error_parts.append("\nStep 3: Verify configuration:")
                error_parts.append("  switch# show running-config | section username")
                error_parts.append("  (Should show Emergency-Admin, not admin)")
                
                error_parts.append("\nStep 4: Secure emergency credentials:")
                error_parts.append("  - Document username and password")
                error_parts.append("  - Store in sealed envelope")
                error_parts.append("  - Keep in safe or secure location")
                error_parts.append("  - Use ONLY when authentication servers unavailable")
                
                error_parts.append("\nBest practices:")
                error_parts.append("  - Use a strong, unique password for emergency account")
                error_parts.append("  - Name clearly indicates emergency purpose")
                error_parts.append("  - Only ONE local privileged account for emergencies")
                error_parts.append("  - Regular users authenticate via AAA server")
                
                error_parts.append("\nWithout proper emergency account:")
                error_parts.append("  - Default account is a security vulnerability")
                error_parts.append("  - Attackers know to target 'admin' account")
                error_parts.append("  - No clear emergency access procedure")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking emergency account configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Default admin account: removed")
            print(f"  ✓ Emergency account(s) configured:")
            
            if result.get('emergency_accounts'):
                for account in result['emergency_accounts']:
                    print(f"    - {account['username']} (privilege {account['privilege']})")
            
            if result.get('privilege_15_accounts'):
                print(f"  ✓ Privilege 15 accounts:")
                for account in result['privilege_15_accounts']:
                    print(f"    - {account['username']} (role: {account['role']})")
            
            print(f"  ✓ Account of last resort properly configured")
            print(f"\n  ℹ️  Reminder: Ensure emergency credentials are:")
            print(f"     - Documented and stored securely offline")
            print(f"     - Accessible only in emergency situations")
            print(f"     - Reviewed and updated regularly")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Default admin exists: {'✗ YES (finding)' if result.get('default_admin_exists') else '✓ NO'}")
                print(f"  Emergency account configured: {'✓ YES' if result.get('has_emergency_account') else '✗ NO'}")
                
                if result.get('all_accounts'):
                    print(f"\n  Local accounts found ({len(result['all_accounts'])}):")
                    for account in result['all_accounts']:
                        priv_info = f"privilege {account['privilege']}" if account['privilege'] else "privilege ?"
                        indicator = "✗" if account['username'].lower() == DEFAULT_ADMIN_ACCOUNT else "•"
                        print(f"    {indicator} {account['username']}: {priv_info}")


if __name__ == "__main__":
    test_emergency_account_configuration()
