"""
STIG ID: ARST-ND-000120
Finding ID: V-255949
Rule ID: SV-255949r960840_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista Multilayer Switch must enforce the limit of three consecutive invalid 
logon attempts, after which time it must lock out the user account from accessing the device 
for 15 minutes.

Discussion:
By limiting the number of failed login attempts, the risk of unauthorized system access via 
user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by 
locking the account.

Setting the lockout period to 15 minutes (900 seconds) is a common practice that balances 
security with operational needs. This duration:
- Prevents rapid brute-force attacks
- Allows legitimate users to regain access after a reasonable waiting period
- Discourages attackers while minimizing impact on authorized administrators

The account lockout policy should:
- Limit consecutive invalid logon attempts (typically 3)
- Lock out the account for a defined duration (minimum 15 minutes/900 seconds)
- Apply to all user accounts accessing the device

Check Text:
Review the device configuration to verify that the account lockout policy is configured to 
lock out an account after three consecutive invalid logon attempts for a minimum of 15 minutes.

aaa authentication policy lockout failure 3 duration 900

If the device is not configured to enforce an account lockout policy after three consecutive 
invalid logon attempts for 15 minutes, this is a finding.

Fix Text:
Configure the account lockout policy using the following commands:

switch(config)# aaa authentication policy lockout failure 3 duration 900
switch(config)# exit

Note: The command combines both the failure count and duration in a single statement.
- failure 3: Lock out after 3 consecutive invalid attempts
- duration 900: Lock out for 900 seconds (15 minutes)

References:
CCI: CCI-000044
NIST SP 800-53 :: AC-7 a
NIST SP 800-53 Revision 4 :: AC-7 a
NIST SP 800-53 Revision 5 :: AC-7 a
NIST SP 800-53A :: AC-7.1 (ii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000120"
FINDING_ID = "V-255949"
RULE_ID = "SV-255949r960840_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must enforce account lockout after 3 invalid logon attempts for 15 minutes"

# STIG requirements
MAX_FAILED_ATTEMPTS = 3
MIN_LOCKOUT_DURATION = 900  # 15 minutes in seconds


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
    # Expected structure: {"jsonrpc": "2.0", "result": [{"cmds": {...}}]}
    if isinstance(data, dict) and 'result' in data:
        result = data.get('result', [])
        if result and len(result) > 0:
            config = result[0].get('cmds', {})
            # Extract hostname from config if available
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


def test_account_lockout_policy():
    """
    Test that account lockout policy is configured to lock accounts after 3 failed attempts for 15 minutes.
    
    STIG V-255949 (ARST-ND-000120) requires that the Arista switch enforces an account lockout 
    policy to protect against brute-force password attacks. This ensures:
    - Accounts are locked after a limited number of failed login attempts
    - Locked accounts remain inaccessible for a minimum duration
    - Attackers cannot rapidly try multiple password combinations
    - Legitimate users are protected from account compromise
    
    The test validates that:
    1. AAA authentication policy lockout is configured
    2. Failure count is set to 3 or fewer consecutive invalid attempts
    3. Lockout duration is set to 900 seconds (15 minutes) or longer
    
    This implements AC-7 (Unsuccessful Logon Attempts) from NIST SP 800-53.
    
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
            
            # Initialize compliance flags
            lockout_policy_configured = False
            failure_count = None
            lockout_duration = None
            failure_compliant = False
            duration_compliant = False
            
            # Check for AAA authentication policy lockout
            # Arista format: "aaa authentication policy lockout failure 3 duration 900": null
            for cmd_key in config.keys():
                if cmd_key.startswith('aaa authentication policy lockout'):
                    lockout_policy_configured = True
                    
                    # Parse the command to extract failure count and duration
                    # Format: "aaa authentication policy lockout failure X duration Y"
                    parts = cmd_key.split()
                    
                    try:
                        # Find 'failure' keyword and get the next value
                        if 'failure' in parts:
                            failure_idx = parts.index('failure')
                            if failure_idx + 1 < len(parts):
                                failure_count = int(parts[failure_idx + 1])
                                # Check if failure count is compliant (3 or fewer)
                                if failure_count <= MAX_FAILED_ATTEMPTS:
                                    failure_compliant = True
                        
                        # Find 'duration' keyword and get the next value
                        if 'duration' in parts:
                            duration_idx = parts.index('duration')
                            if duration_idx + 1 < len(parts):
                                lockout_duration = int(parts[duration_idx + 1])
                                # Check if duration is compliant (900 seconds or more)
                                if lockout_duration >= MIN_LOCKOUT_DURATION:
                                    duration_compliant = True
                    except (ValueError, IndexError):
                        # Parsing failed, leave values as None
                        pass
                    
                    break
            
            # Overall compliance - both failure count and duration must be compliant
            overall_compliant = (
                lockout_policy_configured and 
                failure_compliant and 
                duration_compliant
            )
            
            results[device_name] = {
                'lockout_policy_configured': lockout_policy_configured,
                'failure_count': failure_count,
                'lockout_duration': lockout_duration,
                'failure_compliant': failure_compliant,
                'duration_compliant': duration_compliant,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not lockout_policy_configured:
                    error_parts.append("  ✗ Account lockout policy is NOT configured")
                else:
                    if not failure_compliant:
                        if failure_count is None:
                            error_parts.append("  ✗ Failure count is NOT configured")
                        else:
                            error_parts.append(f"  ✗ Failure count is {failure_count} (requires ≤ {MAX_FAILED_ATTEMPTS})")
                    
                    if not duration_compliant:
                        if lockout_duration is None:
                            error_parts.append("  ✗ Lockout duration is NOT configured")
                        else:
                            error_parts.append(f"  ✗ Lockout duration is {lockout_duration} seconds (requires ≥ {MIN_LOCKOUT_DURATION})")
                            error_parts.append(f"    Current: {lockout_duration // 60} minutes")
                            error_parts.append(f"    Required: {MIN_LOCKOUT_DURATION // 60} minutes minimum")
                
                error_parts.append("\nAccount lockout policy does NOT meet requirements!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  switch(config)# aaa authentication policy lockout failure 3 duration 900")
                error_parts.append("  switch(config)# exit")
                error_parts.append("\nConfiguration breakdown:")
                error_parts.append(f"  - failure 3: Lock account after {MAX_FAILED_ATTEMPTS} consecutive invalid attempts")
                error_parts.append(f"  - duration 900: Lock account for {MIN_LOCKOUT_DURATION} seconds (15 minutes)")
                error_parts.append("\nAlternative configurations:")
                error_parts.append("  - More restrictive: failure 2 duration 1800 (2 attempts, 30 min lockout)")
                error_parts.append("  - Balanced: failure 3 duration 900 (3 attempts, 15 min lockout) [RECOMMENDED]")
                error_parts.append("  - Less restrictive: failure 5 duration 900 (5 attempts, 15 min lockout)")
                error_parts.append("\nNote: Duration must be at least 900 seconds (15 minutes)")
                error_parts.append("\nWithout account lockout policy:")
                error_parts.append("  - Brute-force password attacks are not mitigated")
                error_parts.append("  - Unlimited login attempts are allowed")
                error_parts.append("  - Accounts can be compromised more easily")
                error_parts.append("  - No deterrent for attackers")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking account lockout policy on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Required: ≤{MAX_FAILED_ATTEMPTS} failures, ≥{MIN_LOCKOUT_DURATION} seconds ({MIN_LOCKOUT_DURATION // 60} minutes)")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Account lockout policy configured")
            print(f"  ✓ Failure count: {result['failure_count']} consecutive invalid attempts")
            print(f"  ✓ Lockout duration: {result['lockout_duration']} seconds ({result['lockout_duration'] // 60} minutes)")
            print(f"  ✓ Policy meets STIG requirements")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Lockout policy configured: {'✓' if result.get('lockout_policy_configured') else '✗'}")
                if result.get('failure_count') is not None:
                    compliant_indicator = '✓' if result.get('failure_compliant') else '✗'
                    print(f"  {compliant_indicator} Failure count: {result['failure_count']} (requires ≤{MAX_FAILED_ATTEMPTS})")
                if result.get('lockout_duration') is not None:
                    compliant_indicator = '✓' if result.get('duration_compliant') else '✗'
                    print(f"  {compliant_indicator} Lockout duration: {result['lockout_duration']} seconds / {result['lockout_duration'] // 60} minutes")
                    print(f"     (requires ≥{MIN_LOCKOUT_DURATION} seconds / {MIN_LOCKOUT_DURATION // 60} minutes)")


if __name__ == "__main__":
    test_account_lockout_policy()
