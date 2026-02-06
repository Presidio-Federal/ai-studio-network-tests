"""
STIG ID: ARST-ND-000150
Finding ID: V-255951
Rule ID: SV-255951r960777_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista Multilayer Switch must be configured to automatically audit account creation, 
modification, disabling, removal, and enabling actions.

Discussion:
Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events relating 
to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or 
policy filter). Account management functions include:
- Account creation
- Account modification
- Account disabling
- Account removal
- Account enabling
- Privileged function execution

The network device must be configured to automatically audit these account management actions, 
providing a comprehensive audit trail for:
- Forensic analysis
- Security incident investigation
- Non-repudiation of actions
- Compliance verification
- Unauthorized activity detection

For Arista switches, this is accomplished through multiple AAA configurations:
1. Authentication logging (on-success and on-failure)
2. Accounting for exec sessions
3. Accounting for system events
4. Accounting for all commands

This ensures comprehensive logging of all account-related activities and privileged operations.

Check Text:
Verify the Arista network device is configured to automatically audit account management actions.

aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa accounting exec default start-stop group radius logging
aaa accounting system default start-stop group radius logging
aaa accounting commands all default start-stop logging group radius

If the device is not configured to automatically audit account management actions, this is a finding.

Fix Text:
Configure the Arista network device to automatically audit account management actions:

switch(config)# aaa authentication policy on-success log
switch(config)# aaa authentication policy on-failure log
switch(config)# aaa accounting exec default start-stop group radius logging
switch(config)# aaa accounting system default start-stop group radius logging
switch(config)# aaa accounting commands all default start-stop logging group radius
switch(config)# exit

Note: These configurations ensure that:
- Authentication successes and failures are logged
- Exec session start/stop events are logged
- System-level events are logged
- All commands (including privileged) are logged

References:
CCI: CCI-000018 (Account creation)
CCI: CCI-001403 (Account modification)
CCI: CCI-001404 (Account disabling)
CCI: CCI-001405 (Account removal)
CCI: CCI-002130 (Account enabling)
CCI: CCI-002234 (Privileged function execution)
CCI: CCI-000135 (Additional audit information)
CCI: CCI-000166 (Non-repudiation)
CCI: CCI-000172 (Audit record generation)

NIST SP 800-53 :: AC-2 (4), AC-6 (9), AU-3 (1), AU-10, AU-12 c
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000150"
FINDING_ID = "V-255951"
RULE_ID = "SV-255951r960777_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must automatically audit account management actions"

# Required AAA configurations for comprehensive account auditing
REQUIRED_AAA_CONFIGS = {
    'authentication_on_success': 'aaa authentication policy on-success log',
    'authentication_on_failure': 'aaa authentication policy on-failure log',
    'accounting_exec': 'aaa accounting exec default start-stop',  # Partial match
    'accounting_system': 'aaa accounting system default start-stop',  # Partial match
    'accounting_commands': 'aaa accounting commands all default start-stop'  # Partial match
}


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


def test_account_auditing_configuration():
    """
    Test that comprehensive AAA auditing is configured for account management actions.
    
    STIG V-255951 (ARST-ND-000150) requires that the Arista switch automatically audits 
    account management actions including creation, modification, disabling, removal, and 
    enabling. This ensures:
    - Complete audit trail for all account-related activities
    - Detection of unauthorized account manipulation
    - Non-repudiation of administrative actions
    - Forensic evidence for security investigations
    - Compliance with AC-2 (4) and other controls
    
    The test validates that:
    1. Authentication success logging is enabled
    2. Authentication failure logging is enabled
    3. Exec session accounting is configured
    4. System event accounting is configured
    5. Command accounting (all commands) is configured
    
    This comprehensive configuration ensures that:
    - Account creation, modification, disabling, removal, and enabling are logged
    - Privileged function execution is logged
    - Complete audit records are generated
    - Non-repudiation is supported
    
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
            
            # Track which required configurations are present
            config_status = {}
            missing_configs = []
            
            # Check each required AAA configuration
            for config_name, config_pattern in REQUIRED_AAA_CONFIGS.items():
                found = False
                matched_command = None
                
                # Search for the configuration in the device config
                for cmd_key in config.keys():
                    if config_pattern in cmd_key:
                        found = True
                        matched_command = cmd_key
                        break
                
                config_status[config_name] = {
                    'required': config_pattern,
                    'found': found,
                    'matched': matched_command
                }
                
                if not found:
                    missing_configs.append(config_name)
            
            # Overall compliance - all required configurations must be present
            overall_compliant = len(missing_configs) == 0
            
            results[device_name] = {
                'config_status': config_status,
                'missing_configs': missing_configs,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append(f"\n  Missing {len(missing_configs)} required AAA configuration(s):")
                
                for config_name in missing_configs:
                    config_pattern = REQUIRED_AAA_CONFIGS[config_name]
                    error_parts.append(f"    ✗ {config_name}: '{config_pattern}' NOT found")
                
                if config_status:
                    error_parts.append("\n  Configuration status:")
                    for config_name, status in config_status.items():
                        if status['found']:
                            error_parts.append(f"    ✓ {config_name}: Found")
                            error_parts.append(f"      Command: {status['matched']}")
                        else:
                            error_parts.append(f"    ✗ {config_name}: NOT found")
                
                error_parts.append("\nAccount management auditing is NOT fully configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  switch(config)# aaa authentication policy on-success log")
                error_parts.append("  switch(config)# aaa authentication policy on-failure log")
                error_parts.append("  switch(config)# aaa accounting exec default start-stop group radius logging")
                error_parts.append("  switch(config)# aaa accounting system default start-stop group radius logging")
                error_parts.append("  switch(config)# aaa accounting commands all default start-stop logging group radius")
                error_parts.append("  switch(config)# exit")
                error_parts.append("\nWhat each configuration provides:")
                error_parts.append("  1. on-success log: Logs successful authentication events")
                error_parts.append("  2. on-failure log: Logs failed authentication attempts")
                error_parts.append("  3. accounting exec: Logs exec session start/stop (account usage)")
                error_parts.append("  4. accounting system: Logs system events (account changes)")
                error_parts.append("  5. accounting commands: Logs all commands (privileged operations)")
                error_parts.append("\nAccount management actions audited:")
                error_parts.append("  - Account creation (CCI-000018)")
                error_parts.append("  - Account modification (CCI-001403)")
                error_parts.append("  - Account disabling (CCI-001404)")
                error_parts.append("  - Account removal (CCI-001405)")
                error_parts.append("  - Account enabling (CCI-002130)")
                error_parts.append("  - Privileged function execution (CCI-002234)")
                error_parts.append("\nWithout comprehensive auditing:")
                error_parts.append("  - Account management actions may go undetected")
                error_parts.append("  - Security incidents cannot be fully investigated")
                error_parts.append("  - No audit trail for forensic analysis")
                error_parts.append("  - Non-repudiation is not supported")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking account auditing configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"\nRequired AAA Configurations: {len(REQUIRED_AAA_CONFIGS)}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ All required AAA configurations present:")
            for config_name, status in result['config_status'].items():
                print(f"    ✓ {config_name}")
                if status.get('matched'):
                    print(f"      → {status['matched']}")
            print(f"  ✓ Comprehensive account management auditing configured")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Configurations found: {len(REQUIRED_AAA_CONFIGS) - len(result['missing_configs'])}/{len(REQUIRED_AAA_CONFIGS)}")
                if result.get('missing_configs'):
                    print(f"  Missing configurations:")
                    for config in result['missing_configs']:
                        print(f"    ✗ {config}")


if __name__ == "__main__":
    test_account_auditing_configuration()
