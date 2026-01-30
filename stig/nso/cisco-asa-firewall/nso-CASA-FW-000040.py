"""
STIG ID: CASA-FW-000040
Finding ID: V-239855
Rule ID: SV-239855r665851_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000074-FW-000009
Rule Title: The Cisco ASA must be configured to generate traffic log entries 
            containing information to establish what type of events occurred.

Check Text:
Step 1: Verify that all ACL deny statements have the log parameter defined.
        Example: access-list OUTSIDE_OUT extended deny ip any any log

Step 2: Verify logging is enabled.
        Command: logging enable

Fix Text:
Step 1: Enable logging.
        ASA(config)# logging enable

Step 2: Include the log parameter on all deny ACL statements.
        ASA(config)# access-list OUTSIDE_OUT extended deny ip any any log

References:
CCI: CCI-000130
NIST SP 800-53 :: AU-3
NIST SP 800-53 Revision 4 :: AU-3
NIST SP 800-53 Revision 5 :: AU-3 a
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000040"
FINDING_ID = "V-239855"
RULE_ID = "SV-239855r665851_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must generate traffic log entries with event type information"


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
    # Format 2: {tailf-ncs:config: {tailf-ned-cisco-asa:...}} - direct NSO config
    # Format 3: {tailf-ned-cisco-asa:hostname: ..., ...} - unwrapped ASA config
    
    # Check if this is wrapped in tailf-ncs:config
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        # Direct NSO config with tailf-ncs:config wrapper
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: data}
    
    # Check if this is a direct ASA config (has tailf-ned-cisco-asa keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-asa:') for k in data.keys()):
        # Direct ASA config - wrap it
        device_name = data.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_asa_logging_and_acl_deny_logging():
    """
    Test that ASA logging is enabled and all ACL deny statements have log parameter.
    
    STIG V-239855 (CASA-FW-000040) requires that:
    1. Logging is enabled globally
    2. All ACL deny statements include the log parameter
    
    This ensures traffic log entries contain information to establish event types.
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
            # Get the config section
            device_config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            logging_enabled = False
            all_deny_rules_have_logging = True
            deny_rules_without_logging = []
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify all ACL deny statements have log parameter
            access_list_config = device_config.get('tailf-ned-cisco-asa:access-list', {})
            access_list_ids = access_list_config.get('access-list-id', [])
            
            for acl in access_list_ids:
                acl_name = acl.get('id', 'unknown')
                rules = acl.get('rule', [])
                
                for rule in rules:
                    rule_id = rule.get('id', '')
                    
                    # Check if this is a deny rule
                    if 'deny' in rule_id.lower():
                        # Check if log parameter is present
                        has_log = 'log' in rule
                        
                        if not has_log:
                            all_deny_rules_have_logging = False
                            deny_rules_without_logging.append({
                                'acl': acl_name,
                                'rule': rule_id
                            })
            
            # Overall compliance
            overall_compliant = logging_enabled and all_deny_rules_have_logging
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'all_deny_rules_have_logging': all_deny_rules_have_logging,
                'deny_rules_without_logging': deny_rules_without_logging,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not logging_enabled:
                error_parts.append("- Logging is not enabled (missing 'logging enable')")
            
            if not all_deny_rules_have_logging:
                error_parts.append(f"- {len(deny_rules_without_logging)} deny rule(s) missing log parameter:")
                for rule_info in deny_rules_without_logging:
                    error_parts.append(f"    ACL '{rule_info['acl']}': {rule_info['rule']}")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" + "\n".join(error_parts)
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking logging configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                if not result.get('logging_enabled'):
                    print("  - Logging is not enabled")
                if not result.get('all_deny_rules_have_logging'):
                    print(f"  - {len(result.get('deny_rules_without_logging', []))} deny rules missing log parameter")


if __name__ == "__main__":
    test_asa_logging_and_acl_deny_logging()
