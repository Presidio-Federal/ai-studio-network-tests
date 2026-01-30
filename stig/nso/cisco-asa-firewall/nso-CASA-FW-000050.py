"""
STIG ID: CASA-FW-000050
Finding ID: V-239856
Rule ID: SV-239856r665854_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000075-FW-000010
Rule Title: The Cisco ASA must be configured to generate traffic log entries 
            containing information to establish when (date and time) the events occurred.

Discussion:
Without establishing when events occurred, it is impossible to establish, correlate, 
and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis of 
network traffic patterns, it is essential for security personnel to know when flow 
control events occurred (date and time) within the infrastructure.

Check Text:
Verify that the logging timestamp command has been configured as shown below.

logging enable
logging timestamp

If the ASA is not configured to generate traffic log entries containing information 
to establish when the events occurred, this is a finding.

Fix Text:
Configure the ASA to generate traffic log entries containing information to establish 
when the events occurred.

ASA(config)# logging timestamp

References:
CCI: CCI-000131
NIST SP 800-53 :: AU-3
NIST SP 800-53 Revision 4 :: AU-3
NIST SP 800-53 Revision 5 :: AU-3 b
NIST SP 800-53A :: AU-3.1
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000050"
FINDING_ID = "V-239856"
RULE_ID = "SV-239856r665854_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must generate traffic log entries with timestamp information"


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


def test_asa_logging_timestamp():
    """
    Test that ASA logging timestamp is enabled.
    
    STIG V-239856 (CASA-FW-000050) requires that:
    1. Logging is enabled globally
    2. Logging timestamp is configured
    
    This ensures traffic log entries contain date/time information to establish 
    when events occurred.
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
            logging_timestamp_configured = False
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify logging timestamp is configured
            # The timestamp can appear as 'timestamp' key in logging config
            logging_timestamp_configured = 'timestamp' in logging_config
            
            # Overall compliance - both must be true
            overall_compliant = logging_enabled and logging_timestamp_configured
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'logging_timestamp_configured': logging_timestamp_configured,
                'compliant': overall_compliant
            }
            
            # Assert that the device is compliant
            assert overall_compliant, (
                f"Device {device_name} is not compliant with STIG {STIG_ID}:\n"
                f"- Logging Enabled: {logging_enabled}\n"
                f"- Logging Timestamp Configured: {logging_timestamp_configured}\n"
                f"\nRequired configuration:\n"
                f"  ASA(config)# logging enable\n"
                f"  ASA(config)# logging timestamp"
            )
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking logging timestamp configuration on {device_name}: {e}"
    
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
                    print("  ✗ Logging is not enabled")
                else:
                    print("  ✓ Logging is enabled")
                
                if not result.get('logging_timestamp_configured'):
                    print("  ✗ Logging timestamp is not configured")
                else:
                    print("  ✓ Logging timestamp is configured")


if __name__ == "__main__":
    test_asa_logging_timestamp()
