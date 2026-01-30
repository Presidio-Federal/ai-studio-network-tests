"""
STIG ID: CASA-FW-000150
Finding ID: V-239860
Rule ID: SV-239860r991796_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000193-FW-000030
Rule Title: The Cisco ASA must be configured to enable threat detection to mitigate 
            risks of denial-of-service (DoS) attacks.

Discussion:
A firewall experiencing a DoS attack will not be able to handle production traffic load. 
The high utilization and CPU caused by a DoS attack will also have an effect on control 
keep-alives and timers used for neighbor peering, resulting in route flapping and will 
eventually black-hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's 
resource utilization. The use of redundant components and load balancing are examples of 
mitigating "flood-type" DoS attacks through increased capacity.

Check Text:
NOTE: When operating the ASA in multi-context mode with a separate IDPS, threat detection 
cannot be enabled, and this check is Not Applicable.

Review the ASA configuration to determine if threat detection has been enabled.

threat-detection basic-threat

If the ASA has not been configured to enable threat detection to mitigate risks of DoS 
attacks, this is a finding.

Fix Text:
Configure threat detection as shown in the example below.

ASA(config)# threat-detection basic-threat

References:
CCI: CCI-001095, CCI-004866
NIST SP 800-53 :: SC-5 (2)
NIST SP 800-53 Revision 4 :: SC-5 (2)
NIST SP 800-53 Revision 5 :: SC-5 (2), SC-5 b
NIST SP 800-53A :: SC-5 (2).1
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000150"
FINDING_ID = "V-239860"
RULE_ID = "SV-239860r991796_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must enable threat detection to mitigate DoS attacks"


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


def test_asa_threat_detection_enabled():
    """
    Test that ASA has threat detection enabled for DoS mitigation.
    
    STIG V-239860 (CASA-FW-000150) requires that:
    1. Threat detection basic-threat is enabled
    
    NOTE: This check is Not Applicable when operating ASA in multi-context mode 
    with a separate IDPS.
    
    This ensures the ASA can detect and mitigate denial-of-service attacks.
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
            threat_detection_configured = False
            basic_threat_enabled = False
            
            # Check: Verify threat-detection is configured
            threat_detection_config = device_config.get('tailf-ned-cisco-asa:threat-detection', None)
            
            if threat_detection_config is not None:
                threat_detection_configured = True
                
                # Threat detection can be a list of objects with 'id' field
                # Example: [{'id': 'basic-threat'}, {'id': 'scanning-threat', 'shun': {}}, ...]
                if isinstance(threat_detection_config, list):
                    # Check if any entry has 'id' == 'basic-threat'
                    for entry in threat_detection_config:
                        if isinstance(entry, dict) and entry.get('id') == 'basic-threat':
                            basic_threat_enabled = True
                            break
                # Also check if it's a dict format
                elif isinstance(threat_detection_config, dict):
                    basic_threat_enabled = 'basic-threat' in threat_detection_config
            
            # Overall compliance
            overall_compliant = threat_detection_configured and basic_threat_enabled
            
            # Store results
            results[device_name] = {
                'threat_detection_configured': threat_detection_configured,
                'basic_threat_enabled': basic_threat_enabled,
                'compliant': overall_compliant
            }
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_parts = []
                if not threat_detection_configured:
                    error_parts.append("- Threat detection is not configured")
                elif not basic_threat_enabled:
                    error_parts.append("- Threat detection is present but 'basic-threat' is not enabled")
                
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired configuration:\n"
                    f"  ASA(config)# threat-detection basic-threat\n"
                    f"\nNote: If operating in multi-context mode with separate IDPS, "
                    f"this check is Not Applicable."
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking threat detection configuration on {device_name}: {e}"
    
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
                if result.get('threat_detection_configured'):
                    print("  ✓ Threat detection is configured")
                    if result.get('basic_threat_enabled'):
                        print("  ✓ Basic-threat is enabled")
                    else:
                        print("  ✗ Basic-threat is not enabled")
                else:
                    print("  ✗ Threat detection is not configured")
        else:
            print(f"  ✓ Threat detection configured")
            print(f"  ✓ Basic-threat enabled")


if __name__ == "__main__":
    test_asa_threat_detection_enabled()
