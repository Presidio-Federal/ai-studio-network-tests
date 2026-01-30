"""
STIG ID: CASA-FW-000220
Finding ID: V-239864
Rule ID: SV-239864r891328_rule
Severity: CAT I (High)
Classification: Unclass

Group Title: SRG-NET-000362-FW-000028
Rule Title: The Cisco ASA must be configured to implement scanning threat detection.

Discussion:
In a port scanning attack, an unauthorized application is used to scan the host devices 
for available services and open ports for subsequent use in an attack. This type of 
scanning can be used as a DoS attack when the probing packets are sent excessively.

Check Text:
NOTE: When operating the ASA in multi-context mode with a separate IDPS, threat detection 
cannot be enabled and this check is Not Applicable.

Review the ASA configuration to determine if scanning threat detection has been enabled.

threat-detection scanning-threat shun

NOTE: The parameter "shun" is an optional parameter in the Cisco documentation, but is 
required here to offer additional protection by dropping further connections from the threat.

If the ASA has not been configured to enable scanning threat detection, this is a finding.

Fix Text:
Configure scanning threat detection as shown in the example below.

ASA(config)# threat-detection scanning-threat shun

References:
CCI: CCI-002385
NIST SP 800-53 Revision 4 :: SC-5
NIST SP 800-53 Revision 5 :: SC-5 a
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000220"
FINDING_ID = "V-239864"
RULE_ID = "SV-239864r891328_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must implement scanning threat detection"


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


def test_asa_scanning_threat_detection():
    """
    Test that ASA has scanning threat detection enabled with shun.
    
    STIG V-239864 (CASA-FW-000220) requires that:
    1. Threat detection is configured
    2. Scanning-threat is enabled
    3. Shun parameter is configured (to drop further connections from threat)
    
    This is a CAT I (High) severity finding because port scanning attacks can be 
    used for reconnaissance before attacks or as DoS attacks.
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
            scanning_threat_enabled = False
            shun_configured = False
            scanning_threat_config = None
            
            # Check threat-detection configuration
            threat_detection_config = device_config.get('tailf-ned-cisco-asa:threat-detection', None)
            
            if threat_detection_config is not None:
                threat_detection_configured = True
                
                # threat-detection can be a list of dicts or a single dict
                if isinstance(threat_detection_config, dict):
                    threat_detection_config = [threat_detection_config]
                elif not isinstance(threat_detection_config, list):
                    threat_detection_config = []
                
                # Look for scanning-threat entry
                for entry in threat_detection_config:
                    if isinstance(entry, dict):
                        entry_id = entry.get('id', None)
                        if entry_id == 'scanning-threat':
                            scanning_threat_enabled = True
                            scanning_threat_config = entry
                            
                            # Check if shun is configured
                            # shun can be an empty dict {} or have configuration
                            if 'shun' in entry:
                                shun_configured = True
                            
                            break
            
            # Overall compliance - all three must be true
            overall_compliant = (
                threat_detection_configured and 
                scanning_threat_enabled and
                shun_configured
            )
            
            # Store results
            results[device_name] = {
                'threat_detection_configured': threat_detection_configured,
                'scanning_threat_enabled': scanning_threat_enabled,
                'shun_configured': shun_configured,
                'scanning_threat_config': scanning_threat_config,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            
            if not threat_detection_configured:
                error_parts.append("- Threat detection is not configured")
            
            if not scanning_threat_enabled:
                if threat_detection_configured:
                    error_parts.append("- Scanning-threat is not enabled")
                    error_parts.append("  (threat-detection is configured but missing 'scanning-threat' entry)")
            
            if scanning_threat_enabled and not shun_configured:
                error_parts.append("- Scanning-threat is enabled but 'shun' parameter is not configured")
                error_parts.append("  NOTE: The 'shun' parameter is REQUIRED to drop further connections from threats")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\n⚠️  SEVERITY: CAT I (HIGH) - This is a critical security finding!\n"
                    f"\nRequired configuration:\n"
                    f"  ASA(config)# threat-detection scanning-threat shun\n"
                    f"\nNote: The 'shun' parameter provides additional protection by dropping\n"
                    f"      further connections from the scanning threat source."
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking scanning threat detection on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"⚠️  Severity: {SEVERITY} (CAT I - CRITICAL)")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Threat detection: {'✓' if result.get('threat_detection_configured') else '✗'}")
                print(f"  Scanning-threat enabled: {'✓' if result.get('scanning_threat_enabled') else '✗'}")
                print(f"  Shun configured: {'✓' if result.get('shun_configured') else '✗'}")
        else:
            # Show config details for passing tests
            print(f"  ✓ Threat detection configured")
            print(f"  ✓ Scanning-threat enabled")
            print(f"  ✓ Shun parameter configured")
            if result.get('scanning_threat_config'):
                print(f"  Config: {result.get('scanning_threat_config')}")


if __name__ == "__main__":
    test_asa_scanning_threat_detection()
