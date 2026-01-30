"""
STIG ID: CASA-FW-000270
Finding ID: V-239869
Rule ID: SV-239869r665893_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000364-FW-000040
Rule Title: The Cisco ASA must be configured to inspect all inbound and outbound 
            traffic at the application layer.

Discussion:
Application inspection enables the firewall to control traffic based on different 
parameters that exist within the packets such as enforcing application-specific 
message and field length. Inspection provides improved protection against 
application-based attacks by restricting the types of commands allowed for the 
applications. Application inspection also enforces conformance against published RFCs.

Some applications embed an IP address in the packet that needs to match the source 
address that is normally translated when it goes through the firewall. Enabling 
application inspection for a service that embeds IP addresses, the firewall translates 
embedded addresses and updates any checksum or other fields that are affected by the 
translation. Enabling application inspection for a service that uses dynamically 
assigned ports, the firewall monitors sessions to identify the dynamic port assignments, 
and permits data exchange on these ports for the duration of the specific session.

Check Text:
Review the firewall configuration to verify that inspection for applications deployed 
within the network is being performed on all interfaces.

The following command should be configured:
service-policy global_policy global

If the firewall is not configured to inspect all inbound and outbound traffic at the 
application layer, this is a finding.

Fix Text:
Configure the firewall to inspect all inbound and outbound traffic at the application layer.

ASA(config)# service-policy global_policy global
ASA(config)# end

References:
CCI: CCI-000366
NIST SP 800-53 :: CM-6 b
NIST SP 800-53 Revision 4 :: CM-6 b
NIST SP 800-53 Revision 5 :: CM-6 b
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000270"
FINDING_ID = "V-239869"
RULE_ID = "SV-239869r665893_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must inspect all inbound and outbound traffic at application layer"


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


def test_asa_application_layer_inspection():
    """
    Test that ASA has global application layer inspection configured.
    
    STIG V-239869 (CASA-FW-000270) requires that:
    1. A service-policy is configured
    2. The service-policy is applied globally
    3. The policy name is typically 'global_policy' (or custom policy with inspection)
    
    This ensures all inbound and outbound traffic is inspected at the application layer
    for improved protection against application-based attacks.
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
            service_policy_configured = False
            global_policy_applied = False
            policy_name = None
            global_scope = None
            
            # Check service-policy configuration
            service_policy_config = device_config.get('tailf-ned-cisco-asa:service-policy', None)
            
            if service_policy_config is not None:
                service_policy_configured = True
                
                # service-policy can be a list of dicts or a single dict
                if isinstance(service_policy_config, dict):
                    service_policy_config = [service_policy_config]
                elif not isinstance(service_policy_config, list):
                    service_policy_config = []
                
                # Look for global policy
                for entry in service_policy_config:
                    if isinstance(entry, dict):
                        # Check for policy-map name
                        pm_name = entry.get('policy-map', None)
                        
                        # Check if applied globally
                        # The 'global' key indicates global application
                        if 'global' in entry:
                            global_policy_applied = True
                            policy_name = pm_name
                            global_scope = entry.get('global')
                            break
                        
                        # Also check for 'interface' - if present, it's not global
                        if 'interface' not in entry and pm_name:
                            # Store the first policy we find
                            if policy_name is None:
                                policy_name = pm_name
            
            # Overall compliance - must have service-policy applied globally
            overall_compliant = service_policy_configured and global_policy_applied
            
            # Store results
            results[device_name] = {
                'service_policy_configured': service_policy_configured,
                'global_policy_applied': global_policy_applied,
                'policy_name': policy_name,
                'global_scope': global_scope,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            
            if not service_policy_configured:
                error_parts.append("- No service-policy is configured")
            elif not global_policy_applied:
                if policy_name:
                    error_parts.append(f"- Service-policy '{policy_name}' is configured but not applied globally")
                    error_parts.append("  (Policy must be applied with 'global' scope for all interfaces)")
                else:
                    error_parts.append("- Service-policy is configured but not applied globally")
                error_parts.append("  Expected: service-policy <policy-name> global")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nApplication layer inspection is REQUIRED for all inbound/outbound traffic.\n"
                    f"\nRequired configuration:\n"
                    f"  ASA(config)# service-policy global_policy global\n"
                    f"\nThis enables:\n"
                    f"  - Application-specific message and field length enforcement\n"
                    f"  - Protection against application-based attacks\n"
                    f"  - RFC conformance checking\n"
                    f"  - Embedded IP address translation\n"
                    f"  - Dynamic port monitoring for applications"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking application layer inspection on {device_name}: {e}"
    
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
                print(f"  Service-policy configured: {'✓' if result.get('service_policy_configured') else '✗'}")
                print(f"  Global policy applied: {'✓' if result.get('global_policy_applied') else '✗'}")
                if result.get('policy_name'):
                    print(f"  Policy name: {result.get('policy_name')}")
        else:
            # Show config details for passing tests
            print(f"  ✓ Service-policy configured")
            print(f"  ✓ Global policy applied")
            print(f"  Policy name: {result.get('policy_name', 'N/A')}")
            print(f"  Scope: global")


if __name__ == "__main__":
    test_asa_application_layer_inspection()
