"""
STIG ID: CISC-RT-000150
Finding ID: V-220998
Rule ID: SV-220998r856403_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-101713; SV-110817

Group Title: SRG-NET-000362-RTR-000111

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Switch

Rule Title: The Cisco switch must be configured to have Gratuitous ARP disabled on all external interfaces.

Discussion:
A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. 
It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause 
network mapping information to be stored incorrectly, causing network malfunction.

Gratuitous ARP can be exploited by attackers to:
- Poison ARP caches of other devices
- Redirect traffic to malicious hosts
- Conduct man-in-the-middle attacks
- Cause denial of service conditions
- Disrupt network operations

By disabling gratuitous ARP on external interfaces, the switch reduces its exposure to ARP spoofing 
and other ARP-based attacks, protecting against denial of service events.

Check Text:
Review the configuration to determine if gratuitous ARP is disabled. The following command should 
NOT be found in the switch configuration:

ip gratuitous-arps

Note: With Cisco IOS, Gratuitous ARP is enabled and disabled globally.

If gratuitous ARP is enabled on any external interface, this is a finding.

Fix Text:
Disable gratuitous ARP as shown in the example below:

SW1(config)# no ip gratuitous-arps
SW1(config)# end

References:
CCI: CCI-002385: Protect against or limit the effects of organization-defined types of denial of service events.
NIST SP 800-53 Revision 4 :: SC-5
NIST SP 800-53 Revision 5 :: SC-5 a
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-RT-000150"
FINDING_ID = "V-220998"
RULE_ID = "SV-220998r856403_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must have Gratuitous ARP disabled on all external interfaces"


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


def test_gratuitous_arp_disabled():
    """
    Test that Gratuitous ARP is disabled globally on the switch.
    
    STIG V-220998 (CISC-RT-000150) requires that gratuitous ARP be disabled to protect 
    against ARP spoofing attacks and denial of service events. A gratuitous ARP broadcast 
    with matching source and destination MAC addresses can be spoofed to poison ARP caches 
    and redirect traffic maliciously.
    
    The test validates that:
    1. The 'ip gratuitous-arps' command is NOT present in the configuration
    2. Gratuitous ARP is disabled globally (which is the default behavior)
    
    This ensures the switch is protected against ARP-based attacks and DoS conditions.
    
    Native extraction method: Tests against native API/CLI JSON output.
    
    Note: With Cisco IOS/IOS-XE, gratuitous ARP is controlled globally, not per-interface.
    The default behavior is disabled unless explicitly enabled with 'ip gratuitous-arps'.
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
            
            # Initialize compliance flag
            gratuitous_arp_enabled = False
            gratuitous_arp_key = None
            
            # Check for gratuitous ARP configuration
            # The configuration element would appear as 'ip.gratuitous-arps' in native format
            # or 'tailf-ned-cisco-ios:ip.gratuitous-arps' in NSO format
            
            if data_format == 'native':
                # Native format: Check under 'ip' object
                ip_config = config.get('ip', {})
                
                # Check for 'gratuitous-arps' key (can be various forms)
                possible_keys = [
                    'gratuitous-arps',
                    'Cisco-IOS-XE-ip:gratuitous-arps',
                    'gratuitous-arp',
                    'Cisco-IOS-XE-ip:gratuitous-arp'
                ]
                
                for key in possible_keys:
                    if key in ip_config:
                        gratuitous_arp_enabled = True
                        gratuitous_arp_key = key
                        break
            
            else:
                # NSO format: Check under 'tailf-ned-cisco-ios:ip' object
                ip_config = config.get('tailf-ned-cisco-ios:ip', {})
                
                possible_keys = [
                    'gratuitous-arps',
                    'gratuitous-arp'
                ]
                
                for key in possible_keys:
                    if key in ip_config:
                        gratuitous_arp_enabled = True
                        gratuitous_arp_key = key
                        break
            
            # Compliant if gratuitous ARP is NOT enabled (not present in config)
            overall_compliant = not gratuitous_arp_enabled
            
            results[device_name] = {
                'gratuitous_arp_enabled': gratuitous_arp_enabled,
                'gratuitous_arp_key': gratuitous_arp_key,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append("")
                error_parts.append(f"  ✗ Gratuitous ARP is ENABLED (found '{gratuitous_arp_key}' in configuration)")
                error_parts.append("")
                error_parts.append("Security Risk:")
                error_parts.append("  • Gratuitous ARP can be exploited for ARP spoofing attacks")
                error_parts.append("  • Attackers can poison ARP caches on the network")
                error_parts.append("  • Traffic can be redirected to malicious hosts")
                error_parts.append("  • Man-in-the-middle attacks become easier")
                error_parts.append("  • Network disruption and denial of service conditions")
                error_parts.append("")
                error_parts.append("Gratuitous ARP MUST be disabled to protect against DoS attacks!")
                error_parts.append("")
                error_parts.append("Required remediation:")
                error_parts.append("  SW1(config)# no ip gratuitous-arps")
                error_parts.append("  SW1(config)# end")
                error_parts.append("")
                error_parts.append("Note: Gratuitous ARP is controlled globally in Cisco IOS/IOS-XE.")
                error_parts.append("      Once disabled, it applies to all interfaces.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking gratuitous ARP configuration on {device_name}: {e}"
    
    # Print summary
    print("\n" + "="*80)
    print("STIG Compliance Check Results")
    print("="*80)
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY} (CAT II)")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("="*80)
    print("\nDevice Results:")
    print("-"*80)
    
    for device, result in results.items():
        status = "✓ PASS" if result.get('compliant') else "✗ FAIL"
        print(f"\n{device}: {status}")
        
        if result.get('compliant'):
            print(f"  ✓ Gratuitous ARP is disabled (not configured)")
            print(f"  ✓ Protected against ARP spoofing attacks")
            print(f"  ✓ DoS prevention measure in place")
            print(f"  ✓ Compliant with SC-5 (Denial of Service Protection)")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  ✗ Gratuitous ARP is enabled: {result.get('gratuitous_arp_key')}")
                print(f"  ✗ Vulnerable to ARP spoofing and DoS attacks")
                print(f"  ✗ Must be disabled immediately")
    
    print("\n" + "="*80)
    print("Control Mapping:")
    print("  CCI-002385: Protect against DoS events")
    print("  NIST SP 800-53 Rev 4: SC-5")
    print("  NIST SP 800-53 Rev 5: SC-5 a")
    print("="*80 + "\n")


if __name__ == "__main__":
    test_gratuitous_arp_disabled()
