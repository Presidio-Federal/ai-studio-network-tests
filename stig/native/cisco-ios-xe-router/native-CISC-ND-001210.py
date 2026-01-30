"""
STIG ID: CISC-ND-001210
Finding ID: V-220556
Rule ID: SV-220556r961557_rule
Severity: CAT I (High)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to use SSH version 2 and FIPS-approved 
            encryption algorithms.

Discussion:
SSH version 1 is a protocol that has never been defined in a standard. Since SSH-1 has 
inherent design flaws which make it vulnerable to attacks, e.g., man-in-the-middle 
attacks, it is now generally considered obsolete and should be avoided by explicitly 
disabling fallback to SSH-1.

Without confidentiality protection mechanisms, unauthorized individuals may gain access 
to sensitive information via a remote access session. Remote access is access to DoD 
nonpublic information systems by an authorized user (or an information system) 
communicating through an external, non-organization-controlled network. Remote access 
methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized 
access to the data traversing the remote access connection thereby providing a degree 
of confidentiality. The encryption strength of mechanism is selected based on the 
security categorization of the information.

Check Text:
Review the router configuration to verify that SSH version 2 is configured and that 
FIPS-approved encryption algorithms are used.

ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
ip ssh server algorithm mac hmac-sha2-256

If SSH version 2 is not configured or if FIPS-approved encryption is not used, this 
is a finding.

Fix Text:
Configure SSH version 2 and FIPS-approved encryption algorithms.

Router(config)# ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
Router(config)# ip ssh server algorithm mac hmac-sha2-256
Router(config)# end

References:
CCI: CCI-000068
NIST SP 800-53 :: AC-17 (2)
NIST SP 800-53 Revision 4 :: AC-17 (2)
NIST SP 800-53 Revision 5 :: AC-17 (2)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001210"
FINDING_ID = "V-220556"
RULE_ID = "SV-220556r961557_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must use SSH version 2 with FIPS-approved encryption"

# FIPS-approved encryption algorithms
APPROVED_ENCRYPTION = ['aes256-ctr', 'aes192-ctr', 'aes128-ctr']
APPROVED_MAC = ['hmac-sha2-256', 'hmac-sha2-512']


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
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_ssh_version_2_and_fips_encryption():
    """
    Test that SSH version 2 is configured with FIPS-approved encryption algorithms.
    
    STIG V-220556 (CISC-ND-001210) requires:
    1. SSH server algorithm encryption must use FIPS-approved ciphers (AES-CTR)
    2. SSH server algorithm MAC must use FIPS-approved HMAC (SHA2)
    
    This is a CAT I (High) finding because SSH v1 and weak encryption expose the 
    device to man-in-the-middle attacks and unauthorized access.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            ip_config = config.get('tailf-ned-cisco-ios:ip', {})
            ssh_config = ip_config.get('ssh', {})
            
            # Initialize compliance flags
            ssh_configured = False
            encryption_configured = False
            mac_configured = False
            all_encryption_approved = False
            all_mac_approved = False
            
            configured_encryption = []
            configured_mac = []
            non_approved_encryption = []
            non_approved_mac = []
            
            if ssh_config:
                ssh_configured = True
                server_config = ssh_config.get('server', {})
                algorithm_config = server_config.get('algorithm', {})
                
                # Check encryption algorithms
                encryption_list = algorithm_config.get('encryption', [])
                if encryption_list:
                    encryption_configured = True
                    configured_encryption = encryption_list
                    
                    # Check if all configured encryption algorithms are approved
                    non_approved = [alg for alg in encryption_list if alg not in APPROVED_ENCRYPTION]
                    non_approved_encryption = non_approved
                    all_encryption_approved = len(non_approved) == 0 and len(encryption_list) > 0
                
                # Check MAC algorithms
                mac_list = algorithm_config.get('mac', [])
                if mac_list:
                    mac_configured = True
                    configured_mac = mac_list
                    
                    # Check if all configured MAC algorithms are approved
                    non_approved = [alg for alg in mac_list if alg not in APPROVED_MAC]
                    non_approved_mac = non_approved
                    all_mac_approved = len(non_approved) == 0 and len(mac_list) > 0
            
            # Overall compliance
            overall_compliant = (
                ssh_configured and
                encryption_configured and
                mac_configured and
                all_encryption_approved and
                all_mac_approved
            )
            
            results[device_name] = {
                'ssh_configured': ssh_configured,
                'encryption_configured': encryption_configured,
                'mac_configured': mac_configured,
                'all_encryption_approved': all_encryption_approved,
                'all_mac_approved': all_mac_approved,
                'configured_encryption': configured_encryption,
                'configured_mac': configured_mac,
                'non_approved_encryption': non_approved_encryption,
                'non_approved_mac': non_approved_mac,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not ssh_configured:
                    error_parts.append("  ✗ SSH is not configured")
                elif not encryption_configured:
                    error_parts.append("  ✗ SSH encryption algorithms not configured")
                elif not all_encryption_approved:
                    error_parts.append("  ✗ Non-FIPS approved encryption algorithms detected:")
                    error_parts.append(f"    Configured: {', '.join(configured_encryption)}")
                    if non_approved_encryption:
                        error_parts.append(f"    Non-approved: {', '.join(non_approved_encryption)}")
                    error_parts.append(f"    Approved: {', '.join(APPROVED_ENCRYPTION)}")
                
                if not mac_configured:
                    error_parts.append("  ✗ SSH MAC algorithms not configured")
                elif not all_mac_approved:
                    error_parts.append("  ✗ Non-FIPS approved MAC algorithms detected:")
                    error_parts.append(f"    Configured: {', '.join(configured_mac)}")
                    if non_approved_mac:
                        error_parts.append(f"    Non-approved: {', '.join(non_approved_mac)}")
                    error_parts.append(f"    Approved: {', '.join(APPROVED_MAC)}")
                
                error_parts.append("\n⚠️  SEVERITY: CAT I (HIGH) - This is a critical security finding!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  Router(config)# ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr")
                error_parts.append("  Router(config)# ip ssh server algorithm mac hmac-sha2-256")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking SSH configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"⚠️  Severity: {SEVERITY} (CAT I - CRITICAL)")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ SSH configured with FIPS-approved algorithms")
            print(f"  Encryption: {', '.join(result.get('configured_encryption', []))}")
            print(f"  MAC: {', '.join(result.get('configured_mac', []))}")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  SSH configured: {'✓' if result.get('ssh_configured') else '✗'}")
                print(f"  Encryption configured: {'✓' if result.get('encryption_configured') else '✗'}")
                print(f"  MAC configured: {'✓' if result.get('mac_configured') else '✗'}")
                print(f"  All encryption FIPS-approved: {'✓' if result.get('all_encryption_approved') else '✗'}")
                print(f"  All MAC FIPS-approved: {'✓' if result.get('all_mac_approved') else '✗'}")


if __name__ == "__main__":
    test_ssh_version_2_and_fips_encryption()
