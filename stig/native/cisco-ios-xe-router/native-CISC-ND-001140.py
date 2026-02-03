"""
STIG ID: CISC-ND-001140
Finding ID: V-215697
Rule ID: SV-215697r961506_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96137; SV-105275

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to encrypt SNMP messages using a 
FIPS 140-2 approved algorithm.

Discussion:
Without confidentiality protection mechanisms, unauthorized individuals may gain access 
to sensitive information via a remote access session. Encryption provides a means to secure 
the remote connection to prevent unauthorized access to the data traversing the remote 
access connection, thereby providing a degree of confidentiality.

Remote access is access to DoD nonpublic information systems by an authorized user (or an 
information system) communicating through an external, non-organization-controlled network. 
For network devices, remote access includes SNMP queries and responses containing device 
configuration and status information.

SNMPv3 provides encryption (privacy) using FIPS 140-2 approved algorithms. The privacy 
protocol encrypts the SNMP message payload to prevent eavesdropping and protect sensitive 
information from unauthorized disclosure.

FIPS 140-2 approved encryption algorithms for SNMPv3:
- AES (128-bit, 192-bit, 256-bit): FIPS 197 approved
- 3DES: FIPS 46-3 approved (legacy, AES preferred)

Non-FIPS approved algorithms:
- DES: Not FIPS 140-2 approved (56-bit, deprecated)
- No encryption (authNoPriv): Not FIPS 140-2 compliant

SNMPv3 security levels:
- noAuthNoPriv: No authentication, no encryption (INSECURE, non-compliant)
- authNoPriv (auth): Authentication only, no encryption (NON-COMPLIANT for this control)
- authPriv (priv): Authentication and encryption (COMPLIANT when using AES/3DES)

The "priv" security level must be configured to enable encryption. Organizations should 
use AES encryption (128, 192, or 256-bit) as it is the current FIPS-approved standard 
and provides stronger security than legacy 3DES.

Check Text:
Review the router configuration and verify that SNMP is configured to encrypt messages 
using a FIPS 140-2 approved algorithm.

snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
snmp-server user V3USER V3GROUP v3 auth sha <password> priv aes 256 <key>
snmp-server host x.x.x.x version 3 priv V3USER

Verify using the show command:
show snmp user

User name: V3USER
Authentication Protocol: SHA
Privacy Protocol: AES256

If the Cisco router is not configured to encrypt SNMP messages using a FIPS 140-2 approved 
algorithm, this is a finding.

Fix Text:
Configure the Cisco router to encrypt SNMP messages using a FIPS 140-2 approved algorithm 
as shown in the example below.

R4(config)# snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
R4(config)# snmp-server user V3USER V3GROUP v3 auth sha <password> priv aes 256 <key>
R4(config)# snmp-server view V3READ iso included
R4(config)# snmp-server view V3WRITE iso included
R4(config)# snmp-server host x.x.x.x version 3 priv V3USER
R4(config)# end

Note: Other FIPS-approved options include:
- priv aes 128 (AES-128)
- priv aes 192 (AES-192)
- priv 3des (3DES, legacy but FIPS-approved)

References:
CCI: CCI-000068
NIST SP 800-53 :: AC-17 (2)
NIST SP 800-53 Revision 4 :: AC-17 (2)
NIST SP 800-53 Revision 5 :: AC-17 (2)
NIST SP 800-53A :: AC-17 (2).1
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001140"
FINDING_ID = "V-215697"
RULE_ID = "SV-215697r961506_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must encrypt SNMP messages using FIPS 140-2 approved algorithm"

# FIPS 140-2 compliant security level (requires encryption)
FIPS_COMPLIANT_SECURITY_LEVEL = 'priv'


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


def test_snmp_fips_encryption():
    """
    Test that SNMP is configured to encrypt messages using FIPS 140-2 approved algorithm.
    
    STIG V-215697 (CISC-ND-001140) requires that the router encrypts SNMP messages using 
    a FIPS 140-2 approved algorithm. This ensures:
    - SNMP messages are protected from eavesdropping
    - Sensitive device information is not disclosed to unauthorized parties
    - Remote access sessions have confidentiality protection
    - Cryptographic mechanisms protect data in transit
    
    The test validates that:
    1. SNMPv3 groups are configured
    2. Groups use "priv" security level (authPriv - authentication + encryption)
    3. Groups do not use insecure "auth" (authNoPriv - auth only) or "noAuthNoPriv"
    
    Note: The specific encryption algorithm (AES-128, AES-192, AES-256, 3DES) is 
    configured with the "snmp-server user" command and typically not visible in 
    configuration output due to key encryption. Organizations must ensure FIPS-approved 
    algorithms (AES or 3DES, not DES) are used when creating users.
    
    FIPS 140-2 approved encryption algorithms:
    - AES-128, AES-192, AES-256 (FIPS 197) [RECOMMENDED]
    - 3DES (FIPS 46-3) [LEGACY, but approved]
    
    Non-FIPS approved:
    - DES (56-bit, deprecated)
    - No encryption (authNoPriv)
    
    SNMPv3 security levels:
    - noAuthNoPriv: No auth, no encryption [NON-COMPLIANT]
    - auth (authNoPriv): Auth only, no encryption [NON-COMPLIANT for this control]
    - priv (authPriv): Auth + encryption [COMPLIANT with AES/3DES]
    
    Native extraction method: Tests against native API/CLI JSON output.
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
            
            # Initialize compliance flags
            snmp_configured = False
            v3_groups = []
            compliant_groups = []
            non_compliant_groups = []
            snmp_hosts = []
            
            # Check SNMP configuration
            if data_format == 'nso':
                # NSO format: tailf-ned-cisco-ios:snmp-server
                snmp_config = config.get('tailf-ned-cisco-ios:snmp-server', {})
            else:
                # Native format: snmp-server
                snmp_config = config.get('snmp-server', {})
            
            if snmp_config:
                snmp_configured = True
                
                # Check SNMPv3 groups
                if data_format == 'nso':
                    # NSO format: snmp-server -> group[]
                    groups = snmp_config.get('group', [])
                else:
                    # Native format: snmp-server -> Cisco-IOS-XE-snmp:group[]
                    groups = snmp_config.get('Cisco-IOS-XE-snmp:group', [])
                
                for group in groups:
                    group_id = group.get('id') or group.get('name', 'unknown')
                    
                    # Check for v3 configuration
                    v3_config = group.get('v3', {})
                    if v3_config:
                        v3_groups.append(group_id)
                        
                        # Get security level - can be in different places
                        security_level = v3_config.get('security-level')
                        
                        # Also check security-level-list for native format
                        if not security_level:
                            security_level_list = v3_config.get('security-level-list', [])
                            if security_level_list and len(security_level_list) > 0:
                                security_level = security_level_list[0].get('security-level')
                        
                        # Check if security level is FIPS-compliant (priv only)
                        if security_level == FIPS_COMPLIANT_SECURITY_LEVEL:
                            compliant_groups.append({
                                'name': group_id,
                                'security_level': security_level
                            })
                        else:
                            non_compliant_groups.append({
                                'name': group_id,
                                'security_level': security_level or 'not specified'
                            })
                
                # Check SNMP hosts (informational)
                if data_format == 'nso':
                    host_list = snmp_config.get('host', [])
                else:
                    host_list = snmp_config.get('Cisco-IOS-XE-snmp:host', [])
                
                for host in host_list:
                    ip = host.get('ip-address') or host.get('ip', 'unknown')
                    version = host.get('version', 'unknown')
                    sec_level = host.get('security-level', 'unknown')
                    snmp_hosts.append({'ip': ip, 'version': version, 'security_level': sec_level})
            
            # Overall compliance - at least one SNMPv3 group with priv required
            overall_compliant = len(compliant_groups) > 0 and len(non_compliant_groups) == 0
            
            results[device_name] = {
                'snmp_configured': snmp_configured,
                'v3_groups': v3_groups,
                'compliant_groups': compliant_groups,
                'non_compliant_groups': non_compliant_groups,
                'snmp_hosts': snmp_hosts,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not snmp_configured:
                    error_parts.append("  ✗ SNMP is NOT configured")
                elif len(v3_groups) == 0:
                    error_parts.append("  ✗ No SNMPv3 groups configured")
                elif len(compliant_groups) == 0:
                    error_parts.append("  ✗ No SNMPv3 groups with encryption enabled (priv security level)")
                
                if non_compliant_groups:
                    error_parts.append(f"  ✗ Non-compliant groups found (missing encryption):")
                    for group in non_compliant_groups:
                        error_parts.append(f"    - {group['name']}: security level '{group['security_level']}'")
                
                error_parts.append("\nSNMP is NOT using FIPS 140-2 approved encryption!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R4(config)# snmp-server group V3GROUP v3 priv read V3READ write V3WRITE")
                error_parts.append("  R4(config)# snmp-server user V3USER V3GROUP v3 auth sha <password> priv aes 256 <key>")
                error_parts.append("  R4(config)# snmp-server view V3READ iso included")
                error_parts.append("  R4(config)# snmp-server view V3WRITE iso included")
                error_parts.append("  R4(config)# snmp-server host x.x.x.x version 3 priv V3USER")
                error_parts.append("  R4(config)# end")
                error_parts.append("\nSNMPv3 Security Levels:")
                error_parts.append("  - noAuthNoPriv: No auth, no encryption [NON-COMPLIANT]")
                error_parts.append("  - auth (authNoPriv): Auth only, NO encryption [NON-COMPLIANT]")
                error_parts.append("  - priv (authPriv): Auth + encryption [COMPLIANT]")
                error_parts.append("\nFIPS 140-2 Approved Encryption Algorithms:")
                error_parts.append("  ✓ AES-128 (priv aes 128): FIPS 197 approved [RECOMMENDED]")
                error_parts.append("  ✓ AES-192 (priv aes 192): FIPS 197 approved [RECOMMENDED]")
                error_parts.append("  ✓ AES-256 (priv aes 256): FIPS 197 approved [RECOMMENDED]")
                error_parts.append("  ✓ 3DES (priv 3des): FIPS 46-3 approved [LEGACY]")
                error_parts.append("  ✗ DES (priv des): NOT FIPS-approved (do not use)")
                error_parts.append("\nIMPORTANT:")
                error_parts.append("  1. Group must use 'priv' security level (not 'auth')")
                error_parts.append("  2. User must be configured with 'priv aes' or 'priv 3des' (not 'priv des')")
                error_parts.append("  3. Hosts must use 'version 3 priv' (not 'version 3 auth')")
                error_parts.append("\nWithout FIPS-approved encryption:")
                error_parts.append("  - SNMP messages can be intercepted and read")
                error_parts.append("  - Sensitive device information may be disclosed")
                error_parts.append("  - Configuration data is transmitted in clear text")
                error_parts.append("  - Remote access confidentiality is not protected")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking SNMP encryption configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ SNMP configured")
            print(f"  ✓ SNMPv3 groups configured with encryption: {len(result['compliant_groups'])}")
            for group in result['compliant_groups']:
                print(f"    - {group['name']}: security level '{group['security_level']}' (encryption enabled)")
            if result.get('snmp_hosts'):
                print(f"  ✓ SNMP hosts configured:")
                for host in result['snmp_hosts']:
                    sec_info = f" (security: {host['security_level']})" if host.get('security_level') != 'unknown' else ""
                    print(f"    - {host['ip']} (v{host['version']}){sec_info}")
            print(f"  ✓ SNMP uses FIPS 140-2 approved encryption")
            print(f"  ℹ Note: Ensure users are configured with 'priv aes' (not 'priv des')")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  SNMP configured: {'✓' if result.get('snmp_configured') else '✗'}")
                print(f"  SNMPv3 groups: {len(result.get('v3_groups', []))}")
                print(f"  Groups with encryption (priv): {len(result.get('compliant_groups', []))}")
                if result.get('non_compliant_groups'):
                    print(f"  Groups without encryption: {len(result['non_compliant_groups'])}")
                    for group in result['non_compliant_groups']:
                        print(f"    - {group['name']}: '{group['security_level']}'")


if __name__ == "__main__":
    test_snmp_fips_encryption()
