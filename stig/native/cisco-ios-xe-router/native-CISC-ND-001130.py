"""
STIG ID: CISC-ND-001130
Finding ID: V-215696
Rule ID: SV-215696r961506_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96135; SV-105273

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to authenticate SNMP messages using a 
FIPS-validated Keyed-Hash Message Authentication Code (HMAC).

Discussion:
Without authenticating devices, unidentified or unknown devices may be introduced, thereby 
facilitating malicious activity. Bidirectional authentication provides stronger safeguards 
to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. 
A network connection is any connection with a device that communicates through a network. 
A remote connection is any connection with a device communicating through an external network.

For network devices, this requirement applies to device management traffic. Device management 
traffic includes SNMP queries and responses. SNMPv3 provides strong authentication using 
FIPS-validated HMAC algorithms (SHA-1, SHA-256, SHA-384, SHA-512). The authentication ensures 
that SNMP messages have not been tampered with and originate from authenticated sources.

SNMPv3 security levels:
- noAuthNoPriv: No authentication, no encryption (NOT FIPS-compliant)
- authNoPriv: Authentication with HMAC, no encryption (FIPS-compliant with SHA)
- authPriv (priv): Authentication with HMAC and encryption (FIPS-compliant with SHA)

FIPS-validated HMAC algorithms for SNMPv3:
- SHA (SHA-1): FIPS 180-4 validated
- SHA-256, SHA-384, SHA-512: FIPS 180-4 validated
- MD5: NOT FIPS-validated (should not be used)

This test verifies that SNMPv3 is configured with authentication (auth or priv security level), 
which requires HMAC-based authentication. Organizations should use SHA algorithms (not MD5) 
when configuring SNMP users.

Check Text:
Review the router configuration and verify that SNMP is configured to authenticate messages 
using a FIPS-validated HMAC.

snmp-server group V3GROUP v3 auth read V3READ write V3WRITE
snmp-server user V3USER V3GROUP v3 auth sha <password>
snmp-server host x.x.x.x version 3 auth V3USER

Verify using the show command:
show snmp user

User name: V3USER
Authentication Protocol: SHA

If the Cisco router is not configured to authenticate SNMP messages using a FIPS-validated 
HMAC, this is a finding.

Fix Text:
Configure the Cisco router to authenticate SNMP messages as shown in the example below.

R4(config)# snmp-server group V3GROUP v3 auth read V3READ write V3WRITE
R4(config)# snmp-server user V3USER V3GROUP v3 auth sha <password>
R4(config)# snmp-server view V3READ iso included
R4(config)# snmp-server view V3WRITE iso included
R4(config)# snmp-server host x.x.x.x version 3 auth V3USER
R4(config)# end

Note: Use "priv" instead of "auth" for both authentication and encryption:
R4(config)# snmp-server group V3GROUP v3 priv read V3READ write V3WRITE

References:
CCI: CCI-001967
NIST SP 800-53 Revision 4 :: IA-3 (1)
NIST SP 800-53 Revision 5 :: IA-3 (1)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001130"
FINDING_ID = "V-215696"
RULE_ID = "SV-215696r961506_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must authenticate SNMP messages using FIPS-validated HMAC"

# Valid FIPS-compliant security levels (require HMAC authentication)
FIPS_COMPLIANT_SECURITY_LEVELS = ['auth', 'priv']


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


def test_snmp_fips_hmac_authentication():
    """
    Test that SNMP is configured to authenticate messages using FIPS-validated HMAC.
    
    STIG V-215696 (CISC-ND-001130) requires that the router authenticates SNMP messages 
    using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC). This ensures:
    - SNMP messages have not been tampered with
    - SNMP messages originate from authenticated sources
    - Device management traffic is cryptographically protected
    - Bidirectional authentication for network connections
    
    The test validates that:
    1. SNMPv3 groups are configured
    2. Groups use authentication security level ("auth" or "priv")
    3. Groups do not use insecure "noAuthNoPriv" mode
    
    Note: The specific authentication protocol (SHA vs MD5) is configured with the 
    "snmp-server user" command and typically not visible in configuration output due to 
    password encryption. Organizations must ensure SHA (not MD5) is used when creating users.
    
    FIPS-validated HMAC algorithms:
    - SHA-1, SHA-256, SHA-384, SHA-512 (FIPS 180-4)
    - MD5 is NOT FIPS-validated and should not be used
    
    SNMPv3 security levels:
    - noAuthNoPriv: No authentication, no encryption (INSECURE, non-compliant)
    - auth: Authentication with HMAC, no encryption (COMPLIANT with SHA)
    - priv: Authentication with HMAC and encryption (COMPLIANT with SHA, RECOMMENDED)
    
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
                        
                        # Check if security level is FIPS-compliant (auth or priv)
                        if security_level in FIPS_COMPLIANT_SECURITY_LEVELS:
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
                    snmp_hosts.append({'ip': ip, 'version': version})
            
            # Overall compliance - at least one SNMPv3 group with auth/priv required
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
                    error_parts.append("  ✗ No SNMPv3 groups with FIPS-compliant authentication (auth/priv)")
                
                if non_compliant_groups:
                    error_parts.append(f"  ✗ Non-compliant groups found:")
                    for group in non_compliant_groups:
                        error_parts.append(f"    - {group['name']}: security level '{group['security_level']}'")
                
                error_parts.append("\nSNMP is NOT using FIPS-validated HMAC authentication!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R4(config)# snmp-server group V3GROUP v3 auth read V3READ write V3WRITE")
                error_parts.append("  R4(config)# snmp-server user V3USER V3GROUP v3 auth sha <password>")
                error_parts.append("  R4(config)# snmp-server view V3READ iso included")
                error_parts.append("  R4(config)# snmp-server view V3WRITE iso included")
                error_parts.append("  R4(config)# snmp-server host x.x.x.x version 3 auth V3USER")
                error_parts.append("  R4(config)# end")
                error_parts.append("\nRecommended (with encryption):")
                error_parts.append("  R4(config)# snmp-server group V3GROUP v3 priv read V3READ write V3WRITE")
                error_parts.append("  R4(config)# snmp-server user V3USER V3GROUP v3 auth sha <password> priv aes 128 <key>")
                error_parts.append("  R4(config)# snmp-server host x.x.x.x version 3 priv V3USER")
                error_parts.append("\nSNMPv3 Security Levels:")
                error_parts.append("  - noAuthNoPriv: No auth, no encryption [NON-COMPLIANT]")
                error_parts.append("  - auth: HMAC authentication, no encryption [COMPLIANT]")
                error_parts.append("  - priv: HMAC authentication + encryption [COMPLIANT, RECOMMENDED]")
                error_parts.append("\nFIPS-Validated HMAC Algorithms:")
                error_parts.append("  ✓ SHA (SHA-1): FIPS 180-4 validated")
                error_parts.append("  ✓ SHA-256, SHA-384, SHA-512: FIPS 180-4 validated")
                error_parts.append("  ✗ MD5: NOT FIPS-validated (do not use)")
                error_parts.append("\nIMPORTANT: When creating users, use 'auth sha' not 'auth md5'")
                error_parts.append("\nWithout FIPS-validated HMAC:")
                error_parts.append("  - SNMP messages can be spoofed or tampered with")
                error_parts.append("  - Unauthorized devices may access device management")
                error_parts.append("  - Device authentication is weak or non-existent")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking SNMP HMAC authentication on {device_name}: {e}"
    
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
            print(f"  ✓ SNMPv3 groups configured: {len(result['compliant_groups'])}")
            for group in result['compliant_groups']:
                print(f"    - {group['name']}: security level '{group['security_level']}'")
            if result.get('snmp_hosts'):
                print(f"  ✓ SNMP hosts configured:")
                for host in result['snmp_hosts']:
                    print(f"    - {host['ip']} (version {host['version']})")
            print(f"  ✓ SNMP uses FIPS-validated HMAC authentication")
            print(f"  ℹ Note: Ensure SNMP users are configured with 'auth sha' (not 'auth md5')")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  SNMP configured: {'✓' if result.get('snmp_configured') else '✗'}")
                print(f"  SNMPv3 groups: {len(result.get('v3_groups', []))}")
                print(f"  Compliant groups (auth/priv): {len(result.get('compliant_groups', []))}")
                if result.get('non_compliant_groups'):
                    print(f"  Non-compliant groups: {len(result['non_compliant_groups'])}")


if __name__ == "__main__":
    test_snmp_fips_hmac_authentication()
