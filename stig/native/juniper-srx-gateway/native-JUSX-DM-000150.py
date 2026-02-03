"""
STIG ID: JUSX-DM-000150
Finding ID: V-223227
Rule ID: SV-223227r1056177_rule
Version: 3, Release: 3
Severity: CAT I (High)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000514-NDM-000338

Rule Title: The Juniper SRX Services Gateway must implement cryptographic mechanisms 
            to protect the confidentiality of remote maintenance sessions.

Discussion:
This requirement addresses the confidentiality of nonlocal maintenance and diagnostic 
communications. Nonlocal maintenance and diagnostic activities are those activities 
conducted by individuals communicating through a network, either an external network 
(e.g., the Internet) or an internal network.

The use of weak or untested encryption algorithms undermines the purposes of using 
encryption to protect data. The network element must implement cryptographic modules 
adhering to the higher standards approved by the federal government since this provides 
assurance they have been tested and validated.

This is a CAT I (High severity) finding because weak cryptographic mechanisms expose 
administrative credentials and configuration data to interception and decryption, 
potentially leading to complete device compromise.

Required SSH cryptographic mechanisms:

1. **Protocol Version:** SSHv2 only (SSHv1 has known vulnerabilities)

2. **Ciphers (Encryption Algorithms):**
   - aes256-ctr (AES 256-bit Counter Mode)
   - aes192-ctr (AES 192-bit Counter Mode)
   - aes128-ctr (AES 128-bit Counter Mode)
   - CTR mode provides confidentiality without authentication

3. **MACs (Message Authentication Codes):**
   - hmac-sha2-512 (HMAC with SHA-2 512-bit)
   - hmac-sha2-256 (HMAC with SHA-2 256-bit)
   - SHA-2 family provides stronger integrity protection than SHA-1

4. **Key Exchange Algorithms:**
   - ecdh-sha2-nistp521 (ECDH with NIST P-521 curve)
   - ecdh-sha2-nistp384 (ECDH with NIST P-384 curve)
   - ecdh-sha2-nistp256 (ECDH with NIST P-256 curve)
   - Elliptic Curve Diffie-Hellman provides forward secrecy

Why These Mechanisms Matter:
- Protects administrative credentials during authentication
- Encrypts all configuration commands and responses
- Prevents man-in-the-middle attacks
- Ensures forward secrecy (past sessions remain secure if key compromised)
- Provides integrity protection against tampering

Security Impact of Weak Cryptography:
- Credentials can be captured and decrypted
- Configuration changes can be intercepted
- Device can be completely compromised
- Lateral movement to other devices possible
- Compliance violations (FIPS 140-2, DoD APL)

Check Text:
Verify SSH is configured to use only FIPS 140-2 approved algorithms.

[edit]
show system services ssh

The configuration should include:
protocol-version v2;
ciphers [ aes256-ctr aes192-ctr aes128-ctr ];
macs [ hmac-sha2-512 hmac-sha2-256 ];
key-exchange [ ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 ];

If SSH is not configured to use only FIPS 140-2 approved algorithms, this is a finding.

Fix Text:
Configure SSH to use only FIPS 140-2 approved algorithms.

[edit]
set system services ssh protocol-version v2
set system services ssh ciphers aes256-ctr
set system services ssh ciphers aes192-ctr
set system services ssh ciphers aes128-ctr
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh key-exchange ecdh-sha2-nistp521
set system services ssh key-exchange ecdh-sha2-nistp384
set system services ssh key-exchange ecdh-sha2-nistp256
commit

References:
CCI: CCI-003123: Implement organization-defined cryptographic mechanisms to protect 
                 the confidentiality of nonlocal maintenance and diagnostic communications.
NIST SP 800-53 Revision 4 :: MA-4 (6)
NIST SP 800-53 Revision 5 :: MA-4 (6)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223227
Rule ID: SV-223227r1056177_rule
STIG ID: JUSX-DM-000150
Severity: CAT I
Classification: Unclass
Legacy IDs: V-66531; SV-81021
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000150"
FINDING_ID = "V-223227"
RULE_ID = "SV-223227r1056177_rule"
SEVERITY = "CAT I"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Required SSH cryptographic configurations
REQUIRED_PROTOCOL_VERSION = "v2"
REQUIRED_CIPHERS = ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
REQUIRED_MACS = ["hmac-sha2-512", "hmac-sha2-256"]
REQUIRED_KEY_EXCHANGE = ["ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256"]


def load_test_data(file_path):
    """Load test data from JSON or YAML file (Native Juniper format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Juniper native JSON format
    # Expected structure: {"configuration": {...}}
    if isinstance(data, dict) and 'configuration' in data:
        # Extract hostname if available
        hostname = data.get('configuration', {}).get('system', {}).get('host-name', 'unknown-device')
        return {hostname: data}
    
    # If data is already wrapped with device names
    return data


def test_ssh_fips_cryptographic_mechanisms():
    """
    Test that SSH uses only FIPS 140-2 approved cryptographic mechanisms.
    
    STIG JUSX-DM-000150 (CAT I) requires that SSH be configured with strong 
    cryptographic mechanisms to protect the confidentiality of remote maintenance 
    and diagnostic communications.
    
    This test validates:
    1. Protocol version is v2 (SSHv1 has vulnerabilities)
    2. Ciphers include approved AES-CTR algorithms
    3. MACs include approved HMAC-SHA2 algorithms
    4. Key exchange includes approved ECDH algorithms
    
    These mechanisms ensure:
    - Strong encryption protecting credentials and configuration data
    - Message integrity preventing tampering
    - Forward secrecy protecting past sessions
    - FIPS 140-2 compliance for DoD environments
    
    CAT I Severity: Weak cryptography can lead to complete device compromise 
    through credential interception and configuration manipulation.
    
    Native extraction method: Tests against native Juniper CLI/API JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('configuration', {})
            
            # Initialize compliance tracking
            protocol_version_compliant = False
            ciphers_compliant = False
            macs_compliant = False
            key_exchange_compliant = False
            
            protocol_version = None
            configured_ciphers = []
            configured_macs = []
            configured_key_exchange = []
            
            missing_ciphers = []
            missing_macs = []
            missing_key_exchange = []
            
            # Check SSH configuration
            # Path: configuration.system.services.ssh
            system_config = config.get('system', {})
            services_config = system_config.get('services', {})
            ssh_config = services_config.get('ssh', {})
            
            if not ssh_config:
                results[device_name] = {
                    'error': 'SSH configuration not found',
                    'compliant': False
                }
                continue
            
            # Check protocol version
            if 'protocol-version' in ssh_config:
                protocol_version_value = ssh_config.get('protocol-version')
                # Handle both string and array formats
                if isinstance(protocol_version_value, list):
                    protocol_version = protocol_version_value[0] if protocol_version_value else None
                else:
                    protocol_version = protocol_version_value
                
                if protocol_version == REQUIRED_PROTOCOL_VERSION:
                    protocol_version_compliant = True
            
            # Check ciphers
            if 'ciphers' in ssh_config:
                ciphers_list = ssh_config.get('ciphers', [])
                if isinstance(ciphers_list, list):
                    configured_ciphers = ciphers_list
                else:
                    configured_ciphers = [ciphers_list] if ciphers_list else []
                
                # Check if all required ciphers are present
                missing_ciphers = [c for c in REQUIRED_CIPHERS if c not in configured_ciphers]
                if len(missing_ciphers) == 0:
                    ciphers_compliant = True
            else:
                missing_ciphers = REQUIRED_CIPHERS
            
            # Check MACs (already validated in JUSX-DM-000124, checking again for completeness)
            if 'macs' in ssh_config:
                macs_list = ssh_config.get('macs', [])
                if isinstance(macs_list, list):
                    configured_macs = macs_list
                else:
                    configured_macs = [macs_list] if macs_list else []
                
                # Check if required MACs are present (at least the approved ones)
                missing_macs = [m for m in REQUIRED_MACS if m not in configured_macs]
                if len(missing_macs) == 0:
                    macs_compliant = True
            else:
                missing_macs = REQUIRED_MACS
            
            # Check key exchange algorithms
            if 'key-exchange' in ssh_config:
                kex_list = ssh_config.get('key-exchange', [])
                if isinstance(kex_list, list):
                    configured_key_exchange = kex_list
                else:
                    configured_key_exchange = [kex_list] if kex_list else []
                
                # Check if all required key exchange algorithms are present
                missing_key_exchange = [k for k in REQUIRED_KEY_EXCHANGE if k not in configured_key_exchange]
                if len(missing_key_exchange) == 0:
                    key_exchange_compliant = True
            else:
                missing_key_exchange = REQUIRED_KEY_EXCHANGE
            
            # Overall compliance requires all four components
            overall_compliant = (
                protocol_version_compliant and
                ciphers_compliant and
                macs_compliant and
                key_exchange_compliant
            )
            
            results[device_name] = {
                'protocol_version': protocol_version,
                'protocol_version_compliant': protocol_version_compliant,
                'configured_ciphers': configured_ciphers,
                'ciphers_compliant': ciphers_compliant,
                'missing_ciphers': missing_ciphers,
                'configured_macs': configured_macs,
                'macs_compliant': macs_compliant,
                'missing_macs': missing_macs,
                'configured_key_exchange': configured_key_exchange,
                'key_exchange_compliant': key_exchange_compliant,
                'missing_key_exchange': missing_key_exchange,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append(f"Severity: {SEVERITY} (HIGH - Critical Security Vulnerability)")
                
                # Protocol version
                if not protocol_version_compliant:
                    error_parts.append(f"\n  ✗ Protocol Version: {protocol_version or 'NOT CONFIGURED'}")
                    error_parts.append(f"    Required: {REQUIRED_PROTOCOL_VERSION}")
                    error_parts.append("    Risk: SSHv1 has known cryptographic vulnerabilities")
                else:
                    error_parts.append(f"  ✓ Protocol Version: {protocol_version}")
                
                # Ciphers
                if not ciphers_compliant:
                    error_parts.append(f"\n  ✗ Ciphers: Missing {len(missing_ciphers)} required algorithm(s)")
                    error_parts.append(f"    Configured: {', '.join(configured_ciphers) if configured_ciphers else 'NONE'}")
                    error_parts.append(f"    Missing: {', '.join(missing_ciphers)}")
                    error_parts.append("    Risk: Weak ciphers expose encrypted data to decryption")
                else:
                    error_parts.append(f"  ✓ Ciphers: {len(configured_ciphers)} approved algorithms configured")
                
                # MACs
                if not macs_compliant:
                    error_parts.append(f"\n  ✗ MACs: Missing {len(missing_macs)} required algorithm(s)")
                    error_parts.append(f"    Configured: {', '.join(configured_macs) if configured_macs else 'NONE'}")
                    error_parts.append(f"    Missing: {', '.join(missing_macs)}")
                    error_parts.append("    Risk: Weak MACs allow session tampering and injection")
                else:
                    error_parts.append(f"  ✓ MACs: {len(configured_macs)} approved algorithms configured")
                
                # Key Exchange
                if not key_exchange_compliant:
                    error_parts.append(f"\n  ✗ Key Exchange: Missing {len(missing_key_exchange)} required algorithm(s)")
                    error_parts.append(f"    Configured: {', '.join(configured_key_exchange) if configured_key_exchange else 'NONE'}")
                    error_parts.append(f"    Missing: {', '.join(missing_key_exchange)}")
                    error_parts.append("    Risk: Weak key exchange compromises forward secrecy")
                else:
                    error_parts.append(f"  ✓ Key Exchange: {len(configured_key_exchange)} approved algorithms configured")
                
                error_parts.append("\n" + "="*70)
                error_parts.append("CRITICAL FINDING (CAT I)")
                error_parts.append("="*70)
                error_parts.append("\nSecurity Impact:")
                error_parts.append("  - Administrative credentials vulnerable to interception")
                error_parts.append("  - Configuration commands can be captured and decrypted")
                error_parts.append("  - Man-in-the-middle attacks possible")
                error_parts.append("  - Complete device compromise risk")
                error_parts.append("  - Lateral movement to other devices")
                error_parts.append("  - FIPS 140-2 compliance violation")
                error_parts.append("\nRequired FIPS 140-2 Approved Algorithms:")
                error_parts.append("  Protocol: v2 (SSHv1 prohibited)")
                error_parts.append("  Ciphers: aes256-ctr, aes192-ctr, aes128-ctr")
                error_parts.append("  MACs: hmac-sha2-512, hmac-sha2-256")
                error_parts.append("  Key Exchange: ecdh-sha2-nistp521, ecdh-sha2-nistp384, ecdh-sha2-nistp256")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system services ssh protocol-version v2")
                error_parts.append("  set system services ssh ciphers aes256-ctr")
                error_parts.append("  set system services ssh ciphers aes192-ctr")
                error_parts.append("  set system services ssh ciphers aes128-ctr")
                error_parts.append("  set system services ssh macs hmac-sha2-512")
                error_parts.append("  set system services ssh macs hmac-sha2-256")
                error_parts.append("  set system services ssh key-exchange ecdh-sha2-nistp521")
                error_parts.append("  set system services ssh key-exchange ecdh-sha2-nistp384")
                error_parts.append("  set system services ssh key-exchange ecdh-sha2-nistp256")
                error_parts.append("  commit")
                error_parts.append("\nVerification:")
                error_parts.append("  show system services ssh")
                error_parts.append("  show configuration system services ssh | display set")
                error_parts.append("\nIMPORTANT: This is a CAT I finding requiring immediate remediation.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking SSH cryptographic mechanisms on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY} (HIGH)")
    print(f"Title: SSH FIPS 140-2 approved cryptographic mechanisms")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Protocol Version: {result.get('protocol_version')}")
            print(f"  Ciphers: {len(result.get('configured_ciphers', []))} approved")
            print(f"  MACs: {len(result.get('configured_macs', []))} approved")
            print(f"  Key Exchange: {len(result.get('configured_key_exchange', []))} approved")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: FIPS 140-2 cryptography enforced for SSH")
        else:
            if 'error' not in result:
                print(f"  Protocol Version: {'✓' if result.get('protocol_version_compliant') else '✗'}")
                print(f"  Ciphers: {'✓' if result.get('ciphers_compliant') else '✗'}")
                print(f"  MACs: {'✓' if result.get('macs_compliant') else '✗'}")
                print(f"  Key Exchange: {'✓' if result.get('key_exchange_compliant') else '✗'}")


if __name__ == "__main__":
    test_ssh_fips_cryptographic_mechanisms()
