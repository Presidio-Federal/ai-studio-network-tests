"""
STIG ID: JUSX-DM-000124
Finding ID: V-223216
Rule ID: SV-223216r960993_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000156-NDM-000250

Rule Title: The Juniper SRX Services Gateway must implement replay-resistant 
            authentication mechanisms for network access to privileged accounts.

Discussion:
A replay attack may enable an unauthorized user to gain access to the application. 
Authentication sessions between the authenticator and the application validating the 
user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a 
successful authentication by recording and replaying a previous authentication message.

There are 2 approved methods for accessing the Juniper SRX which are, in order of 
preference, the SSH protocol and the console port.

SSH MAC (Message Authentication Code) algorithms provide cryptographic integrity and 
authentication for SSH sessions, preventing replay attacks by ensuring that:
1. Each message is authenticated with a cryptographic hash
2. Messages include sequence numbers to prevent reordering
3. Tampered or replayed messages are detected and rejected

Approved HMAC algorithms include:
- hmac-sha2-512 (preferred, strongest)
- hmac-sha2-256 (preferred, strong)
- hmac-sha1 (acceptable for compatibility)
- hmac-sha1-96 (acceptable for compatibility)

Check Text:
Verify SSH is configured to use a replay-resistant authentication mechanism.

[edit]
show system services ssh

If SSH is not configured to use the MAC authentication protocol, this is a finding.

Fix Text:
Configure SSH to use a replay-resistant authentication mechanism. The following is 
an example stanza.

[edit]
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh macs hmac-sha1
set system services ssh macs hmac-sha1-96

References:
CCI: CCI-001941: Implement replay-resistant authentication mechanisms for access to 
                 privileged accounts and/or non-privileged accounts.
NIST SP 800-53 Revision 4 :: IA-2 (8)
NIST SP 800-53 Revision 5 :: IA-2 (8)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223216
Rule ID: SV-223216r960993_rule
STIG ID: JUSX-DM-000124
Severity: CAT II
Classification: Unclass
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000124"
FINDING_ID = "V-223216"
RULE_ID = "SV-223216r960993_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Approved HMAC algorithms for SSH (in order of preference)
APPROVED_MACS = [
    "hmac-sha2-512",    # Preferred
    "hmac-sha2-256",    # Preferred
    "hmac-sha1",        # Acceptable for compatibility
    "hmac-sha1-96"      # Acceptable for compatibility
]

# Minimum number of MACs that should be configured
MIN_MACS_REQUIRED = 1


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


def test_ssh_mac_algorithms():
    """
    Test that SSH is configured with approved MAC algorithms for replay-resistant authentication.
    
    STIG JUSX-DM-000124 requires that the Juniper SRX Services Gateway implement 
    replay-resistant authentication mechanisms by configuring SSH with approved 
    HMAC (Hash-based Message Authentication Code) algorithms.
    
    This test validates:
    1. SSH MAC algorithms are configured
    2. At least one approved HMAC algorithm is present
    3. All configured MACs are from the approved list
    
    Replay attacks are prevented by MAC algorithms that:
    - Cryptographically authenticate each SSH message
    - Include sequence numbers to detect reordering
    - Detect tampered or replayed messages
    
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
            
            macs_configured = False
            configured_macs = []
            approved_macs_present = []
            unapproved_macs = []
            
            # Check SSH configuration
            # Path: configuration.system.services.ssh.macs
            system_config = config.get('system', {})
            services_config = system_config.get('services', {})
            ssh_config = services_config.get('ssh', {})
            
            if ssh_config and 'macs' in ssh_config:
                macs_configured = True
                mac_list = ssh_config.get('macs', [])
                
                # Ensure it's a list
                if not isinstance(mac_list, list):
                    mac_list = [mac_list]
                
                configured_macs = mac_list
                
                # Check each configured MAC
                for mac in configured_macs:
                    if mac in APPROVED_MACS:
                        approved_macs_present.append(mac)
                    else:
                        unapproved_macs.append(mac)
            
            # Determine compliance
            # Must have MACs configured AND at least one approved MAC
            overall_compliant = (
                macs_configured and 
                len(approved_macs_present) >= MIN_MACS_REQUIRED and
                len(unapproved_macs) == 0
            )
            
            results[device_name] = {
                'macs_configured': macs_configured,
                'configured_macs': configured_macs,
                'approved_macs_present': approved_macs_present,
                'unapproved_macs': unapproved_macs,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not macs_configured:
                    error_parts.append("  SSH MAC algorithms are NOT configured")
                elif len(approved_macs_present) < MIN_MACS_REQUIRED:
                    error_parts.append(f"  No approved MAC algorithms configured (found: {len(approved_macs_present)})")
                    if configured_macs:
                        error_parts.append(f"  Configured MACs: {', '.join(configured_macs)}")
                elif len(unapproved_macs) > 0:
                    error_parts.append(f"  Unapproved MAC algorithms found: {', '.join(unapproved_macs)}")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without approved MAC algorithms, SSH sessions are vulnerable")
                error_parts.append("  to replay attacks where attackers can intercept and replay")
                error_parts.append("  authentication messages to gain unauthorized access.")
                error_parts.append("\nSecurity Risk:")
                error_parts.append("  Replay attacks can allow:")
                error_parts.append("    - Unauthorized authentication using captured credentials")
                error_parts.append("    - Message tampering without detection")
                error_parts.append("    - Session hijacking through replayed messages")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system services ssh macs hmac-sha2-512")
                error_parts.append("  set system services ssh macs hmac-sha2-256")
                error_parts.append("  set system services ssh macs hmac-sha1")
                error_parts.append("  set system services ssh macs hmac-sha1-96")
                error_parts.append("  commit")
                error_parts.append("\nApproved MAC algorithms (in order of preference):")
                for mac in APPROVED_MACS:
                    error_parts.append(f"  - {mac}")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking SSH MAC algorithms on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Replay-resistant authentication mechanisms (SSH MACs)")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  SSH MACs configured: Yes")
            print(f"  Approved MACs: {', '.join(result.get('approved_macs_present', []))}")
            print(f"  Total MACs: {len(result.get('configured_macs', []))}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Replay-resistant authentication enabled")
        else:
            if 'error' not in result:
                print(f"  MACs configured: {'Yes' if result.get('macs_configured') else 'No'}")
                if result.get('configured_macs'):
                    print(f"  Configured: {', '.join(result.get('configured_macs', []))}")
                if result.get('approved_macs_present'):
                    print(f"  Approved: {', '.join(result.get('approved_macs_present', []))}")
                if result.get('unapproved_macs'):
                    print(f"  Unapproved: {', '.join(result.get('unapproved_macs', []))}")


if __name__ == "__main__":
    test_ssh_mac_algorithms()
