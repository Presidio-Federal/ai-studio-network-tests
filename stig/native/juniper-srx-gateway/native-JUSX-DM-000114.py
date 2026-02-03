"""
STIG ID: JUSX-DM-000114
Finding ID: V-223214
Rule ID: SV-223214r1043177_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000142-NDM-000245

Rule Title: The Juniper SRX Services Gateway must ensure TCP forwarding is disabled 
            for SSH to prevent unauthorized access.

Discussion:
Use this configuration option to prevent a user from creating an SSH tunnel over a 
CLI session to the Juniper SRX via SSH. This type of tunnel could be used to forward 
TCP traffic, bypassing any firewall filters or ACLs, allowing unauthorized access.

SSH tunneling (also known as SSH port forwarding) allows users to create encrypted 
tunnels through SSH connections. While this can be legitimate in some contexts, on 
network security devices it can be exploited to bypass security controls by:
- Forwarding traffic around firewall rules
- Creating covert channels for data exfiltration
- Bypassing network access controls
- Tunneling prohibited protocols through the SSH connection

Disabling TCP forwarding prevents these types of unauthorized tunnels.

Check Text:
Use the CLI to view this setting for disabled for SSH.

[edit]
show system services ssh

If TCP forwarding is not disabled for the root user, this is a finding.

Fix Text:
From the configuration mode, enter the following commands to disable TCP forwarding 
for the SSH protocol.

[edit]
set system services ssh no-tcp-forwarding

References:
CCI: CCI-000382: Configure the system to prohibit or restrict the use of 
                 organization-defined prohibited or restricted functions, system 
                 ports, protocols, software, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53 Revision 4 :: CM-7 b
NIST SP 800-53 Revision 5 :: CM-7 b
NIST SP 800-53A :: CM-7.1 (iii)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223214
Rule ID: SV-223214r1043177_rule
STIG ID: JUSX-DM-000114
Severity: CAT II
Classification: Unclass
Legacy IDs: V-66509; SV-80999
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000114"
FINDING_ID = "V-223214"
RULE_ID = "SV-223214r1043177_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"


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


def test_ssh_no_tcp_forwarding():
    """
    Test that TCP forwarding is disabled for SSH to prevent unauthorized tunneling.
    
    STIG JUSX-DM-000114 requires that the Juniper SRX Services Gateway disable TCP 
    forwarding for SSH to prevent users from creating SSH tunnels that could bypass 
    firewall filters and ACLs.
    
    This test validates:
    1. SSH no-tcp-forwarding is configured
    
    SSH tunneling can be exploited to:
    - Bypass firewall rules
    - Create covert data exfiltration channels
    - Circumvent network access controls
    - Forward prohibited protocols
    
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
            
            tcp_forwarding_disabled = False
            
            # Check SSH configuration
            # Path: configuration.system.services.ssh.no-tcp-forwarding
            system_config = config.get('system', {})
            services_config = system_config.get('services', {})
            ssh_config = services_config.get('ssh', {})
            
            # In Juniper JSON, configuration flags like "no-tcp-forwarding" 
            # are represented as keys with null value or empty list
            if ssh_config:
                # Check if no-tcp-forwarding is present
                # It can be: "no-tcp-forwarding": [null] or "no-tcp-forwarding": null
                if 'no-tcp-forwarding' in ssh_config:
                    tcp_forwarding_disabled = True
            
            # Compliant if TCP forwarding is explicitly disabled
            overall_compliant = tcp_forwarding_disabled
            
            results[device_name] = {
                'tcp_forwarding_disabled': tcp_forwarding_disabled,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append("  SSH TCP forwarding is NOT disabled")
                error_parts.append("\nFinding:")
                error_parts.append("  Without disabling TCP forwarding, users can create SSH tunnels")
                error_parts.append("  that bypass firewall filters and access control lists.")
                error_parts.append("\nSecurity Risk:")
                error_parts.append("  SSH tunneling can be exploited to:")
                error_parts.append("    - Bypass firewall security policies")
                error_parts.append("    - Create covert channels for data exfiltration")
                error_parts.append("    - Circumvent network access controls")
                error_parts.append("    - Forward prohibited protocols through the SSH connection")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system services ssh no-tcp-forwarding")
                error_parts.append("  commit")
                error_parts.append("\nNote:")
                error_parts.append("  This setting prevents both local and remote port forwarding")
                error_parts.append("  and is critical for maintaining firewall security integrity.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking SSH TCP forwarding on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: SSH TCP forwarding disabled")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  SSH TCP forwarding: Disabled")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: SSH tunneling prevention enabled")
        else:
            if 'error' not in result:
                print(f"  TCP forwarding disabled: {'Yes' if result.get('tcp_forwarding_disabled') else 'No'}")
                print(f"  Required: no-tcp-forwarding must be configured")


if __name__ == "__main__":
    test_ssh_no_tcp_forwarding()
