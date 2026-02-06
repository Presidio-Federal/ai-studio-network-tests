"""
STIG ID: ARST-ND-000110
Finding ID: V-255948
Rule ID: SV-255948r991781_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista Multilayer Switch must be configured to enforce approved authorizations 
for controlling the flow of management information within the device based on control policies.

Discussion:
A mechanism to detect and prevent unauthorized communication flow must be configured or provided 
as part of the system design. If information flow is not enforced based on approved authorizations, 
the system may become compromised. Information flow control regulates where information is allowed 
to travel within a network.

The flow of all network traffic must be monitored and controlled so it does not introduce any 
unacceptable risk to the network infrastructure or data. Management traffic (e.g., device 
configuration, software updates) must be separated from operational traffic to protect the 
management plane from attacks.

For Arista switches, this is accomplished by:
1. Defining access control lists (ACLs) that permit only authorized management networks
2. Applying these ACLs to management services such as SSH
3. Denying all other traffic to management interfaces

This ensures that only authorized administrators from approved networks can access the device 
management plane, providing logical separation of maintenance sessions from other network traffic.

Check Text:
Verify the Arista network device is configured with access control lists to control the flow 
of management information.

Step 1: Verify SSH has an inbound ACL applied.

management ssh
  ip access-group MGMT_NETWORK in

Step 2: Verify the ACL permits only hosts from the management network to access the device.

ip access-list MGMT_NETWORK
  10 permit ip 10.1.12.0/24 any
  20 deny ip any any log

If the Arista network device is not configured to enforce approved authorizations for controlling 
the flow of management information within the device based on control policies, this is a finding.

Fix Text:
Step 1: Configure an ACL for SSH access using the following commands:

switch(config)# ip access-list MGMT_NETWORK
switch(config-acl-MGMT_NETWORK)# 10 permit ip 10.1.12.0/24 any
switch(config-acl-MGMT_NETWORK)# 20 deny ip any any log
switch(config-acl-MGMT_NETWORK)# exit

Step 2: Apply the ACL to management ssh.

switch(config)# management ssh 
switch(config-mgmt-ssh)# ip access-group MGMT_NETWORK in
switch(config-mgmt-ssh)# exit

References:
CCI: CCI-001368
NIST SP 800-53 :: AC-4
NIST SP 800-53 Revision 4 :: AC-4
NIST SP 800-53 Revision 5 :: AC-4
NIST SP 800-53A :: AC-4.1 (iii)

CCI: CCI-004192
NIST SP 800-53 Revision 5 :: MA-4 (4) (b) (2)
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000110"
FINDING_ID = "V-255948"
RULE_ID = "SV-255948r991781_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must enforce authorizations for controlling management information flow"

# Requirements for compliance
ACL_REQUIRED = True


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native Arista eAPI format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Arista eAPI JSON-RPC response format
    # Expected structure: {"jsonrpc": "2.0", "result": [{"cmds": {...}}]}
    if isinstance(data, dict) and 'result' in data:
        result = data.get('result', [])
        if result and len(result) > 0:
            config = result[0].get('cmds', {})
            # Extract hostname from config if available
            device_name = 'unknown-device'
            for cmd_key in config.keys():
                if cmd_key.startswith('hostname '):
                    device_name = cmd_key.replace('hostname ', '').strip()
                    break
            return {device_name: {'config': config}}
    
    # Direct format (already extracted cmds)
    if isinstance(data, dict) and 'cmds' in data:
        device_name = 'unknown-device'
        for cmd_key in data['cmds'].keys():
            if cmd_key.startswith('hostname '):
                device_name = cmd_key.replace('hostname ', '').strip()
                break
        return {device_name: {'config': data['cmds']}}
    
    return data


def test_management_acl_configured():
    """
    Test that management SSH has an ACL applied to control information flow.
    
    STIG V-255948 (ARST-ND-000110) requires that the Arista switch enforces approved 
    authorizations for controlling the flow of management information. This ensures:
    - Management traffic is separated from operational traffic
    - Only authorized networks can access the management plane
    - Information flow is controlled based on approved policies
    - Protection against unauthorized management access
    - Logical separation of maintenance sessions
    
    The test validates that:
    1. Management SSH is configured
    2. An ACL is applied to management SSH (inbound direction)
    3. The referenced ACL exists in the configuration
    4. Organizations should verify the ACL permits only authorized management networks
    
    This implements:
    - AC-4: Information flow enforcement
    - MA-4(4): Logically separated maintenance sessions
    
    Native extraction method: Tests against Arista eAPI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('config', {})
            
            # Initialize compliance flags
            management_ssh_configured = False
            acl_applied = False
            acl_name = None
            acl_exists = False
            acl_has_permit = False
            acl_has_deny = False
            acl_entries = []
            
            # Step 1: Check for management ssh with ACL
            # Arista format: "management ssh": {"cmds": {"ip access-group NAME in": null}}
            management_ssh = config.get('management ssh', {})
            
            if management_ssh:
                management_ssh_configured = True
                
                # Get the cmds section within management ssh
                ssh_cmds = management_ssh.get('cmds', {})
                
                # Look for ip access-group command
                # Format: "ip access-group MGMT_NETWORK in": null
                for cmd_key in ssh_cmds.keys():
                    if cmd_key.startswith('ip access-group ') and cmd_key.endswith(' in'):
                        acl_applied = True
                        # Extract ACL name (between "ip access-group " and " in")
                        acl_name = cmd_key.replace('ip access-group ', '').replace(' in', '').strip()
                        break
            
            # Step 2: Check if the referenced ACL exists and has proper rules
            if acl_name:
                # Look for the ACL definition
                # Format: "ip access-list MGMT_NETWORK": {"cmds": {...}}
                acl_key = f'ip access-list {acl_name}'
                acl_config = config.get(acl_key, {})
                
                if acl_config:
                    acl_exists = True
                    
                    # Get ACL entries
                    acl_cmds = acl_config.get('cmds', {})
                    
                    # Check for permit and deny entries
                    for entry_key in acl_cmds.keys():
                        acl_entries.append(entry_key)
                        if 'permit' in entry_key.lower():
                            acl_has_permit = True
                        if 'deny' in entry_key.lower():
                            acl_has_deny = True
            
            # Overall compliance
            # Must have: management SSH configured, ACL applied, ACL exists
            # Should have: at least one permit and one deny rule (best practice)
            overall_compliant = (
                management_ssh_configured and 
                acl_applied and 
                acl_exists and
                acl_has_permit and
                acl_has_deny
            )
            
            results[device_name] = {
                'management_ssh_configured': management_ssh_configured,
                'acl_applied': acl_applied,
                'acl_name': acl_name,
                'acl_exists': acl_exists,
                'acl_has_permit': acl_has_permit,
                'acl_has_deny': acl_has_deny,
                'acl_entries': acl_entries,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not management_ssh_configured:
                    error_parts.append("  ✗ Management SSH is NOT configured")
                elif not acl_applied:
                    error_parts.append("  ✗ No ACL applied to management SSH")
                elif not acl_exists:
                    error_parts.append(f"  ✗ ACL '{acl_name}' is referenced but NOT defined")
                elif not acl_has_permit:
                    error_parts.append(f"  ✗ ACL '{acl_name}' has no permit rules")
                elif not acl_has_deny:
                    error_parts.append(f"  ✗ ACL '{acl_name}' has no deny rules (implicit deny not visible)")
                
                if acl_entries:
                    error_parts.append(f"\n  Current ACL '{acl_name}' entries:")
                    for entry in acl_entries:
                        error_parts.append(f"    - {entry}")
                
                error_parts.append("\nManagement information flow control is NOT properly configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("\nStep 1: Configure an ACL for SSH access:")
                error_parts.append("  switch(config)# ip access-list MGMT_NETWORK")
                error_parts.append("  switch(config-acl-MGMT_NETWORK)# 10 permit ip 10.1.12.0/24 any")
                error_parts.append("  switch(config-acl-MGMT_NETWORK)# 20 deny ip any any log")
                error_parts.append("  switch(config-acl-MGMT_NETWORK)# exit")
                error_parts.append("\nStep 2: Apply the ACL to management SSH:")
                error_parts.append("  switch(config)# management ssh")
                error_parts.append("  switch(config-mgmt-ssh)# ip access-group MGMT_NETWORK in")
                error_parts.append("  switch(config-mgmt-ssh)# exit")
                error_parts.append("\nBest practices:")
                error_parts.append("  - Permit only authorized management networks/hosts")
                error_parts.append("  - Deny all other traffic with logging")
                error_parts.append("  - Use specific IP ranges, not 'any'")
                error_parts.append("  - Review and update ACLs regularly")
                error_parts.append("\nWithout management ACLs:")
                error_parts.append("  - Unauthorized networks can access management plane")
                error_parts.append("  - Management traffic is not separated from user traffic")
                error_parts.append("  - Information flow is not controlled")
                error_parts.append("  - Maintenance sessions are not logically separated")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking management ACL configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Management SSH configured")
            print(f"  ✓ ACL applied: {result['acl_name']}")
            print(f"  ✓ ACL exists and is properly defined")
            print(f"  ✓ ACL has permit rules: {result['acl_has_permit']}")
            print(f"  ✓ ACL has deny rules: {result['acl_has_deny']}")
            if result.get('acl_entries'):
                print(f"  ✓ ACL entries configured:")
                for entry in result['acl_entries']:
                    print(f"    - {entry}")
            print(f"  ✓ Management information flow control enforced")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Management SSH configured: {'✓' if result.get('management_ssh_configured') else '✗'}")
                print(f"  ACL applied: {'✓' if result.get('acl_applied') else '✗'}")
                if result.get('acl_name'):
                    print(f"  ACL name: {result['acl_name']}")
                    print(f"  ACL exists: {'✓' if result.get('acl_exists') else '✗'}")
                    if result.get('acl_entries'):
                        print(f"  ACL entries:")
                        for entry in result['acl_entries']:
                            print(f"    - {entry}")


if __name__ == "__main__":
    test_management_acl_configured()
