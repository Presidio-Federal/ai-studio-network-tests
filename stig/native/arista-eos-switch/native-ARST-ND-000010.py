"""
STIG ID: ARST-ND-000010
Finding ID: V-255947
Rule ID: SV-255947r960735_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista Multilayer Switch must limit the number of concurrent sessions to an 
organization-defined number for each administrator account and/or administrator account type.

Discussion:
Network devices management includes the ability to control the number of administrators and 
management sessions that manage a device. Limiting the number of allowed administrators and 
sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address 
concurrent sessions by a single administrator via multiple administrative accounts. The maximum 
number of concurrent sessions should be defined based upon mission needs and the operational 
environment for each system. Management sessions are administrator sessions established for 
administrative purposes (e.g., configuring the device). Administrator sessions for the purposes 
of managing the device must be audited.

For Arista switches, the management ssh connection limit command restricts the total number of 
concurrent SSH sessions that can be established to the device. This helps prevent resource 
exhaustion and ensures that administrative access is controlled and limited to authorized 
personnel only.

Check Text:
Review the switch configuration to verify that it limits the number of concurrent management 
sessions.

management ssh
  connection limit 5

If the switch does not limit the number of concurrent management sessions to an organization-defined 
number, this is a finding.

Note: The connection limit value should be based on organization-defined requirements. The example 
shows a limit of 5, but organizations may define different limits based on their operational needs.

Fix Text:
Configure the switch to limit SSH concurrent connections to the device with the following commands:

switch# configure
switch(config)# management ssh
switch(config-mgmt-ssh)# connection limit 5
switch(config-mgmt-ssh)# exit
switch# wr
!

References:
CCI: CCI-000054
NIST SP 800-53 :: AC-10
NIST SP 800-53 Revision 4 :: AC-10
NIST SP 800-53 Revision 5 :: AC-10
NIST SP 800-53A :: AC-10.1 (ii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000010"
FINDING_ID = "V-255947"
RULE_ID = "SV-255947r960735_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must limit concurrent sessions per administrator account"

# Minimum requirement: Connection limit must be configured
# Organizations should define appropriate limits based on operational needs
# Typical values range from 2-10 concurrent sessions
MIN_CONNECTION_LIMIT_REQUIRED = True


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


def test_ssh_connection_limit():
    """
    Test that management SSH connection limit is configured.
    
    STIG V-255947 (ARST-ND-000010) requires that the Arista switch limits the number of 
    concurrent management sessions to an organization-defined number. This ensures:
    - Prevention of resource exhaustion from excessive sessions
    - Controlled administrative access
    - Protection against DoS attacks targeting management plane
    - Compliance with AC-10 access control requirements
    
    The test validates that:
    1. Management SSH is configured
    2. Connection limit is explicitly set
    3. Organizations should verify the limit value meets their requirements
    
    Typical connection limit values:
    - Small environments: 2-5 concurrent sessions
    - Medium environments: 5-10 concurrent sessions
    - Large environments: 10-20 concurrent sessions
    
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
            connection_limit_configured = False
            connection_limit_value = None
            
            # Check for management ssh configuration
            # Arista format: "management ssh": {"cmds": {...}}
            management_ssh = config.get('management ssh', {})
            
            if management_ssh:
                management_ssh_configured = True
                
                # Get the cmds section within management ssh
                ssh_cmds = management_ssh.get('cmds', {})
                
                # Look for connection limit command
                # Format: "connection limit 5": null
                for cmd_key in ssh_cmds.keys():
                    if cmd_key.startswith('connection limit '):
                        connection_limit_configured = True
                        # Extract the numeric value
                        try:
                            limit_str = cmd_key.replace('connection limit ', '').strip()
                            connection_limit_value = int(limit_str)
                        except (ValueError, AttributeError):
                            connection_limit_value = None
                        break
            
            # Overall compliance - connection limit must be configured
            overall_compliant = management_ssh_configured and connection_limit_configured
            
            results[device_name] = {
                'management_ssh_configured': management_ssh_configured,
                'connection_limit_configured': connection_limit_configured,
                'connection_limit_value': connection_limit_value,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not management_ssh_configured:
                    error_parts.append("  ✗ Management SSH is NOT configured")
                elif not connection_limit_configured:
                    error_parts.append("  ✗ SSH connection limit is NOT configured")
                
                error_parts.append("\nConcurrent session limit is NOT configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  switch# configure")
                error_parts.append("  switch(config)# management ssh")
                error_parts.append("  switch(config-mgmt-ssh)# connection limit 5")
                error_parts.append("  switch(config-mgmt-ssh)# exit")
                error_parts.append("  switch# wr")
                error_parts.append("\nRecommended connection limit values:")
                error_parts.append("  - Small environments: 2-5 concurrent sessions")
                error_parts.append("  - Medium environments: 5-10 concurrent sessions")
                error_parts.append("  - Large environments: 10-20 concurrent sessions")
                error_parts.append("\nNote: Configure the limit based on organization-defined")
                error_parts.append("      operational requirements and administrator needs.")
                error_parts.append("\nWithout concurrent session limits:")
                error_parts.append("  - Resource exhaustion attacks may succeed")
                error_parts.append("  - Excessive sessions can degrade device performance")
                error_parts.append("  - Administrative access control is weakened")
                error_parts.append("  - DoS vulnerabilities in management plane")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking SSH connection limit on {device_name}: {e}"
    
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
            print(f"  ✓ Connection limit configured: {result['connection_limit_value']}")
            print(f"  ✓ Concurrent session limit requirement satisfied")
            if result['connection_limit_value']:
                if result['connection_limit_value'] < 2:
                    print(f"  ⚠ Warning: Limit of {result['connection_limit_value']} may be too restrictive")
                elif result['connection_limit_value'] > 20:
                    print(f"  ⚠ Warning: Limit of {result['connection_limit_value']} may be too permissive")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Management SSH configured: {'✓' if result.get('management_ssh_configured') else '✗'}")
                print(f"  Connection limit configured: {'✓' if result.get('connection_limit_configured') else '✗'}")
                if result.get('connection_limit_value') is not None:
                    print(f"  Connection limit value: {result['connection_limit_value']}")


if __name__ == "__main__":
    test_ssh_connection_limit()
