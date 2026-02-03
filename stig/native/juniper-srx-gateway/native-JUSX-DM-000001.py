"""
STIG ID: JUSX-DM-000001
Finding ID: V-223180
Rule ID: SV-223180r960735_rule
Version: 3, Release: 3
Severity: CAT III (Low)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000001-NDM-000200

Rule Title: The Juniper SRX Services Gateway must limit the number of concurrent 
            sessions to a maximum of 10 or less for remote access using SSH.

Discussion:
The connection-limit command limits the total number of concurrent SSH sessions. 
To help thwart brute force authentication attacks, the connection limit should be 
as restrictive as operationally practical.

Juniper Networks recommends the best practice of setting 10 (or less) for the 
connection-limit.

This configuration will permit up to 10 users to log in to the device simultaneously, 
but an attempt to log an 11th user into the device will fail. The attempt will remain 
in a waiting state until a session is terminated and made available.

Check Text:
Verify the Juniper SRX sets a connection-limit for the SSH protocol.

show system services ssh

If the SSH connection-limit is not set to 10 or less, this is a finding.

Fix Text:
Configure the SSH protocol to limit connection and sessions per connection.

[edit]
set system services ssh connection-limit 10
set system services ssh max-sessions-per-connection 1

References:
CCI: CCI-000054: Limit the number of concurrent sessions for each organization-defined 
                 account and/or account type to an organization-defined number.
NIST SP 800-53 :: AC-10
NIST SP 800-53 Revision 4 :: AC-10
NIST SP 800-53 Revision 5 :: AC-10
NIST SP 800-53A :: AC-10.1 (ii)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223180
Rule ID: SV-223180r960735_rule
STIG ID: JUSX-DM-000001
Severity: CAT III
Classification: Unclass
Legacy IDs: V-66549; SV-81039
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000001"
FINDING_ID = "V-223180"
RULE_ID = "SV-223180r960735_rule"
SEVERITY = "CAT III"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Juniper Networks best practice
MAX_SSH_CONNECTION_LIMIT = 10


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


def test_ssh_connection_limit():
    """
    Test that SSH connection limit is set to 10 or less.
    
    STIG JUSX-DM-000001 requires that the Juniper SRX Services Gateway limit 
    concurrent SSH sessions to a maximum of 10 to help prevent brute-force attacks.
    
    This test validates:
    1. SSH connection-limit is configured
    2. Connection limit is set to 10 or less
    
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
            
            connection_limit_configured = False
            connection_limit = None
            max_sessions_per_connection = None
            
            # Check SSH configuration
            # Path: configuration.system.services.ssh
            system_config = config.get('system', {})
            services_config = system_config.get('services', {})
            ssh_config = services_config.get('ssh', {})
            
            if ssh_config:
                if 'connection-limit' in ssh_config:
                    connection_limit_configured = True
                    connection_limit = ssh_config.get('connection-limit')
                
                if 'max-sessions-per-connection' in ssh_config:
                    max_sessions_per_connection = ssh_config.get('max-sessions-per-connection')
            
            # Determine compliance
            # Connection limit must be configured AND be <= 10
            overall_compliant = (
                connection_limit_configured and 
                connection_limit is not None and 
                connection_limit <= MAX_SSH_CONNECTION_LIMIT
            )
            
            results[device_name] = {
                'connection_limit_configured': connection_limit_configured,
                'connection_limit': connection_limit,
                'max_sessions_per_connection': max_sessions_per_connection,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not connection_limit_configured:
                    error_parts.append("  SSH connection-limit is NOT configured")
                elif connection_limit is None:
                    error_parts.append("  SSH connection-limit value is None/missing")
                elif connection_limit > MAX_SSH_CONNECTION_LIMIT:
                    error_parts.append(f"  SSH connection-limit is {connection_limit} (exceeds maximum of {MAX_SSH_CONNECTION_LIMIT})")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without proper SSH connection limits, the device is vulnerable")
                error_parts.append("  to brute-force authentication attacks.")
                error_parts.append("\nRisk:")
                error_parts.append("  Unlimited or excessive SSH connections can be exploited by")
                error_parts.append("  attackers attempting to gain unauthorized access.")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append(f"  set system services ssh connection-limit {MAX_SSH_CONNECTION_LIMIT}")
                error_parts.append("  set system services ssh max-sessions-per-connection 1")
                error_parts.append("\nJuniper Networks Best Practice:")
                error_parts.append(f"  SSH connection-limit should be set to {MAX_SSH_CONNECTION_LIMIT} or less")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking SSH connection limit on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: SSH connection limit for remote access")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  SSH connection-limit: {result.get('connection_limit')}")
            if result.get('max_sessions_per_connection') is not None:
                print(f"  Max sessions per connection: {result.get('max_sessions_per_connection')}")
            print(f"  Juniper Best Practice: <= {MAX_SSH_CONNECTION_LIMIT}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
        else:
            if 'error' not in result:
                print(f"  Connection-limit configured: {'Yes' if result.get('connection_limit_configured') else 'No'}")
                if result.get('connection_limit') is not None:
                    print(f"  Current limit: {result.get('connection_limit')}")
                print(f"  Required: <= {MAX_SSH_CONNECTION_LIMIT}")


if __name__ == "__main__":
    test_ssh_connection_limit()
