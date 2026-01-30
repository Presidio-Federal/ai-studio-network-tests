"""
STIG ID: CASA-FW-000200
Finding ID: V-239862
Rule ID: SV-239862r953982_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000333-FW-000014
Rule Title: The Cisco ASA must be configured to send log data of denied traffic to a 
            central audit server for analysis.

Discussion:
Without the ability to centrally manage the content captured in the traffic log entries, 
identification, troubleshooting, and correlation of suspicious behavior would be difficult 
and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. 
Network components requiring centralized traffic log management must have the ability to 
support centralized management. The content captured in traffic log entries must be 
managed from a central location (necessitating automation). Centralized management of 
traffic log records and logs provides for efficiency in maintenance and management of 
records, as well as the backup and archiving of those records.

Ensure at least one syslog server is configured on the firewall.

Check Text:
Verify that the ASA is configured to send logs to a syslog server. The configuration 
should look similar to the example below.

logging trap notifications
logging host NDM_INTERFACE 10.1.48.10 6/1514

If the ASA is not configured to send log data to the syslog server, this is a finding.

Fix Text:
Configure the ASA to send log messages to the syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10 6/1514
ASA(config)# logging trap notifications

References:
CCI: CCI-001821
NIST SP 800-53 Revision 4 :: CM-1 a 1
NIST SP 800-53 Revision 5 :: CM-1 a 1 (a)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000200"
FINDING_ID = "V-239862"
RULE_ID = "SV-239862r953982_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must send log data to central audit server"


def load_test_data(file_path):
    """Load test data from JSON or YAML file."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle both formats:
    # Format 1: {device_name: {tailf-ncs:config: {...}}} - wrapped
    # Format 2: {tailf-ncs:config: {tailf-ned-cisco-asa:...}} - direct NSO config
    # Format 3: {tailf-ned-cisco-asa:hostname: ..., ...} - unwrapped ASA config
    
    # Check if this is wrapped in tailf-ncs:config
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        # Direct NSO config with tailf-ncs:config wrapper
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: data}
    
    # Check if this is a direct ASA config (has tailf-ned-cisco-asa keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-asa:') for k in data.keys()):
        # Direct ASA config - wrap it
        device_name = data.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_asa_central_syslog_server():
    """
    Test that ASA is configured to send logs to a central syslog server.
    
    STIG V-239862 (CASA-FW-000200) requires that:
    1. Logging is enabled globally
    2. At least one logging host (syslog server) is configured
    3. Logging trap level is configured (to control what gets sent)
    
    This ensures log data is sent to a central audit server for analysis.
    """
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    devices = load_test_data(test_input_file)
    
    # Dictionary to store results
    results = {}
    
    # Check each device configuration
    for device_name, device_data in devices.items():
        try:
            # Get the config section
            device_config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            logging_enabled = False
            logging_host_configured = False
            logging_trap_configured = False
            configured_hosts = []
            trap_level = None
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify at least one logging host is configured
            host_config = logging_config.get('host', [])
            
            # Normalize to list if it's a dict or single item
            if isinstance(host_config, dict):
                host_config = [host_config]
            elif not isinstance(host_config, list):
                host_config = []
            
            if host_config:
                logging_host_configured = True
                for host in host_config:
                    if isinstance(host, dict):
                        interface = host.get('interface', 'unknown')
                        # Try both 'ip-address' and 'host' keys
                        ip_address = host.get('ip-address') or host.get('host', 'unknown')
                        protocol = host.get('protocol', None)
                        port = host.get('port', None)
                        
                        configured_hosts.append({
                            'interface': interface,
                            'ip': ip_address,
                            'protocol': protocol or 'UDP (default)',
                            'port': port
                        })
            
            # Check 3: Verify logging trap level is configured
            trap_config = logging_config.get('trap', None)
            if trap_config is not None:
                logging_trap_configured = True
                # Trap can be a string (level name) or dict with level info
                if isinstance(trap_config, str):
                    trap_level = trap_config
                elif isinstance(trap_config, dict):
                    trap_level = trap_config.get('level', 'configured')
                else:
                    trap_level = 'configured'
            
            # Overall compliance - all three must be true
            overall_compliant = (
                logging_enabled and 
                logging_host_configured and 
                logging_trap_configured
            )
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'logging_host_configured': logging_host_configured,
                'logging_trap_configured': logging_trap_configured,
                'configured_hosts': configured_hosts,
                'trap_level': trap_level,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not logging_enabled:
                error_parts.append("- Logging is not enabled")
            
            if not logging_host_configured:
                error_parts.append("- No logging host (syslog server) configured")
                error_parts.append("  At least one central syslog server is required")
            
            if not logging_trap_configured:
                error_parts.append("- Logging trap level is not configured")
                error_parts.append("  This controls what severity of logs are sent to syslog")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired configuration:\n"
                    f"  ASA(config)# logging enable\n"
                    f"  ASA(config)# logging host <interface> <ip-address> 6/<port>\n"
                    f"  ASA(config)# logging trap notifications"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking central syslog configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                if result.get('logging_enabled'):
                    print("  ✓ Logging is enabled")
                else:
                    print("  ✗ Logging is not enabled")
                
                if result.get('logging_host_configured'):
                    hosts = result.get('configured_hosts', [])
                    print(f"  ✓ Logging host(s) configured: {len(hosts)}")
                    for host in hosts:
                        print(f"    {host['interface']} {host['ip']}")
                else:
                    print("  ✗ No logging host configured")
                
                if result.get('logging_trap_configured'):
                    print(f"  ✓ Logging trap level: {result.get('trap_level', 'unknown')}")
                else:
                    print("  ✗ Logging trap level not configured")
        else:
            # Show config details for passing tests
            hosts = result.get('configured_hosts', [])
            print(f"  ✓ Logging enabled")
            print(f"  ✓ Syslog server(s): {len(hosts)}")
            for host in hosts:
                print(f"    {host['interface']} {host['ip']} (protocol: {host['protocol']})")
            print(f"  ✓ Trap level: {result.get('trap_level', 'unknown')}")


if __name__ == "__main__":
    test_asa_central_syslog_server()
