"""
STIG ID: CASA-FW-000100
Finding ID: V-239858
Rule ID: SV-239858r819136_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000098-FW-000021
Rule Title: The Cisco ASA must be configured to use TCP when sending log records 
            to the central audit server.

Discussion:
If the default UDP protocol is used for communication between the hosts and devices 
to the Central Log Server, then log records that do not reach the log server are not 
detected as a data loss. The use of TCP to transport log records to the log servers 
improves delivery reliability.

Check Text:
Review the ASA configuration and verify it is configured to use TCP as shown in the 
example below.

logging host NDM_INTERFACE 10.1.22.2 6/1514
logging permit-hostdown

Note: The command "logging permit-hostdown" must also be configured to ensure that 
when either the syslog server is down or the log queue is full, new connections to 
ASA are allowed, to prevent an unintended denial of service. However, log records 
can be lost if the internal queue fills before restoring the connection to the log server.

If the ASA is not configured to use TCP when sending log records to the central audit 
server, this is a finding.

Fix Text:
Configure the ASA to use TCP when sending log records to the syslog server.

ASA(config)# logging host NDM_INTERFACE 10.1.22.2 6/1514
ASA(config)# logging permit-hostdown

References:
CCI: CCI-000366
NIST SP 800-53 :: CM-6 b
NIST SP 800-53 Revision 4 :: CM-6 b
NIST SP 800-53 Revision 5 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000100"
FINDING_ID = "V-239858"
RULE_ID = "SV-239858r819136_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must use TCP when sending log records to central audit server"


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


def test_asa_logging_tcp_and_permit_hostdown():
    """
    Test that ASA uses TCP for syslog and has permit-hostdown configured.
    
    STIG V-239858 (CASA-FW-000100) requires that:
    1. Logging is enabled globally
    2. Logging host is configured with TCP protocol (protocol 6)
    3. Logging permit-hostdown is configured
    
    This ensures reliable log delivery using TCP and prevents denial of service 
    when the syslog server is unreachable.
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
            logging_host_with_tcp = False
            logging_permit_hostdown = False
            tcp_hosts = []
            non_tcp_hosts = []
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify logging permit-hostdown is configured
            logging_permit_hostdown = 'permit-hostdown' in logging_config
            
            # Check 3: Verify logging host with TCP (protocol 6)
            # Host config can be a list or dict
            host_config = logging_config.get('host', [])
            
            # Normalize to list if it's a dict or single item
            if isinstance(host_config, dict):
                host_config = [host_config]
            elif not isinstance(host_config, list):
                host_config = []
            
            for host in host_config:
                if isinstance(host, dict):
                    interface = host.get('interface', 'unknown')
                    # Try both 'ip-address' and 'host' keys for the IP
                    ip_address = host.get('ip-address') or host.get('host', 'unknown')
                    # Protocol can be in 'protocol' or 'tcp' keys
                    protocol = host.get('protocol', host.get('tcp', None))
                    port = host.get('port', None)
                    
                    # Check if TCP (protocol 6) is configured
                    # Protocol 6 = TCP, or if 'tcp' key exists with port info
                    is_tcp = False
                    if protocol == '6' or protocol == 6:
                        is_tcp = True
                    elif 'tcp' in host or (port and '/' in str(port) and str(port).startswith('6/')):
                        is_tcp = True
                    
                    if is_tcp:
                        logging_host_with_tcp = True
                        tcp_hosts.append({
                            'interface': interface,
                            'ip': ip_address,
                            'protocol': '6 (TCP)',
                            'port': port
                        })
                    else:
                        non_tcp_hosts.append({
                            'interface': interface,
                            'ip': ip_address,
                            'protocol': protocol or 'UDP (default)',
                            'port': port
                        })
            
            # Overall compliance - all three must be true
            overall_compliant = (
                logging_enabled and 
                logging_host_with_tcp and 
                logging_permit_hostdown
            )
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'logging_host_with_tcp': logging_host_with_tcp,
                'logging_permit_hostdown': logging_permit_hostdown,
                'tcp_hosts': tcp_hosts,
                'non_tcp_hosts': non_tcp_hosts,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not logging_enabled:
                error_parts.append("- Logging is not enabled")
            
            if not logging_host_with_tcp:
                error_parts.append("- No logging host configured with TCP (protocol 6)")
                if non_tcp_hosts:
                    error_parts.append(f"  Found {len(non_tcp_hosts)} host(s) using non-TCP protocols:")
                    for host in non_tcp_hosts:
                        error_parts.append(f"    {host['interface']} {host['ip']} (protocol: {host['protocol']})")
            
            if not logging_permit_hostdown:
                error_parts.append("- Logging permit-hostdown is not configured")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired configuration:\n"
                    f"  ASA(config)# logging host <interface> <ip-address> 6/<port>\n"
                    f"  ASA(config)# logging permit-hostdown"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking TCP logging configuration on {device_name}: {e}"
    
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
                
                if result.get('logging_host_with_tcp'):
                    tcp_hosts = result.get('tcp_hosts', [])
                    print(f"  ✓ Logging host with TCP configured ({len(tcp_hosts)} host(s))")
                    for host in tcp_hosts:
                        print(f"    {host['interface']} {host['ip']} 6/{host['port']}")
                else:
                    print("  ✗ No logging host with TCP configured")
                
                if result.get('logging_permit_hostdown'):
                    print("  ✓ Logging permit-hostdown is configured")
                else:
                    print("  ✗ Logging permit-hostdown is not configured")
        else:
            # Show config details for passing tests
            tcp_hosts = result.get('tcp_hosts', [])
            print(f"  ✓ Logging enabled")
            print(f"  ✓ TCP logging host(s): {len(tcp_hosts)}")
            for host in tcp_hosts:
                print(f"    {host['interface']} {host['ip']} 6/{host['port']}")
            print(f"  ✓ Permit-hostdown configured")


if __name__ == "__main__":
    test_asa_logging_tcp_and_permit_hostdown()
