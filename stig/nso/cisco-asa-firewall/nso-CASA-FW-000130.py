"""
STIG ID: CASA-FW-000130
Finding ID: V-239859
Rule ID: SV-239859r665863_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000131-FW-000025
Rule Title: The Cisco ASA must be configured to disable or remove unnecessary network 
            services and functions that are not used as part of its role in the architecture.

Discussion:
Network devices are capable of providing a wide variety of functions and services. 
Some of these functions and services are installed and enabled by default. The organization 
must determine which functions and services are required to perform the necessary core 
functionality for each component of the firewall. These unnecessary capabilities or 
services are often overlooked and therefore may remain unsecured. They increase the risk 
to the platform by providing additional attack vectors.

Some services are not authorized for combination with the firewall. Examples of these 
services are telnet (never authorized), and others based on the firewall's role.

Check Text:
Features such as telnet should never be enabled, while other features should only be 
enabled if required for operations.

telnet 10.1.22.2 255.255.255.255 INSIDE

Note: The command "http server" actually enables https and is required for ASDM management.

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.

Fix Text:
Disable features that should not be enabled unless required for operations.

ASA(config)# no telnet 10.1.22.2 255.255.255.255 INSIDE

Note: Telnet must always be disabled.

References:
CCI: CCI-000381
NIST SP 800-53 :: CM-7
NIST SP 800-53 Revision 4 :: CM-7 a
NIST SP 800-53 Revision 5 :: CM-7 a
NIST SP 800-53A :: CM-7.1 (ii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000130"
FINDING_ID = "V-239859"
RULE_ID = "SV-239859r665863_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must disable unnecessary network services and functions"


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


def test_asa_no_unnecessary_services():
    """
    Test that ASA has no unnecessary or insecure services enabled.
    
    STIG V-239859 (CASA-FW-000130) requires that:
    1. Telnet must NEVER be enabled (always a finding)
    2. Other unnecessary services should be disabled unless required for documented role
    
    This test focuses on critical security services that should be disabled:
    - Telnet (NEVER authorized - insecure)
    
    Note: HTTP server is allowed as it enables HTTPS for ASDM management.
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
            telnet_disabled = True
            telnet_entries = []
            unauthorized_services = []
            
            # Check 1: Verify Telnet is NOT configured (CRITICAL - never allowed)
            telnet_config = device_config.get('tailf-ned-cisco-asa:telnet', None)
            
            # If telnet key exists at all, it's a finding (even if just timeout is set)
            # The presence of tailf-ned-cisco-asa:telnet means telnet is configured
            if telnet_config is not None:
                telnet_disabled = False
                
                # If it's a dict, check for actual entries or just timeout
                if isinstance(telnet_config, dict):
                    # Check if there are actual telnet entries (not just timeout)
                    if 'timeout' in telnet_config and len(telnet_config) == 1:
                        # Only timeout is set - telnet service is configured but no access entries
                        telnet_entries.append({
                            'ip': 'N/A',
                            'mask': 'N/A', 
                            'interface': 'N/A',
                            'note': 'Telnet timeout configured (service present)'
                        })
                    else:
                        # There are actual telnet access entries
                        for key, value in telnet_config.items():
                            if key != 'timeout':
                                if isinstance(value, dict):
                                    ip = value.get('ip', value.get('address', 'unknown'))
                                    mask = value.get('mask', value.get('netmask', 'unknown'))
                                    interface = value.get('if-name', value.get('interface', 'unknown'))
                                    telnet_entries.append({
                                        'ip': ip,
                                        'mask': mask,
                                        'interface': interface
                                    })
                elif isinstance(telnet_config, list) and telnet_config:
                    # List of telnet entries
                    for entry in telnet_config:
                        if isinstance(entry, dict):
                            ip = entry.get('ip', entry.get('address', 'unknown'))
                            mask = entry.get('mask', entry.get('netmask', 'unknown'))
                            interface = entry.get('if-name', entry.get('interface', 'unknown'))
                            telnet_entries.append({
                                'ip': ip,
                                'mask': mask,
                                'interface': interface
                            })
            
            # Check 2: Document other potentially unauthorized services
            # Note: http server is OK as it enables HTTPS for ASDM
            # We'll just note if other services are present for informational purposes
            
            # FTP server
            if 'tailf-ned-cisco-asa:ftp' in device_config:
                ftp_mode = device_config['tailf-ned-cisco-asa:ftp'].get('mode', None)
                if ftp_mode:
                    unauthorized_services.append(f"FTP (mode: {ftp_mode}) - may be unauthorized")
            
            # DHCP server
            if 'tailf-ned-cisco-asa:dhcpd' in device_config:
                dhcpd_config = device_config['tailf-ned-cisco-asa:dhcpd']
                if dhcpd_config and isinstance(dhcpd_config, dict):
                    if 'address' in dhcpd_config or 'enable' in dhcpd_config:
                        unauthorized_services.append("DHCP server - verify if authorized for this firewall role")
            
            # Overall compliance - Telnet MUST be disabled
            # Other services are informational warnings
            overall_compliant = telnet_disabled
            
            # Store results
            results[device_name] = {
                'telnet_disabled': telnet_disabled,
                'telnet_entries': telnet_entries,
                'unauthorized_services': unauthorized_services,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not telnet_disabled:
                error_parts.append(f"✗ CRITICAL: Telnet is enabled ({len(telnet_entries)} entry/entries)")
                error_parts.append("  Telnet must NEVER be enabled (insecure protocol)")
                for entry in telnet_entries:
                    error_parts.append(f"    telnet {entry['ip']} {entry['mask']} {entry['interface']}")
            
            if unauthorized_services:
                error_parts.append(f"\n⚠ Warning: {len(unauthorized_services)} potentially unauthorized service(s) detected:")
                for service in unauthorized_services:
                    error_parts.append(f"    {service}")
                error_parts.append("  Review these services against the firewall's documented role")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired action:\n"
                    f"  ASA(config)# no telnet <ip> <mask> <interface>"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking unnecessary services on {device_name}: {e}"
    
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
                if not telnet_disabled:
                    print(f"  ✗ Telnet is ENABLED ({len(result.get('telnet_entries', []))} config) - CRITICAL FINDING")
                    for entry in result.get('telnet_entries', []):
                        if entry.get('note'):
                            print(f"    {entry['note']}")
                        else:
                            print(f"    {entry['ip']} {entry['mask']} on {entry['interface']}")
                
                unauthorized = result.get('unauthorized_services', [])
                if unauthorized:
                    print(f"  ⚠  {len(unauthorized)} potentially unauthorized service(s):")
                    for service in unauthorized:
                        print(f"    {service}")
        else:
            # Show status for passing tests
            print(f"  ✓ Telnet is disabled (secure)")
            unauthorized = result.get('unauthorized_services', [])
            if unauthorized:
                print(f"  ⚠  Note: {len(unauthorized)} service(s) detected - verify against role:")
                for service in unauthorized:
                    print(f"    {service}")
            else:
                print(f"  ✓ No obviously unauthorized services detected")


if __name__ == "__main__":
    test_asa_no_unnecessary_services()
