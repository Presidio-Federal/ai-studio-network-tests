"""
STIG ID: CISC-ND-000010
Finding ID: V-215662
Rule ID: SV-215662r1050869_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: NSO
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to limit the number of concurrent 
            management sessions to an organization-defined number.

Discussion:
Device management includes the ability to control the number of administrators and 
management sessions that manage a device. Limiting the number of allowed administrators 
and sessions per administrator based on account type, role, or access type is helpful 
in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not 
address concurrent sessions by a single administrator via multiple administrative accounts. 
The maximum number of concurrent sessions should be defined based upon mission needs and 
the operational environment for each system. At a minimum, limits must be set for SSH, 
HTTPS, account of last resort, and root account sessions.

Check Text:
Note: This requirement is not applicable to file transfer actions such as FTP, SCP, and SFTP.

Review the router configuration to determine if concurrent management sessions are limited:

ip http secure-server
ip http max-connections 2
line vty 0 1
  transport input ssh
line vty 2 4
  transport input none

If the router is not configured to limit the number of concurrent management sessions, 
this is a finding.

Fix Text:
Configure the router to limit the number of concurrent management sessions.

R4(config)# ip http max-connections 2
R4(config)# line vty 0 1
R4(config-line)# transport input ssh
R4(config-line)# exit
R4(config)# line vty 2 4
R4(config-line)# transport input none
R4(config-line)# end

References:
CCI: CCI-000054
NIST SP 800-53 :: AC-10
NIST SP 800-53 Revision 4 :: AC-10
NIST SP 800-53 Revision 5 :: AC-10
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000010"
FINDING_ID = "V-215662"
RULE_ID = "SV-215662r1050869_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
TITLE = "Router must limit concurrent management sessions"

# Organization-defined limits (adjust per mission needs)
MAX_HTTP_CONNECTIONS = 2  # Maximum HTTPS/HTTP connections
MAX_VTY_SSH_LINES = 2      # Maximum VTY lines with SSH enabled


def load_test_data(file_path):
    """Load test data from JSON or YAML file (NSO format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle multiple formats
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_concurrent_session_limits():
    """
    Test that concurrent management sessions are limited to organization-defined numbers.
    
    STIG V-215662 (CISC-ND-000010) requires:
    1. HTTP/HTTPS max-connections is configured and limited
    2. VTY lines with SSH are limited to organization-defined number
    3. Remaining VTY lines have transport input disabled (none)
    
    This prevents DoS attacks by limiting concurrent administrative sessions.
    
    NSO extraction method: Tests against NSO data models.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            http_max_connections_configured = False
            http_max_connections_value = None
            http_compliant = False
            
            vty_ssh_count = 0
            vty_disabled_count = 0
            vty_compliant = False
            vty_details = []
            
            # Check 1: HTTP max-connections
            ip_config = config.get('tailf-ned-cisco-ios:ip', {})
            http_config = ip_config.get('http', {})
            
            if 'max-connections' in http_config:
                http_max_connections_configured = True
                http_max_connections_value = http_config.get('max-connections')
                
                # Check if within limit
                if http_max_connections_value is not None and http_max_connections_value <= MAX_HTTP_CONNECTIONS:
                    http_compliant = True
            
            # Check 2: VTY lines configuration
            line_config = config.get('tailf-ned-cisco-ios:line', {})
            
            # Check vty-single-conf (individual VTY lines)
            vty_single = line_config.get('vty-single-conf', {}).get('vty', [])
            for vty in vty_single:
                line_num = vty.get('first', '?')
                transport = vty.get('transport', {})
                transport_input = transport.get('input', [])
                
                if isinstance(transport_input, list):
                    if 'ssh' in transport_input:
                        vty_ssh_count += 1
                        vty_details.append({
                            'line': f"vty {line_num}",
                            'transport': 'ssh',
                            'compliant': True
                        })
                    elif 'none' in transport_input:
                        vty_disabled_count += 1
                        vty_details.append({
                            'line': f"vty {line_num}",
                            'transport': 'none',
                            'compliant': True
                        })
                    else:
                        vty_details.append({
                            'line': f"vty {line_num}",
                            'transport': str(transport_input),
                            'compliant': False,
                            'issue': 'transport not ssh or none'
                        })
            
            # Check vty ranges
            vty_ranges = line_config.get('vty', [])
            for vty in vty_ranges:
                first = vty.get('first', '?')
                last = vty.get('last', first)
                line_id = f"vty {first} {last}" if first != last else f"vty {first}"
                transport = vty.get('transport', {})
                transport_input = transport.get('input', [])
                
                # Calculate number of lines in range
                try:
                    line_count = int(last) - int(first) + 1
                except:
                    line_count = 1
                
                if isinstance(transport_input, list):
                    if 'ssh' in transport_input:
                        vty_ssh_count += line_count
                        vty_details.append({
                            'line': line_id,
                            'transport': 'ssh',
                            'count': line_count,
                            'compliant': False,
                            'issue': f'adds {line_count} SSH lines - exceeds limit'
                        })
                    elif 'none' in transport_input:
                        vty_disabled_count += line_count
                        vty_details.append({
                            'line': line_id,
                            'transport': 'none',
                            'count': line_count,
                            'compliant': True
                        })
                    else:
                        vty_details.append({
                            'line': line_id,
                            'transport': str(transport_input),
                            'count': line_count,
                            'compliant': False,
                            'issue': 'transport not ssh or none'
                        })
            
            # VTY is compliant if SSH lines are within limit
            vty_compliant = vty_ssh_count > 0 and vty_ssh_count <= MAX_VTY_SSH_LINES
            
            # Overall compliance
            overall_compliant = http_compliant and vty_compliant
            
            results[device_name] = {
                'http_max_connections_configured': http_max_connections_configured,
                'http_max_connections_value': http_max_connections_value,
                'http_compliant': http_compliant,
                'vty_ssh_count': vty_ssh_count,
                'vty_disabled_count': vty_disabled_count,
                'vty_compliant': vty_compliant,
                'vty_details': vty_details,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not http_compliant:
                    if not http_max_connections_configured:
                        error_parts.append("  ✗ HTTP max-connections is NOT configured")
                    else:
                        error_parts.append(f"  ✗ HTTP max-connections ({http_max_connections_value}) exceeds limit ({MAX_HTTP_CONNECTIONS})")
                
                if not vty_compliant:
                    if vty_ssh_count == 0:
                        error_parts.append("  ✗ No VTY lines with SSH configured")
                    elif vty_ssh_count > MAX_VTY_SSH_LINES:
                        error_parts.append(f"  ✗ Too many VTY lines with SSH enabled ({vty_ssh_count} > {MAX_VTY_SSH_LINES})")
                    
                    error_parts.append("\n  VTY Line Details:")
                    for vty in vty_details:
                        if not vty.get('compliant', True):
                            count_str = f" ({vty['count']} lines)" if 'count' in vty else ""
                            error_parts.append(f"    {vty['line']}{count_str}: {vty.get('issue', 'issue')}")
                
                error_parts.append(f"\nRequired configuration:")
                error_parts.append(f"  R4(config)# ip http max-connections {MAX_HTTP_CONNECTIONS}")
                error_parts.append(f"  R4(config)# line vty 0 {MAX_VTY_SSH_LINES - 1}")
                error_parts.append(f"  R4(config-line)# transport input ssh")
                error_parts.append(f"  R4(config-line)# exit")
                error_parts.append(f"  R4(config)# line vty {MAX_VTY_SSH_LINES} 4")
                error_parts.append(f"  R4(config-line)# transport input none")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking concurrent session limits on {device_name}: {e}"
    
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
            print(f"  ✓ HTTP max-connections: {result.get('http_max_connections_value')} (limit: {MAX_HTTP_CONNECTIONS})")
            print(f"  ✓ VTY lines with SSH: {result.get('vty_ssh_count')} (limit: {MAX_VTY_SSH_LINES})")
            print(f"  ✓ VTY lines disabled: {result.get('vty_disabled_count')}")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  HTTP max-connections: {'✓' if result.get('http_compliant') else '✗'} ({result.get('http_max_connections_value', 'not set')})")
                print(f"  VTY SSH lines: {'✓' if result.get('vty_compliant') else '✗'} ({result.get('vty_ssh_count')} configured)")


if __name__ == "__main__":
    test_concurrent_session_limits()
