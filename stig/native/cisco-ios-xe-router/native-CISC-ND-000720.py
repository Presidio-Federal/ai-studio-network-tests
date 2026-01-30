"""
STIG ID: CISC-ND-000720
Finding ID: V-215688
Rule ID: SV-215688r961068_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to terminate all network connections 
            associated with device management after five minutes of inactivity.

Discussion:
Terminating an idle session within a short time period reduces the window of 
opportunity for unauthorized personnel to take control of a management session enabled 
on the console or console port that has been left unattended. In addition, quickly 
terminating an idle session will also free up resources committed by the managed network 
element.

Check Text:
Review the router configuration to verify that it is configured to timeout management 
connections after five minutes of inactivity. The following example will set the timeout 
for the vty lines.

line vty 0 4
  exec-timeout 5 0

If the device is not configured to timeout management connections after five minutes of 
inactivity, this is a finding.

Note: 0 0 means the session will never timeout, which is a finding.

Fix Text:
Configure the device to timeout management connections after five minutes of inactivity 
as shown in the example below.

SW1(config)# line vty 0 4
SW1(config-line)# exec-timeout 5 0
SW1(config-line)# end

References:
CCI: CCI-001133
NIST SP 800-53 :: SC-10
NIST SP 800-53 Revision 4 :: SC-10
NIST SP 800-53 Revision 5 :: SC-10
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000720"
FINDING_ID = "V-215688"
RULE_ID = "SV-215688r961068_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must terminate management connections after 5 minutes of inactivity"

# Maximum allowed timeout in minutes
MAX_TIMEOUT_MINUTES = 5


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native format)."""
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


def test_connection_timeout():
    """
    Test that all management connection lines are configured with appropriate timeout.
    
    STIG V-215688 (CISC-ND-000720) requires that routers terminate management 
    connections after 5 minutes of inactivity. This checks console, aux, and vty lines
    for exec-timeout configuration.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            line_config = config.get('tailf-ned-cisco-ios:line', {})
            
            non_compliant_lines = []
            compliant_lines = []
            
            # Check console lines
            console_lines = line_config.get('console', [])
            for line in console_lines:
                line_id = f"console {line.get('first', '?')}"
                exec_timeout = line.get('exec-timeout', {})
                
                if isinstance(exec_timeout, dict):
                    minutes = exec_timeout.get('minutes', None)
                    
                    # Check if timeout is disabled (0) or exceeds max
                    if minutes is None or minutes == 0 or minutes > MAX_TIMEOUT_MINUTES:
                        non_compliant_lines.append({
                            'line': line_id,
                            'timeout_minutes': minutes if minutes is not None else 'not set',
                            'issue': 'timeout disabled' if minutes == 0 else 'exceeds 5 minutes' if minutes else 'not configured'
                        })
                    else:
                        compliant_lines.append(line_id)
            
            # Check aux lines
            aux_lines = line_config.get('aux', [])
            for line in aux_lines:
                line_id = f"aux {line.get('first', '?')}"
                exec_timeout = line.get('exec-timeout', {})
                
                if isinstance(exec_timeout, dict):
                    minutes = exec_timeout.get('minutes', None)
                    
                    if minutes is None or minutes == 0 or minutes > MAX_TIMEOUT_MINUTES:
                        non_compliant_lines.append({
                            'line': line_id,
                            'timeout_minutes': minutes if minutes is not None else 'not set',
                            'issue': 'timeout disabled' if minutes == 0 else 'exceeds 5 minutes' if minutes else 'not configured'
                        })
                    else:
                        compliant_lines.append(line_id)
            
            # Check vty lines (both single-conf and ranges)
            vty_single = line_config.get('vty-single-conf', {}).get('vty', [])
            for line in vty_single:
                line_id = f"vty {line.get('first', '?')}"
                exec_timeout = line.get('exec-timeout', {})
                
                if isinstance(exec_timeout, dict):
                    minutes = exec_timeout.get('minutes', None)
                    
                    if minutes is None or minutes == 0 or minutes > MAX_TIMEOUT_MINUTES:
                        non_compliant_lines.append({
                            'line': line_id,
                            'timeout_minutes': minutes if minutes is not None else 'not set',
                            'issue': 'timeout disabled' if minutes == 0 else 'exceeds 5 minutes' if minutes else 'not configured'
                        })
                    else:
                        compliant_lines.append(line_id)
            
            # Check vty ranges
            vty_ranges = line_config.get('vty', [])
            for line in vty_ranges:
                first = line.get('first', '?')
                last = line.get('last', first)
                line_id = f"vty {first} {last}" if first != last else f"vty {first}"
                exec_timeout = line.get('exec-timeout', {})
                
                if isinstance(exec_timeout, dict):
                    minutes = exec_timeout.get('minutes', None)
                    
                    if minutes is None or minutes == 0 or minutes > MAX_TIMEOUT_MINUTES:
                        non_compliant_lines.append({
                            'line': line_id,
                            'timeout_minutes': minutes if minutes is not None else 'not set',
                            'issue': 'timeout disabled' if minutes == 0 else 'exceeds 5 minutes' if minutes else 'not configured'
                        })
                    else:
                        compliant_lines.append(line_id)
            
            # Overall compliance
            overall_compliant = len(non_compliant_lines) == 0
            
            results[device_name] = {
                'compliant_lines': compliant_lines,
                'non_compliant_lines': non_compliant_lines,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append(f"\nNon-compliant lines ({len(non_compliant_lines)}):")
                for line_info in non_compliant_lines:
                    error_parts.append(f"  - {line_info['line']}: {line_info['issue']} (timeout: {line_info['timeout_minutes']})")
                
                error_parts.append(f"\nRequired configuration:")
                error_parts.append(f"  SW1(config)# line vty 0 4")
                error_parts.append(f"  SW1(config-line)# exec-timeout 5 0")
                error_parts.append(f"\nNote: Timeout must be ≤ {MAX_TIMEOUT_MINUTES} minutes and cannot be disabled (0 0)")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking connection timeout on {device_name}: {e}"
    
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
            compliant = result.get('compliant_lines', [])
            print(f"  ✓ All lines properly configured ({len(compliant)} lines)")
            for line in compliant:
                print(f"    {line}")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                non_compliant = result.get('non_compliant_lines', [])
                for line_info in non_compliant:
                    print(f"  ✗ {line_info['line']}: {line_info['issue']}")


if __name__ == "__main__":
    test_connection_timeout()
