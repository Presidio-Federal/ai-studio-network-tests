"""
HIPAA ID: HIPAA-AC-003
Rule: Automatic Logoff
Severity: Medium
Classification: HIPAA Security Rule § 164.312(a)(2)(iii)

Extraction Method: NSO (YANG Model)
Platform: Cisco IOS-XE Router

Rule Title: The network device must be configured with automatic logoff after 15 minutes or less of inactivity.

Discussion:
HIPAA Security Rule requires automatic logoff to terminate an electronic session after 
a predetermined time of inactivity. This requirement protects electronic protected health 
information (ePHI) from unauthorized access when a user leaves their workstation or 
terminal session unattended.

The 15-minute threshold aligns with HIPAA best practices and security guidance for 
protecting access to systems that process, store, or transmit ePHI. Longer timeout 
periods increase the risk window for unauthorized access.

Check Text:
Review the router configuration to verify that exec-timeout is configured on all lines 
(console, vty, aux) with a maximum of 15 minutes. The configuration should look similar 
to the example below:

line console 0
  exec-timeout 15 0

line vty 0 4
  exec-timeout 15 0

If exec-timeout is not configured or exceeds 15 minutes (or is set to 0 0, which disables timeout), this is a finding.

Fix Text:
Configure automatic logoff on all access lines:

R1(config)# line console 0
R1(config-line)# exec-timeout 15 0
R1(config-line)# exit
R1(config)# line vty 0 15
R1(config-line)# exec-timeout 15 0
R1(config-line)# exit
R1(config)# line aux 0
R1(config-line)# exec-timeout 15 0
R1(config-line)# end

References:
HIPAA Security Rule: § 164.312(a)(2)(iii) - Automatic Logoff
NIST SP 800-53 Rev 5: AC-11 (Session Lock), AC-12 (Session Termination)
45 CFR 164.312(a)(2)(iii)
"""

import os
import json
import yaml
import pytest

HIPAA_ID = "HIPAA-AC-003"
RULE_TITLE = "Automatic Logoff"
SEVERITY = "Medium"
CATEGORY = "HIPAA"
FRAMEWORK = "HIPAA Security Rule"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
HIPAA_REFERENCE = "45 CFR § 164.312(a)(2)(iii)"

MAX_TIMEOUT_MINUTES = 15


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


def check_exec_timeout(exec_timeout_config, max_minutes=MAX_TIMEOUT_MINUTES):
    """
    Check if exec-timeout is configured and compliant.
    Returns: (is_configured, is_compliant, timeout_minutes, timeout_seconds)
    """
    if not exec_timeout_config:
        return False, False, None, None
    
    minutes = exec_timeout_config.get('minutes', 0)
    seconds = exec_timeout_config.get('seconds', 0)
    
    # Timeout of 0 0 means disabled
    if minutes == 0 and seconds == 0:
        return True, False, 0, 0
    
    # Check if within allowed threshold
    is_compliant = (minutes > 0 and minutes <= max_minutes)
    
    return True, is_compliant, minutes, seconds


def test_automatic_logoff():
    """
    Test that automatic logoff is configured on all access lines.
    
    HIPAA § 164.312(a)(2)(iii) requires automatic logoff after a predetermined time 
    of inactivity to protect ePHI from unauthorized access.
    
    The test validates that:
    1. Exec-timeout is configured on console lines
    2. Exec-timeout is configured on VTY lines
    3. Exec-timeout is configured on AUX lines (if present)
    4. All timeouts are 15 minutes or less (and not disabled with 0 0)
    
    This ensures compliance with HIPAA's automatic logoff requirement.
    
    NSO extraction method: Tests against NSO YANG data models.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            
            # Initialize tracking
            line_results = {
                'console': [],
                'vty': [],
                'aux': []
            }
            
            # Check line configuration
            line_config = config.get('tailf-ned-cisco-ios:line', {})
            
            # Check console lines
            console_lines = line_config.get('console', [])
            for console in console_lines:
                line_id = console.get('first', 'unknown')
                exec_timeout = console.get('exec-timeout', {})
                is_configured, is_compliant, minutes, seconds = check_exec_timeout(exec_timeout)
                
                line_results['console'].append({
                    'line_id': line_id,
                    'configured': is_configured,
                    'compliant': is_compliant,
                    'minutes': minutes,
                    'seconds': seconds
                })
            
            # Check VTY lines (both single-conf and range)
            vty_single_conf = line_config.get('vty-single-conf', {}).get('vty', [])
            for vty in vty_single_conf:
                line_id = vty.get('first', 'unknown')
                exec_timeout = vty.get('exec-timeout', {})
                is_configured, is_compliant, minutes, seconds = check_exec_timeout(exec_timeout)
                
                line_results['vty'].append({
                    'line_id': line_id,
                    'configured': is_configured,
                    'compliant': is_compliant,
                    'minutes': minutes,
                    'seconds': seconds
                })
            
            vty_ranges = line_config.get('vty', [])
            for vty in vty_ranges:
                first = vty.get('first', 'unknown')
                last = vty.get('last', first)
                line_id = f"{first}-{last}" if first != last else str(first)
                exec_timeout = vty.get('exec-timeout', {})
                is_configured, is_compliant, minutes, seconds = check_exec_timeout(exec_timeout)
                
                line_results['vty'].append({
                    'line_id': line_id,
                    'configured': is_configured,
                    'compliant': is_compliant,
                    'minutes': minutes,
                    'seconds': seconds
                })
            
            # Check AUX lines
            aux_lines = line_config.get('aux', [])
            for aux in aux_lines:
                line_id = aux.get('first', 'unknown')
                exec_timeout = aux.get('exec-timeout', {})
                is_configured, is_compliant, minutes, seconds = check_exec_timeout(exec_timeout)
                
                line_results['aux'].append({
                    'line_id': line_id,
                    'configured': is_configured,
                    'compliant': is_compliant,
                    'minutes': minutes,
                    'seconds': seconds
                })
            
            # Evaluate overall compliance
            non_compliant_lines = []
            
            for line_type, lines in line_results.items():
                for line_info in lines:
                    if not line_info['compliant']:
                        non_compliant_lines.append({
                            'type': line_type,
                            'id': line_info['line_id'],
                            'configured': line_info['configured'],
                            'minutes': line_info['minutes'],
                            'seconds': line_info['seconds']
                        })
            
            overall_compliant = len(non_compliant_lines) == 0
            
            results[device_name] = {
                'line_results': line_results,
                'non_compliant_lines': non_compliant_lines,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with HIPAA {HIPAA_ID}:"]
                error_parts.append(f"\nNon-compliant lines (exec-timeout must be ≤ {MAX_TIMEOUT_MINUTES} minutes):")
                
                for line in non_compliant_lines:
                    if not line['configured']:
                        error_parts.append(f"  ✗ {line['type']} {line['id']}: exec-timeout NOT configured")
                    elif line['minutes'] == 0 and line['seconds'] == 0:
                        error_parts.append(f"  ✗ {line['type']} {line['id']}: exec-timeout DISABLED (0 0)")
                    else:
                        error_parts.append(f"  ✗ {line['type']} {line['id']}: exec-timeout {line['minutes']} {line['seconds']} (exceeds {MAX_TIMEOUT_MINUTES} minutes)")
                
                error_parts.append("\nHIPAA requires automatic logoff after ≤15 minutes of inactivity!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# line console 0")
                error_parts.append("  R1(config-line)# exec-timeout 15 0")
                error_parts.append("  R1(config-line)# exit")
                error_parts.append("  R1(config)# line vty 0 15")
                error_parts.append("  R1(config-line)# exec-timeout 15 0")
                error_parts.append("  R1(config-line)# end")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking exec-timeout on {device_name}: {e}"
    
    # Print summary
    print("\nHIPAA Compliance Summary:")
    print(f"HIPAA ID: {HIPAA_ID}")
    print(f"Rule: {RULE_TITLE}")
    print(f"Reference: {HIPAA_REFERENCE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Maximum Allowed Timeout: {MAX_TIMEOUT_MINUTES} minutes")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ All lines have compliant exec-timeout configuration")
            for line_type, lines in result.get('line_results', {}).items():
                for line_info in lines:
                    if line_info['configured']:
                        print(f"  ✓ {line_type} {line_info['line_id']}: {line_info['minutes']} minutes {line_info['seconds']} seconds")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                for line in result.get('non_compliant_lines', []):
                    status_desc = "NOT configured" if not line['configured'] else f"{line['minutes']} min {line['seconds']} sec"
                    print(f"  ✗ {line['type']} {line['id']}: {status_desc}")


if __name__ == "__main__":
    test_automatic_logoff()
