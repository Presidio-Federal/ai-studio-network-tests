"""
Test for STIG ID: CISC-ND-000720
Connection timeout validation
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
PLATFORM = "ios-xe-router-ndm"
TITLE = "The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity"


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
    # Format 2: {tailf-ned-cisco-ios:hostname: ..., tailf-ned-cisco-ios:service: ...} - direct NSO config
    
    # Check if this is a direct NSO config (has tailf-ned-cisco-ios keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        # Direct NSO config - wrap it with a device name
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        # Wrap in expected format
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_connection_timeout_configured():
    """
    Test that connection timeouts are properly configured.
    
    STIG V-215688 (CISC-ND-000720) requires that Cisco routers must be configured
    to terminate all network connections associated with device management after
    five minutes of inactivity. This is validated by checking:
    
    1. HTTP secure server is enabled
    2. HTTP timeout policy is configured with idle timeout <= 300 seconds (5 minutes)
    3. Console line has exec-timeout <= 5 minutes
    4. VTY lines have exec-timeout <= 5 minutes
    """
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    devices = load_test_data(test_input_file)
    
    # Dictionary to store results
    results = {}
    max_timeout_minutes = 5  # Maximum allowed timeout in minutes
    
    # Check each device configuration
    for device_name, config in devices.items():
        try:
            # Get the config section
            device_config = config.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            http_secure_server_enabled = False
            http_timeout_policy_compliant = False
            console_timeout_compliant = False
            vty_timeout_compliant = True  # Default to True, will set to False if any non-compliant VTY found
            
            # 1. Check if HTTP secure server is enabled
            ip_config = device_config.get('tailf-ned-cisco-ios:ip', {})
            http_config = ip_config.get('http', {})
            http_secure_server_enabled = http_config.get('secure-server', False)
            
            # 2. Check HTTP timeout policy
            timeout_policy = http_config.get('timeout-policy', {})
            http_idle_timeout = timeout_policy.get('idle', 0)
            http_timeout_policy_compliant = http_idle_timeout > 0 and http_idle_timeout <= 300
            
            # 3. Check console line timeout
            line_config = device_config.get('tailf-ned-cisco-ios:line', {})
            console_lines = line_config.get('console', [])
            
            for console in console_lines:
                if console.get('first') == '0':
                    exec_timeout = console.get('exec-timeout', {})
                    minutes = exec_timeout.get('minutes', 0)
                    console_timeout_compliant = minutes > 0 and minutes <= max_timeout_minutes
                    break
            
            # 4. Check VTY line timeouts
            vty_lines = line_config.get('vty', [])
            vty_single_conf = line_config.get('vty-single-conf', {})
            vty_single_lines = vty_single_conf.get('vty', []) if vty_single_conf else []
            
            # Check both types of VTY configurations
            all_vty_lines = vty_lines + vty_single_lines
            
            for vty in all_vty_lines:
                exec_timeout = vty.get('exec-timeout', {})
                minutes = exec_timeout.get('minutes', 0)
                if minutes > max_timeout_minutes:
                    vty_timeout_compliant = False
                    break
            
            # Overall compliance
            overall_compliant = (
                http_secure_server_enabled and
                http_timeout_policy_compliant and
                console_timeout_compliant and
                vty_timeout_compliant
            )
            
            # Store results
            results[device_name] = {
                'http_secure_server_enabled': http_secure_server_enabled,
                'http_timeout_policy_compliant': http_timeout_policy_compliant,
                'console_timeout_compliant': console_timeout_compliant,
                'vty_timeout_compliant': vty_timeout_compliant,
                'compliant': overall_compliant
            }
            
            # Assert that the device is compliant
            assert overall_compliant, (
                f"Device {device_name} is not compliant with STIG {STIG_ID}:\n"
                f"- HTTP Secure Server Enabled: {http_secure_server_enabled}\n"
                f"- HTTP Timeout Policy Compliant: {http_timeout_policy_compliant}\n"
                f"- Console Timeout Compliant: {console_timeout_compliant}\n"
                f"- VTY Timeout Compliant: {vty_timeout_compliant}"
            )
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking timeout configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print("  Failed compliance checks:")
                if not result.get('http_secure_server_enabled', True):
                    print("  - HTTP secure server is not enabled")
                if not result.get('http_timeout_policy_compliant', True):
                    print("  - HTTP timeout policy is not properly configured (idle <= 300 seconds)")
                if not result.get('console_timeout_compliant', True):
                    print("  - Console line timeout is not properly configured (<=5 minutes)")
                if not result.get('vty_timeout_compliant', True):
                    print("  - One or more VTY lines timeout is not properly configured (<=5 minutes)")


if __name__ == "__main__":
    test_connection_timeout_configured()
