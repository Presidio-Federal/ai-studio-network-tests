"""
PCI-DSS Requirement: 8.3.6
Version: 4.0
Severity: High
Classification: CDE Network Security

Extraction Method: NSO
Platform: Cisco IOS-XE Router

Requirement Title: Account lockout duration must be at least 30 minutes or until 
                   administrator enables the user ID after failed authentication attempts.

Discussion:
PCI-DSS requires that user accounts be locked out for at least 30 minutes after a 
specified number of failed authentication attempts. This prevents automated password 
guessing attacks (brute-force attacks) by introducing significant delays between 
attempts. The lockout can be reset by an administrator if needed.

For network devices, this is implemented via the login block-for command, which 
should lock accounts for at least 1800 seconds (30 minutes).

Check Text:
Review the router configuration to verify account lockout is configured for at least 
30 minutes after failed authentication attempts.

login block-for 1800 attempts 6 within 120

Note: PCI-DSS requires at least 30 minutes lockout. The number of attempts can vary 
by organization policy (common values: 3-6 attempts).

If the router is not configured to lock accounts for at least 30 minutes after 
failed authentication attempts, this is a PCI-DSS finding.

Fix Text:
Configure the router to lock accounts for 30 minutes after failed attempts.

Router(config)# login block-for 1800 attempts 6 within 120
Router(config)# end

References:
PCI-DSS v4.0 Requirement 8.3.6
CCI: CCI-000044 (NIST AC-7)
"""

import os
import json
import yaml
import pytest

PCI_REQUIREMENT = "8.3.6"
PCI_VERSION = "4.0"
SEVERITY = "High"
CATEGORY = "PCI-DSS"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
TITLE = "Account lockout duration must be at least 30 minutes"

# PCI-DSS requirements
MIN_LOCKOUT_SECONDS = 1800  # 30 minutes minimum
MAX_ATTEMPTS_RECOMMENDED = 6  # Organization-defined (common: 3-10)
WITHIN_SECONDS_RECOMMENDED = 120  # 2 minutes


def load_test_data(file_path):
    """Load test data from JSON or YAML file (NSO format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_pci_account_lockout_duration():
    """
    Test that account lockout duration meets PCI-DSS 30-minute requirement.
    
    PCI-DSS v4.0 Requirement 8.3.6 requires that user accounts be locked for at 
    least 30 minutes (1800 seconds) after failed authentication attempts, or until 
    an administrator enables the account.
    
    This test validates:
    1. Login block-for is configured
    2. Lockout duration is at least 1800 seconds (30 minutes)
    3. Failed attempt limit is configured (organization-defined)
    
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
            
            block_for_configured = False
            block_seconds = None
            attempts = None
            lockout_duration_compliant = False
            
            # Check login block-for configuration
            login_config = config.get('tailf-ned-cisco-ios:login', {})
            
            if 'block-for' in login_config:
                block_for_configured = True
                block_for = login_config['block-for']
                
                block_seconds = block_for.get('seconds')
                attempts = block_for.get('attempts')
                
                # PCI-DSS requires at least 30 minutes (1800 seconds)
                if block_seconds is not None and block_seconds >= MIN_LOCKOUT_SECONDS:
                    lockout_duration_compliant = True
            
            overall_compliant = block_for_configured and lockout_duration_compliant
            
            results[device_name] = {
                'block_for_configured': block_for_configured,
                'block_seconds': block_seconds,
                'attempts': attempts,
                'lockout_duration_compliant': lockout_duration_compliant,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is NOT compliant with PCI-DSS {PCI_REQUIREMENT}:"]
                
                if not block_for_configured:
                    error_parts.append("  Account lockout is NOT configured")
                elif not lockout_duration_compliant:
                    error_parts.append(f"  Lockout duration ({block_seconds}s / {block_seconds//60} min) is less than PCI-DSS requirement ({MIN_LOCKOUT_SECONDS}s / 30 min)")
                
                error_parts.append("\nPCI-DSS v4.0 Requirement 8.3.6 Violation:")
                error_parts.append("  User accounts must be locked for at least 30 minutes after")
                error_parts.append("  failed authentication attempts to prevent brute-force attacks.")
                error_parts.append(f"\nRequired configuration:")
                error_parts.append(f"  Router(config)# login block-for {MIN_LOCKOUT_SECONDS} attempts {MAX_ATTEMPTS_RECOMMENDED} within {WITHIN_SECONDS_RECOMMENDED}")
                error_parts.append(f"\nNote: Lockout duration must be >= 30 minutes for PCI-DSS compliance")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking account lockout on {device_name}: {e}"
    
    print("\nPCI-DSS Compliance Summary:")
    print(f"PCI-DSS Requirement: {PCI_REQUIREMENT}")
    print(f"Version: {PCI_VERSION}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            mins = result.get('block_seconds', 0) // 60
            print(f"  Account lockout: {result.get('block_seconds')}s ({mins} minutes)")
            print(f"  Max attempts: {result.get('attempts')}")
            print(f"  PCI-DSS 8.3.6: COMPLIANT (>= 30 minutes)")
        else:
            if 'error' not in result:
                print(f"  Block-for configured: {'Yes' if result.get('block_for_configured') else 'No'}")
                if result.get('block_seconds'):
                    print(f"  Current lockout: {result.get('block_seconds')}s ({result.get('block_seconds')//60} min)")
                print(f"  Required: >= {MIN_LOCKOUT_SECONDS}s (30 minutes)")


if __name__ == "__main__":
    test_pci_account_lockout_duration()
