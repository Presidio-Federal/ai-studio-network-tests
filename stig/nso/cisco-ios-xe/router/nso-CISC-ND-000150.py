"""
STIG ID: CISC-ND-000150
Finding ID: V-215668
Rule ID: SV-215668r960840_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: NSO
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to enforce the limit of three 
            consecutive invalid logon attempts, after which time it must lock out 
            the user account from accessing the device for 15 minutes.

Discussion:
By limiting the number of failed logon attempts, the risk of unauthorized system 
access via user password guessing, otherwise known as brute-forcing, is reduced.

Check Text:
Review the Cisco router configuration to verify that it enforces the limit of three 
consecutive invalid logon attempts as shown in the example below.

login block-for 900 attempts 3 within 120

Note: The configuration example above will block any login attempt for 15 minutes 
after three consecutive invalid logon attempts within a two-minute period.

If the Cisco router is not configured to enforce the limit of three consecutive 
invalid logon attempts, this is a finding.

Fix Text:
Configure the Cisco router to enforce the limit of three consecutive invalid logon 
attempts as shown in the example below.

R2(config)# login block-for 900 attempts 3 within 120

References:
CCI: CCI-000044
NIST SP 800-53 :: AC-7 a
NIST SP 800-53 Revision 4 :: AC-7 a
NIST SP 800-53 Revision 5 :: AC-7 a
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000150"
FINDING_ID = "V-215668"
RULE_ID = "SV-215668r960840_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
TITLE = "Router must enforce limit of three consecutive invalid logon attempts"

# STIG-required values
REQUIRED_BLOCK_SECONDS = 900  # 15 minutes
REQUIRED_MAX_ATTEMPTS = 3
REQUIRED_WITHIN_SECONDS = 120  # 2 minutes


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


def test_login_block_for_configured():
    """
    Test that login block-for is configured to enforce failed logon attempt limits.
    
    STIG V-215668 (CISC-ND-000150) requires:
    1. Login blocking is configured (block-for)
    2. Block duration is at least 900 seconds (15 minutes)
    3. Maximum attempts is 3 or fewer
    4. Time window is 120 seconds (2 minutes) or less
    
    This prevents brute-force password guessing attacks by locking out accounts 
    after failed login attempts.
    
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
            block_for_configured = False
            block_seconds = None
            attempts = None
            within_seconds = None
            block_duration_compliant = False
            attempts_compliant = False
            within_compliant = False
            
            # Check login block-for configuration
            # Path: login -> block-for -> {seconds, attempts, within}
            login_config = config.get('tailf-ned-cisco-ios:login', {})
            
            if 'block-for' in login_config:
                block_for_configured = True
                block_for = login_config['block-for']
                
                # Get values
                block_seconds = block_for.get('seconds')
                attempts = block_for.get('attempts')
                within_seconds = block_for.get('within')
                
                # Check compliance
                # Block duration must be at least 15 minutes (900 seconds)
                if block_seconds is not None and block_seconds >= REQUIRED_BLOCK_SECONDS:
                    block_duration_compliant = True
                
                # Attempts must be 3 or fewer
                if attempts is not None and attempts <= REQUIRED_MAX_ATTEMPTS:
                    attempts_compliant = True
                
                # Within must be 120 seconds or less
                if within_seconds is not None and within_seconds <= REQUIRED_WITHIN_SECONDS:
                    within_compliant = True
            
            # Overall compliance - all must be configured and compliant
            overall_compliant = (
                block_for_configured and
                block_duration_compliant and
                attempts_compliant and
                within_compliant
            )
            
            results[device_name] = {
                'block_for_configured': block_for_configured,
                'block_seconds': block_seconds,
                'attempts': attempts,
                'within_seconds': within_seconds,
                'block_duration_compliant': block_duration_compliant,
                'attempts_compliant': attempts_compliant,
                'within_compliant': within_compliant,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not block_for_configured:
                    error_parts.append("  ✗ Login block-for is NOT configured")
                else:
                    if not block_duration_compliant:
                        error_parts.append(f"  ✗ Block duration ({block_seconds}s) is less than required ({REQUIRED_BLOCK_SECONDS}s / 15 min)")
                    
                    if not attempts_compliant:
                        error_parts.append(f"  ✗ Max attempts ({attempts}) exceeds limit ({REQUIRED_MAX_ATTEMPTS})")
                    
                    if not within_compliant:
                        error_parts.append(f"  ✗ Time window ({within_seconds}s) exceeds limit ({REQUIRED_WITHIN_SECONDS}s / 2 min)")
                
                error_parts.append("\nBrute-force password attacks are NOT properly prevented!")
                error_parts.append(f"\nRequired configuration:")
                error_parts.append(f"  R2(config)# login block-for {REQUIRED_BLOCK_SECONDS} attempts {REQUIRED_MAX_ATTEMPTS} within {REQUIRED_WITHIN_SECONDS}")
                error_parts.append(f"\nThis will:")
                error_parts.append(f"  - Block login for 15 minutes (900 seconds)")
                error_parts.append(f"  - After 3 failed attempts")
                error_parts.append(f"  - Within a 2 minute (120 seconds) window")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking login block-for configuration on {device_name}: {e}"
    
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
            print(f"  ✓ Login block-for configured")
            print(f"  ✓ Block duration: {result.get('block_seconds')}s ({result.get('block_seconds')//60} minutes)")
            print(f"  ✓ Max attempts: {result.get('attempts')}")
            print(f"  ✓ Time window: {result.get('within_seconds')}s ({result.get('within_seconds')//60} minutes)")
            print(f"  ✓ Brute-force protection enabled")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Login block-for: {'✓' if result.get('block_for_configured') else '✗'}")
                if result.get('block_for_configured'):
                    print(f"    Block duration: {'✓' if result.get('block_duration_compliant') else '✗'} ({result.get('block_seconds')}s)")
                    print(f"    Max attempts: {'✓' if result.get('attempts_compliant') else '✗'} ({result.get('attempts')})")
                    print(f"    Time window: {'✓' if result.get('within_compliant') else '✗'} ({result.get('within_seconds')}s)")


if __name__ == "__main__":
    test_login_block_for_configured()
