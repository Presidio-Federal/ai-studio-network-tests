"""
HIPAA ID: HIPAA-PA-004
Rule: Account Lockout
Severity: High
Classification: HIPAA Security Rule § 164.312(a)(2)(i)

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The network device must enforce account lockout after a maximum of 5 consecutive failed login attempts.

Discussion:
HIPAA Security Rule requires procedures to verify that a person or entity seeking access 
to electronic protected health information (ePHI) is the one claimed. Account lockout 
after consecutive failed login attempts is a critical security control that protects 
against brute-force password attacks and unauthorized access attempts.

Limiting failed login attempts to 5 or fewer aligns with HIPAA security best practices 
and protects against automated password guessing attacks. The lockout period should be 
substantial enough to deter attacks while allowing legitimate users to regain access 
after a reasonable cooling-off period.

Check Text:
Review the router configuration to verify that login block-for is configured with:
- Maximum 5 failed attempts
- Within a reasonable window (e.g., 60-120 seconds)
- Block duration of at least 300 seconds (5 minutes) or 900 seconds (15 minutes)

The configuration should look similar to:

login block-for 900 attempts 3 within 120

If account lockout is not configured or allows more than 5 attempts, this is a finding.

Fix Text:
Configure login block-for to enforce account lockout:

R1(config)# login block-for 900 attempts 3 within 120
R1(config)# login on-failure log
R1(config)# login on-success log
R1(config)# end

This configuration locks out access for 900 seconds (15 minutes) after 3 failed attempts within 120 seconds.

References:
HIPAA Security Rule: § 164.312(a)(2)(i) - Unique User Identification (implies authentication controls)
HIPAA Security Rule: § 164.312(d) - Person or Entity Authentication
NIST SP 800-53 Rev 5: AC-7 (Unsuccessful Logon Attempts)
45 CFR 164.312(a)(2)(i), 164.312(d)
"""

import os
import json
import yaml
import pytest

HIPAA_ID = "HIPAA-PA-004"
RULE_TITLE = "Account Lockout"
SEVERITY = "High"
CATEGORY = "HIPAA"
FRAMEWORK = "HIPAA Security Rule"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
HIPAA_REFERENCE = "45 CFR § 164.312(a)(2)(i), § 164.312(d)"

MAX_FAILED_ATTEMPTS = 5
MIN_BLOCK_DURATION_SECONDS = 300  # 5 minutes


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


def test_account_lockout():
    """
    Test that account lockout is configured to protect against brute-force attacks.
    
    HIPAA § 164.312(a)(2)(i) and § 164.312(d) require authentication controls including 
    protection against unauthorized access attempts.
    
    The test validates that:
    1. Login block-for is configured
    2. Failed attempts threshold is ≤ 5
    3. Block duration is ≥ 300 seconds (5 minutes)
    4. Failed login logging is enabled
    
    This ensures compliance with HIPAA's authentication and access control requirements.
    
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
            
            # Initialize compliance flags
            block_for_configured = False
            block_duration_seconds = None
            attempts = None
            within_seconds = None
            attempts_compliant = False
            block_duration_compliant = False
            failed_login_logging = False
            
            # Check login configuration
            # Path: login -> block-for
            login_config = config.get('tailf-ned-cisco-ios:login', {})
            
            if login_config:
                # Check block-for
                block_for = login_config.get('block-for', {})
                if block_for:
                    block_for_configured = True
                    block_duration_seconds = block_for.get('seconds', 0)
                    attempts = block_for.get('attempts', 0)
                    within_seconds = block_for.get('within', 0)
                    
                    # Check compliance
                    attempts_compliant = (attempts > 0 and attempts <= MAX_FAILED_ATTEMPTS)
                    block_duration_compliant = (block_duration_seconds >= MIN_BLOCK_DURATION_SECONDS)
                
                # Check on-failure logging
                on_failure = login_config.get('on-failure', {})
                if on_failure and 'log' in on_failure:
                    failed_login_logging = True
            
            # Overall compliance
            overall_compliant = (
                block_for_configured and
                attempts_compliant and
                block_duration_compliant and
                failed_login_logging
            )
            
            results[device_name] = {
                'block_for_configured': block_for_configured,
                'block_duration_seconds': block_duration_seconds,
                'attempts': attempts,
                'within_seconds': within_seconds,
                'attempts_compliant': attempts_compliant,
                'block_duration_compliant': block_duration_compliant,
                'failed_login_logging': failed_login_logging,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with HIPAA {HIPAA_ID}:"]
                
                if not block_for_configured:
                    error_parts.append("  ✗ Login block-for is NOT configured")
                else:
                    if not attempts_compliant:
                        if attempts == 0:
                            error_parts.append(f"  ✗ Failed attempts threshold not configured")
                        else:
                            error_parts.append(f"  ✗ Failed attempts threshold ({attempts}) exceeds maximum ({MAX_FAILED_ATTEMPTS})")
                    
                    if not block_duration_compliant:
                        if block_duration_seconds == 0:
                            error_parts.append(f"  ✗ Block duration not configured")
                        else:
                            error_parts.append(f"  ✗ Block duration ({block_duration_seconds}s) is less than minimum ({MIN_BLOCK_DURATION_SECONDS}s)")
                
                if not failed_login_logging:
                    error_parts.append("  ✗ Failed login logging is NOT enabled")
                
                error_parts.append("\nHIPAA requires account lockout to protect against brute-force attacks!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# login block-for 900 attempts 3 within 120")
                error_parts.append("  R1(config)# login on-failure log")
                error_parts.append("  R1(config)# login on-success log")
                error_parts.append("  R1(config)# end")
                error_parts.append(f"\nAccount will lock for 900 seconds after 3 failed attempts within 120 seconds.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking login block-for on {device_name}: {e}"
    
    # Print summary
    print("\nHIPAA Compliance Summary:")
    print(f"HIPAA ID: {HIPAA_ID}")
    print(f"Rule: {RULE_TITLE}")
    print(f"Reference: {HIPAA_REFERENCE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Maximum Failed Attempts: {MAX_FAILED_ATTEMPTS}")
    print(f"Minimum Block Duration: {MIN_BLOCK_DURATION_SECONDS} seconds")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Login block-for configured")
            print(f"  ✓ Block duration: {result['block_duration_seconds']} seconds")
            print(f"  ✓ Failed attempts: {result['attempts']} (within {result['within_seconds']}s)")
            print(f"  ✓ Failed login logging enabled")
            print(f"  ✓ HIPAA account lockout requirement satisfied")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Block-for configured: {'✓' if result.get('block_for_configured') else '✗'}")
                if result.get('block_for_configured'):
                    print(f"  Block duration: {result.get('block_duration_seconds', 0)}s (min: {MIN_BLOCK_DURATION_SECONDS}s)")
                    print(f"  Attempts: {result.get('attempts', 0)} (max: {MAX_FAILED_ATTEMPTS})")
                    print(f"  Within: {result.get('within_seconds', 0)}s")
                print(f"  Failed login logging: {'✓' if result.get('failed_login_logging') else '✗'}")


if __name__ == "__main__":
    test_account_lockout()
