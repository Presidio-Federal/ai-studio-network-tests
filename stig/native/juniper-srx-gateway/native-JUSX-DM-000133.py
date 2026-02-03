"""
STIG ID: JUSX-DM-000133
Finding ID: V-223222
Rule ID: SV-223222r1015757_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000169-NDM-000257

Rule Title: For local accounts using password authentication (i.e., the root account 
            and the account of last resort), the Juniper SRX Services Gateway must 
            enforce password complexity by requiring at least one special character 
            be used.

Discussion:
Use of a complex password helps to increase the time and resources required to 
compromise the password. Password complexity, or strength, is a measure of the 
effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to 
crack a password. The more complex the password, the greater the number of possible 
combinations that need to be tested before the password is compromised.

Special characters (punctuation marks) significantly increase password entropy:
- 8-character password with lowercase only: 26^8 = 208 billion combinations
- 8-character with lowercase + special chars: 62^8 = 218 trillion combinations
- Adding just one special character increases complexity by ~1000x

Check Text:
Verify the default local password enforces password complexity by requiring at least 
one special character be used.

[edit]
show system login password

If the minimum-punctuation is not set to at least 1, this is a finding.

Fix Text:
Configure the default local password to enforce password complexity by requiring at 
least one special character be used.

[edit]
set system login password minimum-punctuations 1

References:
CCI: CCI-004066: For password-based authentication, enforce organization-defined 
                 composition and complexity rules.
NIST SP 800-53 Revision 5 :: IA-5 (1) (h)

CCI: CCI-001619: The information system enforces password complexity by the minimum 
                 number of special characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223222
Rule ID: SV-223222r1015757_rule
STIG ID: JUSX-DM-000133
Severity: CAT II
Classification: Unclass
Legacy IDs: V-66525; SV-81015
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000133"
FINDING_ID = "V-223222"
RULE_ID = "SV-223222r1015757_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Minimum special characters required
MIN_PUNCTUATIONS_REQUIRED = 1


def load_test_data(file_path):
    """Load test data from JSON or YAML file (Native Juniper format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Juniper native JSON format
    # Expected structure: {"configuration": {...}}
    if isinstance(data, dict) and 'configuration' in data:
        # Extract hostname if available
        hostname = data.get('configuration', {}).get('system', {}).get('host-name', 'unknown-device')
        return {hostname: data}
    
    # If data is already wrapped with device names
    return data


def test_password_complexity_special_characters():
    """
    Test that password complexity requires at least one special character.
    
    STIG JUSX-DM-000133 requires that local account passwords enforce complexity 
    by requiring at least one special character (punctuation mark). This significantly 
    increases password strength and resistance to brute-force attacks.
    
    This test validates:
    1. Password minimum-punctuations is configured
    2. Minimum is set to at least 1
    
    Password complexity reduces risk of:
    - Dictionary attacks
    - Brute-force attacks
    - Password guessing
    - Credential compromise
    
    Native extraction method: Tests against native Juniper CLI/API JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('configuration', {})
            
            punctuations_configured = False
            minimum_punctuations = None
            
            # Check password configuration
            # Path: configuration.system.login.password.minimum-punctuations
            system_config = config.get('system', {})
            login_config = system_config.get('login', {})
            password_config = login_config.get('password', {})
            
            if password_config and 'minimum-punctuations' in password_config:
                punctuations_configured = True
                minimum_punctuations = password_config.get('minimum-punctuations')
            
            # Determine compliance
            # Must have minimum-punctuations configured AND >= 1
            overall_compliant = (
                punctuations_configured and 
                minimum_punctuations is not None and 
                minimum_punctuations >= MIN_PUNCTUATIONS_REQUIRED
            )
            
            results[device_name] = {
                'punctuations_configured': punctuations_configured,
                'minimum_punctuations': minimum_punctuations,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not punctuations_configured:
                    error_parts.append("  Password minimum-punctuations is NOT configured")
                elif minimum_punctuations is None:
                    error_parts.append("  Password minimum-punctuations value is None/missing")
                elif minimum_punctuations < MIN_PUNCTUATIONS_REQUIRED:
                    error_parts.append(f"  Password minimum-punctuations is {minimum_punctuations} (less than required {MIN_PUNCTUATIONS_REQUIRED})")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without special character requirements, passwords are weak")
                error_parts.append("  and vulnerable to dictionary and brute-force attacks.")
                error_parts.append("\nPassword Complexity Impact:")
                error_parts.append("  8-char lowercase only:     26^8  = 208 billion combinations")
                error_parts.append("  8-char + special chars:    62^8  = 218 trillion combinations")
                error_parts.append("  Improvement:               ~1,000x stronger")
                error_parts.append("\nSecurity Risks:")
                error_parts.append("  - Dictionary attacks succeed against simple passwords")
                error_parts.append("  - Brute-force attacks complete faster")
                error_parts.append("  - Increased risk of credential compromise")
                error_parts.append("  - Root and administrative account exposure")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password minimum-punctuations 1")
                error_parts.append("  commit")
                error_parts.append("\nNote:")
                error_parts.append("  This applies to all local accounts including root and")
                error_parts.append("  account of last resort.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking password complexity on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Password complexity - special characters required")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Minimum punctuations: {result.get('minimum_punctuations')}")
            print(f"  Requirement: >= {MIN_PUNCTUATIONS_REQUIRED}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Password complexity enforced")
        else:
            if 'error' not in result:
                print(f"  Punctuations configured: {'Yes' if result.get('punctuations_configured') else 'No'}")
                if result.get('minimum_punctuations') is not None:
                    print(f"  Current minimum: {result.get('minimum_punctuations')}")
                print(f"  Required minimum: {MIN_PUNCTUATIONS_REQUIRED}")


if __name__ == "__main__":
    test_password_complexity_special_characters()
