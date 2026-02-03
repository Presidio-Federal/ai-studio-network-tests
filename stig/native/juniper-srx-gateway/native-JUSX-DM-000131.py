"""
STIG ID: JUSX-DM-000131
Finding ID: V-223220
Rule ID: SV-223220r1015755_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000167-NDM-000255

Rule Title: For local accounts using password authentication (i.e., the root account 
            and the account of last resort), the Juniper SRX Services Gateway must 
            enforce password complexity by requiring at least one lowercase character 
            be used.

Discussion:
Use of a complex password helps to increase the time and resources required to 
compromise the password. Password complexity, or strength, is a measure of the 
effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to 
crack a password. The more complex the password, the greater the number of possible 
combinations that need to be tested before the password is compromised.

Lowercase character requirements:
- Prevent all-uppercase or all-numeric passwords
- Increase character set diversity
- Make pattern-based attacks less effective
- Combined with uppercase, numeric, and special character requirements, create 
  strong multi-dimensional passwords

Password character set expansion:
- Uppercase only: 26 characters
- Uppercase + lowercase: 52 characters
- Uppercase + lowercase + numbers: 62 characters
- Uppercase + lowercase + numbers + specials: 94+ characters

Check Text:
Verify the default local password enforces password complexity by requiring at least 
one lowercase character be used.

[edit]
show system login password

If the minimum lowercase characters are not set to at least 1, this is a finding.

Fix Text:
Configure the default local password to enforce password complexity by requiring at 
least one lowercase character be used.

[edit]
set system login password minimum-lower-cases 1

References:
CCI: CCI-004066: For password-based authentication, enforce organization-defined 
                 composition and complexity rules.
NIST SP 800-53 Revision 5 :: IA-5 (1) (h)

CCI: CCI-000193: The information system enforces password complexity by the minimum 
                 number of lower case characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223220
Rule ID: SV-223220r1015755_rule
STIG ID: JUSX-DM-000131
Severity: CAT II
Classification: Unclass
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000131"
FINDING_ID = "V-223220"
RULE_ID = "SV-223220r1015755_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Minimum lowercase characters required
MIN_LOWERCASE_REQUIRED = 1


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


def test_password_complexity_lowercase_characters():
    """
    Test that password complexity requires at least one lowercase character.
    
    STIG JUSX-DM-000131 requires that local account passwords enforce complexity 
    by requiring at least one lowercase character. This increases character set 
    diversity and password entropy, making brute-force and dictionary attacks 
    significantly more difficult.
    
    This test validates:
    1. Password minimum-lower-cases is configured
    2. Minimum is set to at least 1
    
    Lowercase character requirements prevent:
    - All-uppercase passwords
    - All-numeric passwords
    - Limited character set passwords
    - Simple pattern-based passwords
    
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
            
            lowercase_configured = False
            minimum_lowercase = None
            
            # Check password configuration
            # Path: configuration.system.login.password.minimum-lower-cases
            system_config = config.get('system', {})
            login_config = system_config.get('login', {})
            password_config = login_config.get('password', {})
            
            if password_config and 'minimum-lower-cases' in password_config:
                lowercase_configured = True
                minimum_lowercase = password_config.get('minimum-lower-cases')
            
            # Determine compliance
            # Must have minimum-lower-cases configured AND >= 1
            overall_compliant = (
                lowercase_configured and 
                minimum_lowercase is not None and 
                minimum_lowercase >= MIN_LOWERCASE_REQUIRED
            )
            
            results[device_name] = {
                'lowercase_configured': lowercase_configured,
                'minimum_lowercase': minimum_lowercase,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not lowercase_configured:
                    error_parts.append("  Password minimum-lower-cases is NOT configured")
                elif minimum_lowercase is None:
                    error_parts.append("  Password minimum-lower-cases value is None/missing")
                elif minimum_lowercase < MIN_LOWERCASE_REQUIRED:
                    error_parts.append(f"  Password minimum-lower-cases is {minimum_lowercase} (less than required {MIN_LOWERCASE_REQUIRED})")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without lowercase character requirements, passwords have reduced")
                error_parts.append("  character set diversity and are vulnerable to attacks.")
                error_parts.append("\nPassword Character Set Expansion:")
                error_parts.append("  Uppercase only:                      26 characters")
                error_parts.append("  Uppercase + lowercase:               52 characters (2x)")
                error_parts.append("  Uppercase + lowercase + numbers:     62 characters (2.4x)")
                error_parts.append("  All character types + specials:      94+ characters (3.6x)")
                error_parts.append("\nSecurity Risks:")
                error_parts.append("  - All-uppercase passwords are predictable")
                error_parts.append("  - Limited character sets enable faster brute-force")
                error_parts.append("  - Passwords like 'PASSWORD123!' are vulnerable")
                error_parts.append("  - Root and administrative accounts at higher risk")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password minimum-lower-cases 1")
                error_parts.append("  commit")
                error_parts.append("\nBest Practice - Complete Password Policy:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password minimum-lower-cases 1")
                error_parts.append("  set system login password minimum-upper-cases 1")
                error_parts.append("  set system login password minimum-numerics 1")
                error_parts.append("  set system login password minimum-punctuations 1")
                error_parts.append("  set system login password minimum-length 15")
                error_parts.append("  set system login password format sha256")
                error_parts.append("  commit")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking password lowercase requirements on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Password complexity - lowercase characters required")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Minimum lowercase: {result.get('minimum_lowercase')}")
            print(f"  Requirement: >= {MIN_LOWERCASE_REQUIRED}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Password lowercase complexity enforced")
        else:
            if 'error' not in result:
                print(f"  Lowercase configured: {'Yes' if result.get('lowercase_configured') else 'No'}")
                if result.get('minimum_lowercase') is not None:
                    print(f"  Current minimum: {result.get('minimum_lowercase')}")
                print(f"  Required minimum: {MIN_LOWERCASE_REQUIRED}")


if __name__ == "__main__":
    test_password_complexity_lowercase_characters()
