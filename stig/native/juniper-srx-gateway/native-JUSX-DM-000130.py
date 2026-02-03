"""
STIG ID: JUSX-DM-000130
Finding ID: V-223219
Rule ID: SV-223219r1015754_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000166-NDM-000254

Rule Title: For local accounts using password authentication (i.e., the root account 
            and the account of last resort), the Juniper SRX Services Gateway must 
            enforce password complexity by requiring at least one uppercase character 
            be used.

Discussion:
Use of a complex password helps to increase the time and resources required to 
compromise the password. Password complexity, or strength, is a measure of the 
effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to 
crack a password. The more complex the password, the greater the number of possible 
combinations that need to be tested before the password is compromised.

Uppercase character requirements:
- Prevent all-lowercase or all-numeric passwords
- Increase character set diversity alongside lowercase requirements
- Make pattern-based attacks less effective
- Combined with lowercase, numeric, and special character requirements, create 
  strong multi-dimensional passwords

Password entropy with character type requirements:
- Each additional character type requirement exponentially increases entropy
- Uppercase + lowercase: 52 possible characters per position
- All four types (upper, lower, numeric, special): 94+ characters per position
- For 8-character password: 94^8 = 6 quadrillion combinations

Check Text:
Verify the default local password enforces password complexity by requiring at least 
one uppercase character be used.

[edit]
show system login password

If the minimum uppercase characters are not set to at least 1, this is a finding.

Fix Text:
Configure the default local password to enforce password complexity by requiring at 
least one uppercase character be used.

[edit]
set system login password minimum-upper-cases 1

References:
CCI: CCI-004066: For password-based authentication, enforce organization-defined 
                 composition and complexity rules.
NIST SP 800-53 Revision 5 :: IA-5 (1) (h)

CCI: CCI-000192: The information system enforces password complexity by the minimum 
                 number of upper case characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223219
Rule ID: SV-223219r1015754_rule
STIG ID: JUSX-DM-000130
Severity: CAT II
Classification: Unclass
Legacy IDs: V-66519; SV-81009
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000130"
FINDING_ID = "V-223219"
RULE_ID = "SV-223219r1015754_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Minimum uppercase characters required
MIN_UPPERCASE_REQUIRED = 1


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


def test_password_complexity_uppercase_characters():
    """
    Test that password complexity requires at least one uppercase character.
    
    STIG JUSX-DM-000130 requires that local account passwords enforce complexity 
    by requiring at least one uppercase character. This increases character set 
    diversity and password entropy, making brute-force and dictionary attacks 
    significantly more difficult.
    
    This test validates:
    1. Password minimum-upper-cases is configured
    2. Minimum is set to at least 1
    
    Uppercase character requirements prevent:
    - All-lowercase passwords
    - All-numeric passwords
    - Limited character set passwords
    - Simple dictionary word passwords (most are lowercase)
    
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
            
            uppercase_configured = False
            minimum_uppercase = None
            
            # Check password configuration
            # Path: configuration.system.login.password.minimum-upper-cases
            system_config = config.get('system', {})
            login_config = system_config.get('login', {})
            password_config = login_config.get('password', {})
            
            if password_config and 'minimum-upper-cases' in password_config:
                uppercase_configured = True
                minimum_uppercase = password_config.get('minimum-upper-cases')
            
            # Determine compliance
            # Must have minimum-upper-cases configured AND >= 1
            overall_compliant = (
                uppercase_configured and 
                minimum_uppercase is not None and 
                minimum_uppercase >= MIN_UPPERCASE_REQUIRED
            )
            
            results[device_name] = {
                'uppercase_configured': uppercase_configured,
                'minimum_uppercase': minimum_uppercase,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not uppercase_configured:
                    error_parts.append("  Password minimum-upper-cases is NOT configured")
                elif minimum_uppercase is None:
                    error_parts.append("  Password minimum-upper-cases value is None/missing")
                elif minimum_uppercase < MIN_UPPERCASE_REQUIRED:
                    error_parts.append(f"  Password minimum-upper-cases is {minimum_uppercase} (less than required {MIN_UPPERCASE_REQUIRED})")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without uppercase character requirements, passwords have reduced")
                error_parts.append("  character set diversity and are vulnerable to attacks.")
                error_parts.append("\nPassword Entropy with Character Type Requirements:")
                error_parts.append("  Lowercase only (26):              26^8  = 209 billion combinations")
                error_parts.append("  Lowercase + uppercase (52):       52^8  = 53 trillion combinations")
                error_parts.append("  + numeric (62):                   62^8  = 218 trillion combinations")
                error_parts.append("  + special chars (94):             94^8  = 6 quadrillion combinations")
                error_parts.append("\nSecurity Risks:")
                error_parts.append("  - All-lowercase passwords are common dictionary words")
                error_parts.append("  - Limited character sets enable faster brute-force")
                error_parts.append("  - Passwords like 'welcome123!' are vulnerable")
                error_parts.append("  - Root and administrative accounts at higher risk")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password minimum-upper-cases 1")
                error_parts.append("  commit")
                error_parts.append("\nBest Practice - Complete Password Policy:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password minimum-length 15")
                error_parts.append("  set system login password minimum-upper-cases 1")
                error_parts.append("  set system login password minimum-lower-cases 1")
                error_parts.append("  set system login password minimum-numerics 1")
                error_parts.append("  set system login password minimum-punctuations 1")
                error_parts.append("  set system login password format sha256")
                error_parts.append("  set system login password maximum-length 128")
                error_parts.append("  set system login password change-type character-sets")
                error_parts.append("  commit")
                error_parts.append("\nNote: This configuration enforces all four character type requirements,")
                error_parts.append("      creating passwords with 94+ character diversity and maximum entropy.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking password uppercase requirements on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Password complexity - uppercase characters required")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Minimum uppercase: {result.get('minimum_uppercase')}")
            print(f"  Requirement: >= {MIN_UPPERCASE_REQUIRED}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Password uppercase complexity enforced")
        else:
            if 'error' not in result:
                print(f"  Uppercase configured: {'Yes' if result.get('uppercase_configured') else 'No'}")
                if result.get('minimum_uppercase') is not None:
                    print(f"  Current minimum: {result.get('minimum_uppercase')}")
                print(f"  Required minimum: {MIN_UPPERCASE_REQUIRED}")


if __name__ == "__main__":
    test_password_complexity_uppercase_characters()
