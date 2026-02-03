"""
STIG ID: JUSX-DM-000136
Finding ID: V-223223
Rule ID: SV-223223r1056174_rule
Version: 3, Release: 3
Severity: CAT I (High)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000172-NDM-000259

Rule Title: The Juniper SRX Services Gateway must use the SHA256 or later protocol 
            for password authentication for local accounts using password authentication 
            (i.e., the root account and the account of last resort).

Discussion:
Passwords must be protected at all times, and encryption is the standard method for 
protecting passwords. If passwords are not encrypted, they can be plainly read 
(i.e., clear text) and easily compromised.

Modern cryptographic hash functions like SHA-256, SHA-512, and bcrypt provide strong 
protection for stored passwords. Older algorithms like MD5 and SHA-1 are vulnerable 
to collision attacks and should not be used.

Juniper password format options:
- sha256: Uses SHA-256 hashing (approved)
- sha512: Uses SHA-512 hashing (approved, stronger than SHA-256)
- sha1: Uses SHA-1 hashing (deprecated, not approved)
- md5: Uses MD5 hashing (deprecated, not approved)

Check Text:
Verify the default local password enforces this requirement by entering the following 
in configuration mode.

[edit]
show system login password

If the password format is not set to SHA256 or higher, this is a finding.

Fix Text:
Enter the following example command from the configuration mode.

[edit]
set system login password format sha256

Note: sha512 is also acceptable and provides stronger protection.

References:
CCI: CCI-000197: For password-based authentication, transmit passwords only 
                 cryptographically-protected channels.
NIST SP 800-53 :: IA-5 (1) (c)
NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
NIST SP 800-53 Revision 5 :: IA-5 (1) (c)
NIST SP 800-53A :: IA-5 (1).1 (v)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223223
Rule ID: SV-223223r1056174_rule
STIG ID: JUSX-DM-000136
Severity: CAT I
Classification: Unclass
Legacy IDs: V-66527; SV-81017
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000136"
FINDING_ID = "V-223223"
RULE_ID = "SV-223223r1056174_rule"
SEVERITY = "CAT I"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Approved password formats (SHA-256 or later)
APPROVED_FORMATS = [
    "sha256",  # SHA-256 (approved minimum)
    "sha512",  # SHA-512 (approved, stronger)
]

# Deprecated/weak formats (not acceptable)
DEPRECATED_FORMATS = [
    "sha1",    # SHA-1 (vulnerable to collision attacks)
    "md5"      # MD5 (broken, not secure)
]


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


def test_password_format_sha256():
    """
    Test that password format is set to SHA256 or higher for cryptographic protection.
    
    STIG JUSX-DM-000136 (CAT I - HIGH) requires that the Juniper SRX Services Gateway 
    use SHA-256 or stronger cryptographic hashing for local password storage to prevent 
    password compromise.
    
    This test validates:
    1. Password format is configured
    2. Format uses SHA-256 or stronger (sha256, sha512)
    3. Deprecated formats (md5, sha1) are not used
    
    Weak password hashing can lead to:
    - Password cracking through brute-force attacks
    - Rainbow table attacks
    - Collision attacks (for MD5/SHA-1)
    - Unauthorized system access
    
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
            
            password_format_configured = False
            password_format = None
            format_approved = False
            
            # Check password format configuration
            # Path: configuration.system.login.password.format
            system_config = config.get('system', {})
            login_config = system_config.get('login', {})
            password_config = login_config.get('password', {})
            
            if password_config and 'format' in password_config:
                password_format_configured = True
                password_format = password_config.get('format')
                
                # Check if format is approved
                if password_format in APPROVED_FORMATS:
                    format_approved = True
            
            # Determine compliance
            # Must have password format configured AND use approved algorithm
            overall_compliant = password_format_configured and format_approved
            
            results[device_name] = {
                'password_format_configured': password_format_configured,
                'password_format': password_format,
                'format_approved': format_approved,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not password_format_configured:
                    error_parts.append("  Password format is NOT configured")
                elif not format_approved:
                    error_parts.append(f"  Password format '{password_format}' is NOT approved")
                    if password_format in DEPRECATED_FORMATS:
                        error_parts.append(f"  WARNING: {password_format.upper()} is deprecated and vulnerable!")
                
                error_parts.append("\nCAT I - HIGH SEVERITY FINDING:")
                error_parts.append("  Weak password hashing exposes the system to password compromise.")
                error_parts.append("\nSecurity Risks:")
                error_parts.append("  - Password cracking through brute-force attacks")
                error_parts.append("  - Rainbow table attacks against weak hashes")
                error_parts.append("  - Collision attacks (MD5/SHA-1)")
                error_parts.append("  - Unauthorized root and administrative access")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system login password format sha256")
                error_parts.append("  commit")
                error_parts.append("\nApproved password formats:")
                for fmt in APPROVED_FORMATS:
                    strength = "minimum required" if fmt == "sha256" else "stronger, recommended"
                    error_parts.append(f"  - {fmt} ({strength})")
                error_parts.append("\nDeprecated formats (DO NOT USE):")
                for fmt in DEPRECATED_FORMATS:
                    error_parts.append(f"  - {fmt} (vulnerable, not approved)")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking password format on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY} - HIGH")
    print(f"Title: SHA-256 or higher password format")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Password format: {result.get('password_format')}")
            print(f"  Format approved: Yes")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Strong cryptographic password protection enabled")
        else:
            if 'error' not in result:
                print(f"  Format configured: {'Yes' if result.get('password_format_configured') else 'No'}")
                if result.get('password_format'):
                    print(f"  Current format: {result.get('password_format')}")
                    if result.get('password_format') in DEPRECATED_FORMATS:
                        print(f"  WARNING: {result.get('password_format').upper()} IS VULNERABLE!")
                print(f"  Required: sha256 or sha512")


if __name__ == "__main__":
    test_password_format_sha256()
