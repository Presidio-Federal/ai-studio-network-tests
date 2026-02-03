"""
STIG ID: CISC-ND-000160
Finding ID: V-215669
Rule ID: SV-215669r960843_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96027; SV-105165

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Group Title: SRG-APP-000068-NDM-000215

Rule Title: The Cisco router must be configured to display the Standard Mandatory DoD Notice 
and Consent Banner before granting access to the device.

Discussion:
Display of the DoD-approved use notification before granting access to the network device 
ensures privacy and security notification verbiage used is consistent with applicable federal 
laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users 
and are not required when such human interfaces do not exist. This requirement applies to 
network elements that have the concept of a user account and have the logon function residing 
on the network element.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for 
network elements that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for 
USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the 
following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, 
but not limited to, penetration testing, COMSEC monitoring, network operations and defense, 
personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine 
monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect 
USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI 
investigative searching or monitoring of the content of privileged communications, or work 
product, related to personal representation or services by attorneys, psychotherapists, or 
clergy, and their assistants. Such communications and work product are private and confidential. 
See User Agreement for details."

Check Text:
Review the router configuration to verify that the Standard Mandatory DoD Notice and Consent 
Banner is displayed before granting access to the device.

The banner must contain key phrases from the DoD-approved banner, including:
- "U.S. Government (USG) Information System (IS)"
- "USG-authorized use only"
- "consent"
- "monitor"

banner login ^C
You are accessing a U.S. Government (USG) Information System (IS)...
^C

If the router does not display the Standard Mandatory DoD Notice and Consent Banner before 
granting access, this is a finding.

Fix Text:
Configure the router to display the Standard Mandatory DoD Notice and Consent Banner before 
granting access to the device.

R1(config)# banner login ^C
You are accessing a U.S. Government (USG) Information System (IS) that is provided for 
USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the 
following conditions:
[...full banner text...]
^C
R1(config)# end

References:
CCI: CCI-000048
NIST SP 800-53 :: AC-8 a
NIST SP 800-53 Revision 4 :: AC-8 a
NIST SP 800-53 Revision 5 :: AC-8 a
NIST SP 800-53A :: AC-8.1 (ii)
"""

import os
import json
import yaml
import pytest
import re

STIG_ID = "CISC-ND-000160"
FINDING_ID = "V-215669"
RULE_ID = "SV-215669r960843_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must display Standard Mandatory DoD Notice and Consent Banner"

# Key phrases that must be present in the DoD banner
REQUIRED_BANNER_PHRASES = [
    r"U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)",
    r"USG-authorized\s+use\s+only",
    r"consent",
    r"monitor"
]


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
    # Native IOS-XE format: Cisco-IOS-XE-native:native
    if isinstance(data, dict) and 'Cisco-IOS-XE-native:native' in data:
        config = data['Cisco-IOS-XE-native:native']
        device_name = config.get('hostname', 'unknown-device')
        return {device_name: {'config': config}}
    
    # NSO wrapped format: tailf-ncs:config
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'config': config, 'format': 'nso'}}
    
    # Direct NSO format
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'config': data, 'format': 'nso'}}
    
    return data


def check_banner_content(banner_text):
    """
    Check if banner contains required DoD notice phrases.
    Returns: (is_compliant, missing_phrases, found_phrases)
    """
    if not banner_text:
        return False, REQUIRED_BANNER_PHRASES, []
    
    # Normalize whitespace for matching
    normalized_banner = ' '.join(banner_text.split())
    
    missing_phrases = []
    found_phrases = []
    
    for phrase_pattern in REQUIRED_BANNER_PHRASES:
        if re.search(phrase_pattern, normalized_banner, re.IGNORECASE):
            found_phrases.append(phrase_pattern)
        else:
            missing_phrases.append(phrase_pattern)
    
    is_compliant = len(missing_phrases) == 0
    
    return is_compliant, missing_phrases, found_phrases


def test_dod_banner():
    """
    Test that the Standard Mandatory DoD Notice and Consent Banner is configured.
    
    STIG V-215669 (CISC-ND-000160) requires that the router displays the Standard 
    Mandatory DoD Notice and Consent Banner before granting access to the device.
    
    The test validates that:
    1. A login banner is configured
    2. The banner contains required DoD notice key phrases:
       - "U.S. Government (USG) Information System (IS)"
       - "USG-authorized use only"
       - "consent"
       - "monitor"
    
    This ensures users are properly notified of monitoring and acceptable use policies
    before accessing the system.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('config', {})
            data_format = device_data.get('format', 'native')
            
            # Initialize compliance flags
            banner_configured = False
            banner_text = None
            banner_compliant = False
            missing_phrases = []
            found_phrases = []
            
            # Check banner configuration
            if data_format == 'native':
                # Native format: banner -> login -> banner
                banner_config = config.get('banner', {})
                login_banner = banner_config.get('login', {})
                if login_banner:
                    banner_text = login_banner.get('banner', '')
                    banner_configured = bool(banner_text)
            else:
                # NSO format: tailf-ned-cisco-ios:banner -> login -> banner
                banner_config = config.get('tailf-ned-cisco-ios:banner', {})
                login_banner = banner_config.get('login', {})
                if login_banner:
                    banner_text = login_banner.get('banner', '')
                    banner_configured = bool(banner_text)
            
            # Check banner content if configured
            if banner_configured and banner_text:
                banner_compliant, missing_phrases, found_phrases = check_banner_content(banner_text)
            
            # Overall compliance
            overall_compliant = banner_configured and banner_compliant
            
            results[device_name] = {
                'banner_configured': banner_configured,
                'banner_compliant': banner_compliant,
                'banner_length': len(banner_text) if banner_text else 0,
                'missing_phrases': missing_phrases,
                'found_phrases': found_phrases,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not banner_configured:
                    error_parts.append("  ✗ Login banner is NOT configured")
                elif not banner_compliant:
                    error_parts.append("  ✗ Banner does NOT contain all required DoD notice phrases")
                    error_parts.append("\n  Missing required phrases:")
                    for phrase in missing_phrases:
                        # Remove regex escaping for display
                        display_phrase = phrase.replace(r'\s+', ' ').replace(r'\.', '.')
                        error_parts.append(f"    - {display_phrase}")
                    
                    if found_phrases:
                        error_parts.append("\n  Found phrases:")
                        for phrase in found_phrases:
                            display_phrase = phrase.replace(r'\s+', ' ').replace(r'\.', '.')
                            error_parts.append(f"    ✓ {display_phrase}")
                
                error_parts.append("\nStandard Mandatory DoD Notice and Consent Banner is required!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# banner login ^C")
                error_parts.append("  You are accessing a U.S. Government (USG) Information System (IS)")
                error_parts.append("  that is provided for USG-authorized use only.")
                error_parts.append("")
                error_parts.append("  By using this IS (which includes any device attached to this IS),")
                error_parts.append("  you consent to the following conditions:")
                error_parts.append("  [...]")
                error_parts.append("  ^C")
                error_parts.append("  R1(config)# end")
                error_parts.append("\nBanner must contain:")
                error_parts.append("  - 'U.S. Government (USG) Information System (IS)'")
                error_parts.append("  - 'USG-authorized use only'")
                error_parts.append("  - 'consent'")
                error_parts.append("  - 'monitor'")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking banner configuration on {device_name}: {e}"
    
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
            print(f"  ✓ Login banner configured ({result['banner_length']} characters)")
            print(f"  ✓ Banner contains all required DoD notice phrases:")
            for phrase in result.get('found_phrases', []):
                display_phrase = phrase.replace(r'\s+', ' ').replace(r'\.', '.')
                print(f"    ✓ {display_phrase}")
            print(f"  ✓ Standard Mandatory DoD Notice and Consent Banner requirement satisfied")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Banner configured: {'✓' if result.get('banner_configured') else '✗'}")
                if result.get('banner_configured'):
                    print(f"  Banner length: {result['banner_length']} characters")
                    print(f"  Banner compliant: {'✓' if result.get('banner_compliant') else '✗'}")
                    if result.get('missing_phrases'):
                        print(f"  Missing phrases: {len(result['missing_phrases'])}")


if __name__ == "__main__":
    test_dod_banner()
