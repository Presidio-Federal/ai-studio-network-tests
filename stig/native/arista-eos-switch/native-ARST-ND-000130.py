"""
STIG ID: ARST-ND-000130
Finding ID: V-255950
Rule ID: SV-255950r960843_rule
Severity: CAT II (Medium)
Classification: Unclass
Group Title: SRG-APP-000068-NDM-000215

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista network device must display the Standard Mandatory DOD Notice and Consent 
Banner before granting access to the device.

Discussion:
Display of the DOD-approved use notification before granting access to the network device ensures 
privacy and security notification verbiage used is consistent with applicable federal laws, 
Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users. The 
banner must inform users that:
- They are accessing a U.S. Government system
- Use is monitored and recorded
- Unauthorized use is prohibited
- There is no expectation of privacy

Satisfies: SRG-APP-000068-NDM-000215, SRG-APP-000069-NDM-000216

Check Text:
Verify the Arista network device is configured to present a DOD-approved banner that is formatted 
in accordance with DTM-08-060.

banner login
<DOD-approved banner text>
EOF

If the device does not display a DOD-approved banner before granting access, this is a finding.

Fix Text:
Configure the Arista network device to display the Standard Mandatory DOD Notice and Consent Banner 
before granting access to the device.

switch(config)# banner login
Enter TEXT message. 
<Insert banner here>
Type 'EOF' on its own line to end.

Example DOD-approved banner:
You are accessing a U.S. Government (USG) Information System (IS) that is provided for 
USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following 
conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but 
not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel 
misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine 
monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG 
interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative 
searching or monitoring of the content of privileged communications, or work product, related to 
personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. 
Such communications and work product are private and confidential. See User Agreement for details.

References:
CCI: CCI-000048
NIST SP 800-53 :: AC-8 a
NIST SP 800-53 Revision 4 :: AC-8 a
NIST SP 800-53 Revision 5 :: AC-8 a
NIST SP 800-53A :: AC-8.1 (ii)

CCI: CCI-000050
NIST SP 800-53 :: AC-8 b
NIST SP 800-53 Revision 4 :: AC-8 b
NIST SP 800-53 Revision 5 :: AC-8 b
NIST SP 800-53A :: AC-8.1 (iii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000130"
FINDING_ID = "V-255950"
RULE_ID = "SV-255950r960843_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must display Standard Mandatory DOD Notice and Consent Banner"

# DOD-centric keywords that should be present in the banner
# These keywords indicate a DOD-approved banner is in use
REQUIRED_KEYWORDS = [
    'U.S. Government',  # or 'USG'
    'authorized',
    'monitor',
    'consent',
    'private'
]

# Alternative acceptable keywords (case-insensitive)
KEYWORD_ALTERNATIVES = {
    'U.S. Government': ['USG', 'U.S. Government', 'United States Government'],
    'authorized': ['authorized', 'authorised'],
    'monitor': ['monitor', 'monitoring', 'monitored', 'intercept'],
    'consent': ['consent', 'agree', 'acknowledge'],
    'private': ['private', 'privacy', 'not private']
}


def load_test_data(file_path):
    """Load test data from JSON or YAML file (native Arista eAPI format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Arista eAPI JSON-RPC response format
    # Expected structure: {"jsonrpc": "2.0", "result": [{"cmds": {...}}]}
    if isinstance(data, dict) and 'result' in data:
        result = data.get('result', [])
        if result and len(result) > 0:
            config = result[0].get('cmds', {})
            # Extract hostname from config if available
            device_name = 'unknown-device'
            for cmd_key in config.keys():
                if cmd_key.startswith('hostname '):
                    device_name = cmd_key.replace('hostname ', '').strip()
                    break
            return {device_name: {'config': config}}
    
    # Direct format (already extracted cmds)
    if isinstance(data, dict) and 'cmds' in data:
        device_name = 'unknown-device'
        for cmd_key in data['cmds'].keys():
            if cmd_key.startswith('hostname '):
                device_name = cmd_key.replace('hostname ', '').strip()
                break
        return {device_name: {'config': data['cmds']}}
    
    return data


def check_keyword_present(banner_text, keyword_group):
    """Check if any of the alternative keywords are present in the banner (case-insensitive)."""
    banner_lower = banner_text.lower()
    alternatives = KEYWORD_ALTERNATIVES.get(keyword_group, [keyword_group])
    
    for alt in alternatives:
        if alt.lower() in banner_lower:
            return True, alt
    return False, None


def test_dod_login_banner():
    """
    Test that a DOD-approved login banner is configured.
    
    STIG V-255950 (ARST-ND-000130) requires that the Arista switch displays a Standard 
    Mandatory DOD Notice and Consent Banner before granting access. This ensures:
    - Users are notified they are accessing a U.S. Government system
    - Users understand that use is monitored and recorded
    - Users acknowledge there is no expectation of privacy
    - Users consent to the terms before accessing the system
    - Compliance with federal laws and DoD policies
    
    The test validates that:
    1. A login banner is configured
    2. The banner contains DOD-centric keywords indicating proper content:
       - Reference to U.S. Government/USG
       - Authorization language
       - Monitoring notification
       - Consent acknowledgment
       - Privacy notification
    
    Note: This test checks for presence of key DOD-specific terms rather than requiring
    exact verbatim text, allowing for approved variations of the DOD banner.
    
    This implements:
    - AC-8 a: Display system use notification
    - AC-8 b: Retain notification until user acknowledgment
    
    Native extraction method: Tests against Arista eAPI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('config', {})
            
            # Initialize compliance flags
            banner_configured = False
            banner_text = None
            keywords_found = {}
            missing_keywords = []
            
            # Check for login banner
            # Arista format: "banner login\n<banner text>\nEOF": null
            for cmd_key in config.keys():
                if cmd_key.startswith('banner login'):
                    banner_configured = True
                    # Extract banner text (everything after "banner login\n" and before "\nEOF")
                    banner_text = cmd_key.replace('banner login\n', '').replace('\nEOF', '')
                    break
            
            if banner_configured and banner_text:
                # Check for required DOD keywords
                for keyword in REQUIRED_KEYWORDS:
                    found, matched_term = check_keyword_present(banner_text, keyword)
                    keywords_found[keyword] = {
                        'found': found,
                        'matched': matched_term
                    }
                    if not found:
                        missing_keywords.append(keyword)
            
            # Overall compliance - banner must be configured and contain all required keywords
            overall_compliant = (
                banner_configured and 
                banner_text and
                len(missing_keywords) == 0
            )
            
            results[device_name] = {
                'banner_configured': banner_configured,
                'banner_text': banner_text[:200] + '...' if banner_text and len(banner_text) > 200 else banner_text,
                'banner_length': len(banner_text) if banner_text else 0,
                'keywords_found': keywords_found,
                'missing_keywords': missing_keywords,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not banner_configured:
                    error_parts.append("  ✗ Login banner is NOT configured")
                elif not banner_text:
                    error_parts.append("  ✗ Login banner is empty")
                elif missing_keywords:
                    error_parts.append(f"  ✗ Banner is missing required DOD keywords:")
                    for keyword in missing_keywords:
                        alternatives = ', '.join(KEYWORD_ALTERNATIVES.get(keyword, [keyword]))
                        error_parts.append(f"    - '{keyword}' (or alternatives: {alternatives})")
                
                if keywords_found:
                    error_parts.append("\n  Keywords status:")
                    for keyword, status in keywords_found.items():
                        if status['found']:
                            error_parts.append(f"    ✓ {keyword}: Found (matched: '{status['matched']}')")
                        else:
                            error_parts.append(f"    ✗ {keyword}: NOT found")
                
                error_parts.append("\nDOD-approved banner is NOT properly configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  switch(config)# banner login")
                error_parts.append("  Enter TEXT message.")
                error_parts.append("  <Insert DOD-approved banner here>")
                error_parts.append("  Type 'EOF' on its own line to end.")
                error_parts.append("\nRequired DOD-centric keywords in banner:")
                error_parts.append("  1. U.S. Government/USG reference")
                error_parts.append("  2. Authorization language")
                error_parts.append("  3. Monitoring notification")
                error_parts.append("  4. Consent acknowledgment")
                error_parts.append("  5. Privacy notification")
                error_parts.append("\nKey banner elements:")
                error_parts.append("  - Accessing a U.S. Government system")
                error_parts.append("  - Use is for authorized purposes only")
                error_parts.append("  - Communications are monitored and recorded")
                error_parts.append("  - User consent is required")
                error_parts.append("  - No expectation of privacy")
                error_parts.append("\nWithout a proper DOD banner:")
                error_parts.append("  - Users are not properly notified of system use policies")
                error_parts.append("  - Legal protection for monitoring may be compromised")
                error_parts.append("  - Non-compliance with federal laws and DoD directives")
                error_parts.append("  - Compliance requirements are not met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking login banner on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Login banner configured")
            print(f"  ✓ Banner length: {result['banner_length']} characters")
            print(f"  ✓ Required DOD keywords present:")
            for keyword, status in result['keywords_found'].items():
                if status['found']:
                    print(f"    ✓ {keyword} (matched: '{status['matched']}')")
            print(f"  ✓ DOD Notice and Consent Banner requirement satisfied")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Banner configured: {'✓' if result.get('banner_configured') else '✗'}")
                if result.get('banner_length'):
                    print(f"  Banner length: {result['banner_length']} characters")
                if result.get('keywords_found'):
                    print(f"  Keyword check:")
                    for keyword, status in result['keywords_found'].items():
                        found_indicator = '✓' if status['found'] else '✗'
                        matched = f" (matched: '{status['matched']}')" if status['found'] else ""
                        print(f"    {found_indicator} {keyword}{matched}")
                if result.get('missing_keywords'):
                    print(f"  Missing keywords: {', '.join(result['missing_keywords'])}")


if __name__ == "__main__":
    test_dod_login_banner()
