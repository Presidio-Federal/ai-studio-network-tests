"""
STIG ID: ARST-ND-000340
Finding ID: V-255952
Rule ID: SV-255952r1043177_rule
Severity: CAT I (High)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Arista EOS Switch

Rule Title: The Arista Multilayer Switch must be configured to prohibit the use of all unnecessary 
and/or nonsecure functions, ports, protocols, and/or services as defined in the PPSM CAL and 
vulnerability assessments.

Discussion:
Information systems are capable of providing a wide variety of functions (capabilities or processes) 
and services. Some of these functions and services are installed and enabled by default. The 
organization must determine which functions and services are required to perform the content 
filtering and other necessary core functionality for each component of the information system. 
Unnecessary or nonsecure services increase the attack surface and must be disabled.

For network devices, commonly unnecessary or insecure services include:
- Telnet: Transmits credentials and data in clear text (insecure)
- HTTP: Unencrypted web management interface (insecure)
- HTTPS API without proper security controls (potentially insecure depending on use case)

However, some management services may be required for specific operational needs:
- HTTPS API (http-commands): May be needed for automation and API access
- If required, must be properly secured with ACLs, VRF separation, and TLS

This is a CAT I (High) severity finding due to the critical security risk posed by insecure 
protocols, particularly Telnet which transmits credentials in clear text.

Check Text:
Verify the Arista network device has telnet disabled and HTTP management properly secured.

Step 1: Determine if telnet is disabled.
Management telnet should be shutdown or not configured.

Step 2: Determine if HTTP API is properly configured.
Management api http-commands should either be:
- Shutdown (disabled), OR
- Configured without insecure HTTP protocol (only HTTPS)

If telnet is enabled, this is a finding.
If HTTP (not HTTPS) is enabled for management, this is a finding.

Note: HTTPS API (http-commands) may be acceptable if required for automation/API access 
and properly secured with ACLs, VRF separation, and strong TLS protocols.

Fix Text:
Configure the Arista network device to prohibit the use of all unnecessary and/or nonsecure 
functions, ports, protocols, and/or services.

Step 1: Disable telnet:
switch(config)# management telnet
switch(config-mgmt-telnet)# shutdown
switch(config-mgmt-telnet)# exit

Step 2: Disable HTTP API (if not required):
switch(config)# management api http-commands
switch(config-mgmt-api-http-commands)# shutdown
switch(config-mgmt-api-http-commands)# exit

Step 2 Alternative: If API access is required, ensure only HTTPS is enabled:
switch(config)# management api http-commands
switch(config-mgmt-api-http-commands)# no protocol http
switch(config-mgmt-api-http-commands)# protocol https
switch(config-mgmt-api-http-commands)# exit

References:
CCI: CCI-000382
NIST SP 800-53 :: CM-7
NIST SP 800-53 Revision 4 :: CM-7 b
NIST SP 800-53 Revision 5 :: CM-7 b
NIST SP 800-53A :: CM-7.1 (iii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "ARST-ND-000340"
FINDING_ID = "V-255952"
RULE_ID = "SV-255952r1043177_rule"
SEVERITY = "High"  # CAT I
CATEGORY = "STIG"
PLATFORM = "arista-eos-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must prohibit unnecessary/nonsecure functions, ports, protocols, and services"


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
    if isinstance(data, dict) and 'result' in data:
        result = data.get('result', [])
        if result and len(result) > 0:
            config = result[0].get('cmds', {})
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


def test_insecure_protocols_disabled():
    """
    Test that insecure management protocols (telnet, HTTP) are disabled.
    
    STIG V-255952 (ARST-ND-000340) is a CAT I (High severity) requirement that mandates 
    disabling unnecessary and insecure functions, ports, protocols, and services. This ensures:
    - Credentials are not transmitted in clear text (telnet)
    - Management interfaces use encryption (HTTPS vs HTTP)
    - Attack surface is minimized
    - Only required services are enabled
    
    The test validates that:
    1. Telnet is not enabled (shutdown or not configured)
    2. Insecure HTTP protocol is not enabled for management
    
    Note: HTTPS API (http-commands) is considered acceptable if required for automation
    and properly secured. The test will provide informational warnings if API access is
    enabled, but will only fail on truly insecure configurations (telnet, unencrypted HTTP).
    
    This implements CM-7 (Least Functionality) from NIST SP 800-53.
    
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
            
            # Initialize flags
            telnet_status = 'not-configured'  # not-configured, enabled, shutdown
            http_api_status = 'not-configured'  # not-configured, enabled, shutdown
            http_protocol_enabled = False
            https_protocol_enabled = False
            api_vrf = None
            
            # Check for management telnet
            # Arista format: "management telnet": {"cmds": {"shutdown": null}} or no shutdown key
            management_telnet = config.get('management telnet', {})
            if management_telnet:
                telnet_cmds = management_telnet.get('cmds', {})
                if 'shutdown' in telnet_cmds:
                    telnet_status = 'shutdown'
                else:
                    telnet_status = 'enabled'
            
            # Check for management api http-commands
            # Arista format: "management api http-commands": {"cmds": {...}}
            management_api = config.get('management api http-commands', {})
            if management_api:
                api_cmds = management_api.get('cmds', {})
                
                if 'shutdown' in api_cmds:
                    http_api_status = 'shutdown'
                elif 'no shutdown' in api_cmds:
                    http_api_status = 'enabled'
                else:
                    # If neither shutdown nor no shutdown, assume enabled if configured
                    http_api_status = 'enabled'
                
                # Check for protocol configurations
                if 'protocol http' in api_cmds:
                    http_protocol_enabled = True
                if 'protocol https' in api_cmds:
                    https_protocol_enabled = True
                
                # Check for VRF configuration (indicates isolated management)
                for cmd_key in api_cmds.keys():
                    if cmd_key.startswith('vrf '):
                        api_vrf = cmd_key.replace('vrf ', '').strip()
                        break
            
            # Determine compliance
            # CRITICAL: Telnet must not be enabled
            telnet_compliant = (telnet_status != 'enabled')
            
            # HTTP protocol must not be enabled (HTTPS is acceptable)
            # If API is enabled with HTTP protocol, it's a finding
            http_compliant = not http_protocol_enabled
            
            # Overall compliance
            overall_compliant = telnet_compliant and http_compliant
            
            # Informational flags
            api_enabled = (http_api_status == 'enabled')
            api_has_vrf = (api_vrf is not None)
            
            results[device_name] = {
                'telnet_status': telnet_status,
                'telnet_compliant': telnet_compliant,
                'http_api_status': http_api_status,
                'http_protocol_enabled': http_protocol_enabled,
                'https_protocol_enabled': https_protocol_enabled,
                'http_compliant': http_compliant,
                'api_enabled': api_enabled,
                'api_vrf': api_vrf,
                'api_has_vrf': api_has_vrf,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append("\n⚠️  CAT I (HIGH SEVERITY) FINDING ⚠️")
                
                if not telnet_compliant:
                    error_parts.append(f"\n  ✗ CRITICAL: Telnet is ENABLED")
                    error_parts.append("    Risk: Credentials and data transmitted in CLEAR TEXT")
                    error_parts.append("    Action: Immediately disable telnet")
                
                if not http_compliant:
                    error_parts.append(f"\n  ✗ CRITICAL: Insecure HTTP protocol is ENABLED")
                    error_parts.append("    Risk: Unencrypted management traffic")
                    error_parts.append("    Action: Disable HTTP, use only HTTPS")
                
                error_parts.append("\nInsecure protocols are enabled!")
                error_parts.append("\nRequired remediation:")
                
                if not telnet_compliant:
                    error_parts.append("\nStep 1: Disable telnet:")
                    error_parts.append("  switch(config)# management telnet")
                    error_parts.append("  switch(config-mgmt-telnet)# shutdown")
                    error_parts.append("  switch(config-mgmt-telnet)# exit")
                
                if not http_compliant:
                    error_parts.append("\nStep 2: Disable HTTP protocol:")
                    error_parts.append("  switch(config)# management api http-commands")
                    error_parts.append("  switch(config-mgmt-api-http-commands)# no protocol http")
                    error_parts.append("  switch(config-mgmt-api-http-commands)# protocol https")
                    error_parts.append("  switch(config-mgmt-api-http-commands)# exit")
                
                error_parts.append("\nSecurity implications:")
                error_parts.append("  - Telnet transmits credentials in clear text")
                error_parts.append("  - HTTP transmits management data unencrypted")
                error_parts.append("  - Attackers can intercept credentials and commands")
                error_parts.append("  - Compliance violations (CAT I severity)")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking insecure protocols on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY} (CAT I)")
    print(f"Platform: {PLATFORM}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Telnet: {result['telnet_status']}")
            print(f"  ✓ HTTP protocol: {'enabled' if result['http_protocol_enabled'] else 'disabled'}")
            print(f"  ✓ HTTPS protocol: {'enabled' if result['https_protocol_enabled'] else 'disabled'}")
            
            if result.get('api_enabled'):
                print(f"\n  ℹ️  INFORMATIONAL: HTTP API (http-commands) is enabled")
                if result.get('https_protocol_enabled'):
                    print(f"     ✓ HTTPS protocol is configured (secure)")
                if result.get('api_has_vrf'):
                    print(f"     ✓ VRF separation configured: {result['api_vrf']}")
                print(f"     Note: Ensure API access is secured with:")
                print(f"           - Access control lists (ACLs)")
                print(f"           - VRF management separation")
                print(f"           - Strong TLS protocols (1.2+)")
            
            print(f"  ✓ Insecure protocols are disabled")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Telnet status: {result.get('telnet_status', 'unknown')}")
                if not result.get('telnet_compliant'):
                    print(f"    ✗ CRITICAL: Telnet is enabled (clear text)")
                print(f"  HTTP API status: {result.get('http_api_status', 'unknown')}")
                if result.get('http_protocol_enabled'):
                    print(f"    ✗ CRITICAL: HTTP protocol enabled (unencrypted)")
                if result.get('https_protocol_enabled'):
                    print(f"    ✓ HTTPS protocol enabled")


if __name__ == "__main__":
    test_insecure_protocols_disabled()
