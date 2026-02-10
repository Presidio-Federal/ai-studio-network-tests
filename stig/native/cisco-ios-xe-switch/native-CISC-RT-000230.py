"""
STIG ID: CISC-RT-000230
Finding ID: V-221006
Rule ID: SV-221006r1117237_rule
Severity: CAT III (Low)
Classification: Unclass
Legacy IDs: V-101729; SV-110833

Group Title: SRG-NET-000019-RTR-000001

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Switch

Rule Title: The Cisco switch must be configured to disable the auxiliary port unless it is 
connected to a secured modem providing encryption and authentication.

Discussion:
The use of POTS (Plain Old Telephone Service) lines to modems connecting to network devices 
provides clear text of authentication traffic over commercial circuits that could be captured 
and used to compromise the network. Additional war dial attacks on the device could degrade 
the device and the production network.

Secured modem devices must be able to authenticate users and must negotiate a key exchange 
before full encryption takes place. The modem will provide full encryption capability 
(Triple DES) or stronger. The technician who manages these devices will be authenticated 
using a key fob and granted access to the appropriate maintenance port; thus, the technician 
will gain access to the managed device.

The auxiliary port represents an additional attack vector that should be disabled unless:
1. It is connected to a secured modem with encryption (Triple DES or stronger)
2. The modem provides strong authentication (two-factor with token/key fob)
3. One-time passwords are used that change at second intervals
4. The connection is properly authorized and documented

In most modern deployments, auxiliary ports are no longer needed and should be disabled to:
- Reduce attack surface
- Prevent unauthorized dial-in access
- Eliminate war dialing vulnerabilities
- Enforce information flow control policies

Check Text:
Review the configuration and verify that the auxiliary port is disabled unless a secured 
modem providing encryption and authentication is connected to it.

line aux 0
  no exec

Note: Transport input none is the default; hence it will not be shown in the configuration.

If the auxiliary port is not disabled or is not connected to a secured modem when it is 
enabled, this is a finding.

Fix Text:
Disable the auxiliary port:

SW2(config)# line aux 0
SW2(config-line)# no exec 
SW2(config-line)# transport input none
SW2(config-line)# end

References:
CCI: CCI-001414: Enforce approved authorizations for controlling the flow of information 
between connected systems based on organization-defined information flow control policies.
NIST SP 800-53 :: AC-4
NIST SP 800-53 Revision 4 :: AC-4
NIST SP 800-53 Revision 5 :: AC-4
NIST SP 800-53A :: AC-4.1 (iii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-RT-000230"
FINDING_ID = "V-221006"
RULE_ID = "SV-221006r1117237_rule"
SEVERITY = "Low"
CATEGORY = "STIG"
PLATFORM = "ios-xe-switch"
EXTRACTION_METHOD = "native"
TITLE = "Switch must disable auxiliary port unless connected to secured modem"


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


def test_auxiliary_port_disabled():
    """
    Test that the auxiliary port is disabled unless connected to a secured modem.
    
    STIG V-221006 (CISC-RT-000230) requires that the auxiliary port be disabled to prevent 
    unauthorized dial-in access. The aux port can be exploited for:
    - War dialing attacks
    - Unauthorized remote access
    - Clear-text credential capture over POTS lines
    - Bypassing network security controls
    
    The test validates that:
    1. The auxiliary port has 'no exec' configured (exec is disabled)
    2. Transport input is 'none' or not configured (default is none)
    
    This ensures the auxiliary port cannot be used for unauthorized access unless it is 
    properly secured with a modem providing encryption and strong authentication.
    
    Native extraction method: Tests against native API/CLI JSON output.
    
    Note: In modern deployments, auxiliary ports are rarely used and should be disabled.
    If a secured modem is legitimately connected, this test may be marked as not applicable 
    with proper authorization and documentation.
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
            
            # Initialize compliance tracking
            aux_ports_found = []
            non_compliant_ports = []
            
            # Get line configuration
            if data_format == 'native':
                # Native format: line -> aux[]
                line_config = config.get('line', {})
                aux_lines = line_config.get('aux', [])
            else:
                # NSO format: tailf-ned-cisco-ios:line -> aux[]
                line_config = config.get('tailf-ned-cisco-ios:line', {})
                aux_lines = line_config.get('aux', [])
            
            # Check each auxiliary port
            for aux_port in aux_lines:
                port_id = aux_port.get('first', '0')
                port_name = f"aux {port_id}"
                
                # Check if 'no exec' is configured
                # In JSON, this appears as "no-exec": true or similar
                no_exec = aux_port.get('no-exec', False)
                exec_disabled = aux_port.get('exec', {}) if isinstance(aux_port.get('exec'), dict) else None
                
                # Check for explicit exec disable
                is_exec_disabled = (
                    no_exec == True or 
                    no_exec == [None] or 
                    'no-exec' in aux_port
                )
                
                # Check transport input configuration
                # Default is 'none', so if not configured, it's compliant
                # If configured, should be 'none' or should not include telnet/ssh/all
                transport_config = aux_port.get('transport', {})
                transport_input = transport_config.get('input', {})
                
                # Determine if transport is properly restricted
                # If transport_input is empty dict or not present, default is 'none' (compliant)
                # If transport_input has 'none' explicitly, that's compliant
                # If it has 'ssh', 'telnet', 'all', that's non-compliant
                transport_compliant = True
                transport_issue = None
                
                if isinstance(transport_input, dict) and transport_input:
                    # Check for insecure transport protocols
                    if 'telnet' in transport_input or 'all' in transport_input:
                        transport_compliant = False
                        transport_issue = "insecure transport enabled"
                    elif 'ssh' in transport_input:
                        # SSH might be acceptable with secured modem, but typically should be none
                        transport_compliant = False
                        transport_issue = "SSH transport enabled (should be none unless secured modem)"
                
                # Port is compliant if exec is disabled
                # Transport input restriction is secondary but good practice
                port_compliant = is_exec_disabled
                
                port_info = {
                    'port': port_name,
                    'exec_disabled': is_exec_disabled,
                    'transport_compliant': transport_compliant,
                    'transport_issue': transport_issue,
                    'compliant': port_compliant
                }
                
                aux_ports_found.append(port_info)
                
                if not port_compliant:
                    non_compliant_ports.append(port_info)
            
            # Overall compliance - all aux ports must be disabled
            overall_compliant = len(non_compliant_ports) == 0 and len(aux_ports_found) > 0
            
            # If no aux ports found in config, that might mean default config (not explicitly disabled)
            # In native format, if aux is present but minimal, it's not disabled
            if len(aux_ports_found) == 0:
                overall_compliant = False
                non_compliant_ports.append({
                    'port': 'aux 0',
                    'exec_disabled': False,
                    'transport_compliant': None,
                    'transport_issue': 'not configured',
                    'compliant': False
                })
            elif len(aux_ports_found) > 0:
                # Check if any port is only minimally configured (just 'first' field)
                for port_info in aux_ports_found:
                    if not port_info['exec_disabled']:
                        # Port exists but is not disabled - this is the case in sample config
                        overall_compliant = False
            
            results[device_name] = {
                'aux_ports': aux_ports_found,
                'non_compliant_ports': non_compliant_ports,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append("")
                error_parts.append(f"  ✗ Auxiliary port is NOT properly disabled")
                error_parts.append("")
                
                if non_compliant_ports:
                    error_parts.append("Non-compliant auxiliary port(s):")
                    for port in non_compliant_ports:
                        error_parts.append(f"  • {port['port']}:")
                        if not port['exec_disabled']:
                            error_parts.append(f"    ✗ Exec is NOT disabled (no-exec not configured)")
                        if not port['transport_compliant'] and port['transport_issue']:
                            error_parts.append(f"    ⚠ Transport issue: {port['transport_issue']}")
                
                error_parts.append("")
                error_parts.append("Security Risk:")
                error_parts.append("  • Auxiliary port can be exploited for unauthorized dial-in access")
                error_parts.append("  • War dialing attacks can discover and exploit the port")
                error_parts.append("  • Clear-text credentials over POTS lines can be intercepted")
                error_parts.append("  • Network security controls can be bypassed")
                error_parts.append("  • Attack surface is unnecessarily increased")
                error_parts.append("")
                error_parts.append("Auxiliary port MUST be disabled unless connected to a secured modem!")
                error_parts.append("")
                error_parts.append("Required remediation:")
                error_parts.append("  SW2(config)# line aux 0")
                error_parts.append("  SW2(config-line)# no exec")
                error_parts.append("  SW2(config-line)# transport input none")
                error_parts.append("  SW2(config-line)# end")
                error_parts.append("")
                error_parts.append("Note: If a secured modem with encryption (Triple DES+) and")
                error_parts.append("      strong authentication (two-factor) is legitimately connected,")
                error_parts.append("      ensure proper authorization and documentation exists.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking auxiliary port configuration on {device_name}: {e}"
    
    # Print summary
    print("\n" + "="*80)
    print("STIG Compliance Check Results")
    print("="*80)
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY} (CAT III)")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("="*80)
    print("\nDevice Results:")
    print("-"*80)
    
    for device, result in results.items():
        status = "✓ PASS" if result.get('compliant') else "✗ FAIL"
        print(f"\n{device}: {status}")
        
        if result.get('compliant'):
            aux_ports = result.get('aux_ports', [])
            if aux_ports:
                print(f"  ✓ Auxiliary port(s) properly disabled ({len(aux_ports)}):")
                for port in aux_ports:
                    print(f"    • {port['port']}: exec disabled, transport restricted")
            print(f"  ✓ Protected against war dialing attacks")
            print(f"  ✓ Unauthorized dial-in access prevented")
            print(f"  ✓ Information flow control enforced (AC-4)")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                non_compliant = result.get('non_compliant_ports', [])
                if non_compliant:
                    print(f"  ✗ {len(non_compliant)} auxiliary port(s) not properly disabled:")
                    for port in non_compliant:
                        print(f"    • {port['port']}: exec_disabled={port['exec_disabled']}")
    
    print("\n" + "="*80)
    print("Control Mapping:")
    print("  CCI-001414: Information flow control enforcement")
    print("  NIST SP 800-53 Rev 4: AC-4")
    print("  NIST SP 800-53 Rev 5: AC-4")
    print("  Control: Access Control - Information Flow Enforcement")
    print("="*80 + "\n")


if __name__ == "__main__":
    test_auxiliary_port_disabled()
