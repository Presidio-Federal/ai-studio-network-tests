"""
STIG ID: CISC-ND-000140
Finding ID: V-215667
Rule ID: SV-215667r991819_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96023; SV-105161

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to enforce approved authorizations for controlling 
the flow of management information within the device based on control policies.

Discussion:
A mechanism to detect and prevent unauthorized communication flow must be configured or provided 
as part of the system design. If management information flow is not enforced based on approved 
authorizations, the system may become compromised. Management information includes any content 
that might be used to manage the device, as well as management traffic itself.

Unrestricted management access allows unauthorized users to potentially gain access to the device, 
view or modify configuration, or disrupt operations. Restricting management access to specific 
authorized networks or hosts ensures that only authorized personnel can manage the device.

Check Text:
Review the Cisco router configuration to verify that it is compliant with this requirement.

Step 1: Verify that the line vty has an ACL inbound applied as shown in the example below.

line vty 0 1
  access-class MANAGEMENT_NET in
  transport input ssh

Step 2: Verify that the ACL permits only hosts from the management network to access the router.

ip access-list extended MANAGEMENT_NET
  permit ip x.x.x.0 0.0.0.255 any
  deny   ip any any log-input

If the Cisco router is not configured to enforce approved authorizations for controlling the 
flow of management information within the device based on control policies, this is a finding.

Fix Text:
Configure the Cisco router to restrict management access to specific IP addresses via SSH 
as shown in the example below.

SW2(config)# ip access-list standard MANAGEMENT_NET
SW2(config-std-nacl)# permit x.x.x.0 0.0.0.255
SW2(config-std-nacl)# exit
SW2(config)# line vty 0 1
SW2(config-line)# transport input ssh
SW2(config-line)# access-class MANAGEMENT_NET in
SW2(config-line)# end

References:
CCI: CCI-001368, CCI-004192
NIST SP 800-53 :: AC-4
NIST SP 800-53 Revision 4 :: AC-4
NIST SP 800-53 Revision 5 :: AC-4, MA-4 (4) (b) (2)
NIST SP 800-53A :: AC-4.1 (iii)
"""

import os
import json
import yaml
import pytest
import re

STIG_ID = "CISC-ND-000140"
FINDING_ID = "V-215667"
RULE_ID = "SV-215667r991819_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must enforce approved authorizations for management access"


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


def check_acl_for_any_permit(acl_name, acl_config, data_format='native'):
    """
    Check if an ACL contains overly permissive 'permit any' rules.
    Returns: (has_permit_any, permit_details)
    """
    permit_any_found = []
    
    if data_format == 'native':
        # Native format ACL structure
        # Standard ACL - check for 'permit' key with 'any'
        if 'access-list-seq-rule' in acl_config:
            for rule in acl_config.get('access-list-seq-rule', []):
                sequence = rule.get('sequence', 'unknown')
                
                # Standard ACL format has 'permit' or 'deny' as top-level keys
                if 'permit' in rule:
                    permit_config = rule.get('permit', {})
                    std_ace = permit_config.get('std-ace', {})
                    if 'any' in std_ace:
                        permit_any_found.append(f"sequence {sequence}: permit any")
                
                # Extended ACL format
                elif 'ace-rule' in rule:
                    ace_rule = rule.get('ace-rule', {})
                    action = ace_rule.get('action', '')
                    
                    if action == 'permit':
                        # Check for 'any' in source or destination
                        has_any_src = 'any' in ace_rule or 'src-any' in ace_rule
                        has_any_dst = 'dst-any' in ace_rule
                        
                        if has_any_src or has_any_dst:
                            permit_any_found.append(f"sequence {sequence}: permit any")
    
    else:  # NSO format
        # NSO extended ACL
        ext_rules = acl_config.get('ext-access-list-rule', [])
        for rule in ext_rules:
            rule_text = rule.get('rule', '')
            if 'permit' in rule_text.lower() and 'any' in rule_text.lower():
                permit_any_found.append(f"rule: {rule_text}")
        
        # NSO standard ACL
        std_rules = acl_config.get('std-access-list-rule', [])
        for rule in std_rules:
            rule_text = rule.get('rule', '')
            if 'permit' in rule_text.lower() and 'any' in rule_text.lower():
                permit_any_found.append(f"rule: {rule_text}")
    
    return len(permit_any_found) > 0, permit_any_found


def test_management_access_control():
    """
    Test that VTY lines have access-class ACLs configured with specific network restrictions.
    
    STIG V-215667 (CISC-ND-000140) requires that the router enforces approved authorizations 
    for controlling management information flow. This is accomplished by:
    1. Applying an access-class ACL to VTY lines
    2. Ensuring the ACL restricts access to specific management networks (not 'permit any')
    
    The test validates that:
    1. VTY lines have access-class configured
    2. The referenced ACL exists
    3. The ACL does NOT contain overly permissive 'permit any' rules
    4. SSH is configured as the transport input
    
    Native extraction method: Tests against native API/CLI JSON output.
    
    Note: This test will FAIL if ACLs contain 'permit any' rules, as these do not restrict
    management access to specific authorized networks.
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
            
            # Initialize tracking
            vty_lines_checked = []
            non_compliant_vtys = []
            all_acls = {}
            
            # Get ACL configurations
            if data_format == 'native':
                # Native format ACLs
                ip_config = config.get('ip', {})
                access_list_config = ip_config.get('access-list', {})
                
                # Standard ACLs - native format uses different structure
                std_acls_native = access_list_config.get('Cisco-IOS-XE-acl:standard', [])
                for acl in std_acls_native:
                    acl_name = acl.get('name', '')
                    all_acls[acl_name] = acl
                
                # Extended ACLs
                ext_acls_native = access_list_config.get('Cisco-IOS-XE-acl:extended', [])
                for acl in ext_acls_native:
                    acl_name = acl.get('name', '')
                    all_acls[acl_name] = acl
                
                # Get line configuration
                line_config = config.get('line', {})
            else:
                # NSO format
                ip_config = config.get('tailf-ned-cisco-ios:ip', {})
                
                # Standard ACLs
                std_acls = ip_config.get('access-list', {}).get('standard', {}).get('std-named-acl', [])
                for acl in std_acls:
                    acl_name = acl.get('name', '')
                    all_acls[acl_name] = acl
                
                # Extended ACLs
                ext_acls = ip_config.get('access-list', {}).get('extended', {}).get('ext-named-acl', [])
                for acl in ext_acls:
                    acl_name = acl.get('name', '')
                    all_acls[acl_name] = acl
                
                line_config = config.get('tailf-ned-cisco-ios:line', {})
            
            # Check VTY lines
            vty_configs = []
            
            # VTY single-conf format
            if 'vty-single-conf' in line_config:
                vty_configs.extend(line_config.get('vty-single-conf', {}).get('vty', []))
            
            # VTY range format
            if 'vty' in line_config:
                vty_configs.extend(line_config.get('vty', []))
            
            for vty in vty_configs:
                vty_first = vty.get('first', 'unknown')
                vty_last = vty.get('last', vty_first)
                vty_id = f"{vty_first}-{vty_last}" if vty_first != vty_last else str(vty_first)
                
                # Check for access-class
                access_class = None
                if data_format == 'native':
                    access_class_config = vty.get('access-class', {})
                    if access_class_config:
                        # Handle typo in native format: 'acccess-list' instead of 'access-list'
                        acccess_list = access_class_config.get('acccess-list', [])
                        if acccess_list and isinstance(acccess_list, list):
                            for acl_entry in acccess_list:
                                if acl_entry.get('direction') == 'in':
                                    access_class = acl_entry.get('access-list', '')
                                    break
                        # Also check standard format
                        if not access_class:
                            access_class = access_class_config.get('access-class-in-name', '') or \
                                         access_class_config.get('access-list', '')
                else:
                    access_class_config = vty.get('access-class', {})
                    if isinstance(access_class_config, dict):
                        access_class = access_class_config.get('access-class-in-name', '')
                
                # Check transport input
                transport = vty.get('transport', {})
                if isinstance(transport, dict):
                    transport_input = transport.get('input', {})
                    # Native format can have input as dict with protocol keys like 'ssh': true
                    if isinstance(transport_input, dict):
                        ssh_enabled = transport_input.get('ssh', False) == True
                    elif isinstance(transport_input, list):
                        ssh_enabled = 'ssh' in transport_input
                    else:
                        ssh_enabled = False
                else:
                    ssh_enabled = False
                
                vty_info = {
                    'id': vty_id,
                    'has_access_class': bool(access_class),
                    'access_class_name': access_class,
                    'ssh_enabled': ssh_enabled,
                    'compliant': False,
                    'issues': []
                }
                
                # Check compliance
                if not access_class:
                    vty_info['issues'].append("No access-class configured")
                elif access_class not in all_acls:
                    vty_info['issues'].append(f"ACL '{access_class}' not found in configuration")
                else:
                    # Check if ACL has 'permit any'
                    has_permit_any, permit_details = check_acl_for_any_permit(
                        access_class, all_acls[access_class], data_format
                    )
                    if has_permit_any:
                        vty_info['issues'].append(f"ACL '{access_class}' contains overly permissive rules:")
                        for detail in permit_details:
                            vty_info['issues'].append(f"  - {detail}")
                
                if not ssh_enabled:
                    vty_info['issues'].append("SSH not configured as transport input")
                
                # Overall VTY compliance
                vty_info['compliant'] = (
                    bool(access_class) and
                    access_class in all_acls and
                    not check_acl_for_any_permit(access_class, all_acls[access_class], data_format)[0] and
                    ssh_enabled
                )
                
                vty_lines_checked.append(vty_info)
                if not vty_info['compliant']:
                    non_compliant_vtys.append(vty_info)
            
            # Overall device compliance
            overall_compliant = len(non_compliant_vtys) == 0 and len(vty_lines_checked) > 0
            
            results[device_name] = {
                'vty_lines_checked': vty_lines_checked,
                'non_compliant_vtys': non_compliant_vtys,
                'total_acls_found': len(all_acls),
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append("\nManagement access is NOT properly restricted!")
                
                if len(vty_lines_checked) == 0:
                    error_parts.append("  ✗ No VTY lines found in configuration")
                else:
                    for vty in non_compliant_vtys:
                        error_parts.append(f"\n  VTY {vty['id']}:")
                        for issue in vty['issues']:
                            error_parts.append(f"    ✗ {issue}")
                
                error_parts.append("\nRequired configuration:")
                error_parts.append("  SW2(config)# ip access-list standard MANAGEMENT_NET")
                error_parts.append("  SW2(config-std-nacl)# permit x.x.x.0 0.0.0.255")
                error_parts.append("  SW2(config-std-nacl)# deny any log")
                error_parts.append("  SW2(config-std-nacl)# exit")
                error_parts.append("  SW2(config)# line vty 0 15")
                error_parts.append("  SW2(config-line)# transport input ssh")
                error_parts.append("  SW2(config-line)# access-class MANAGEMENT_NET in")
                error_parts.append("  SW2(config-line)# end")
                error_parts.append("\nWARNING: ACLs with 'permit any' do NOT restrict management access!")
                error_parts.append("Specify explicit management networks instead of 'any'.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking management access control on {device_name}: {e}"
    
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
            print(f"  ✓ {len(result['vty_lines_checked'])} VTY line(s) properly restricted")
            for vty in result['vty_lines_checked']:
                print(f"  ✓ VTY {vty['id']}: access-class {vty['access_class_name']}, SSH enabled")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Total VTY lines: {len(result['vty_lines_checked'])}")
                print(f"  Non-compliant VTY lines: {len(result['non_compliant_vtys'])}")
                for vty in result['non_compliant_vtys']:
                    print(f"  ✗ VTY {vty['id']}:")
                    for issue in vty['issues']:
                        print(f"      {issue}")


if __name__ == "__main__":
    test_management_access_control()
