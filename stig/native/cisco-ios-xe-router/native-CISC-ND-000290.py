"""
STIG ID: CISC-ND-000290
Finding ID: V-215673
Rule ID: SV-215673r960897_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96043; SV-105181

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to produce audit log records containing information 
to establish where the events occurred.

Discussion:
Associating information about where the event occurred within the network device provides a means 
of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying 
an improperly configured network device.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for 
security personnel to know where events occurred, such as network device components, device 
identifiers, and node names. Without this information, determining the location of events would be 
difficult and could delay or even prevent proper forensic analysis.

The log-input parameter on deny statements provides the interface and source MAC address of the 
packet that triggered the ACL rule, which helps establish where the event occurred in the network.

Check Text:
Review the router configuration to determine if the log-input parameter is configured after any 
deny statements in configured ACLs.

ip access-list extended BLOCK_INBOUND
  deny icmp any any log-input
  permit ip any any

If the router is not configured to generate audit records containing information to establish 
where the events occurred, this is a finding.

Fix Text:
Configure the log-input parameter after any deny statements to provide the location as to where 
packets have been dropped via an ACL.

R1(config)# ip access-list extended BLOCK_INBOUND
R1(config-ext-nacl)# deny icmp any any log-input
R1(config-ext-nacl)# end

References:
CCI: CCI-000132
NIST SP 800-53 :: AU-3
NIST SP 800-53 Revision 4 :: AU-3
NIST SP 800-53 Revision 5 :: AU-3 c
NIST SP 800-53A :: AU-3.1
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000290"
FINDING_ID = "V-215673"
RULE_ID = "SV-215673r960897_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must produce audit log records containing information to establish where events occurred"


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


def check_acl_deny_rules_for_log_input(acl_name, acl_config, data_format='native'):
    """
    Check if ACL deny rules have log-input configured.
    Returns: (deny_rules_found, deny_rules_with_log_input, deny_rules_without_log_input)
    """
    deny_rules_found = []
    deny_rules_with_log_input = []
    deny_rules_without_log_input = []
    
    if data_format == 'native':
        # Native format ACL structure
        if 'access-list-seq-rule' in acl_config:
            for rule in acl_config.get('access-list-seq-rule', []):
                sequence = rule.get('sequence', 'unknown')
                
                # Check for deny in standard ACL (has 'deny' key)
                if 'deny' in rule:
                    deny_config = rule.get('deny', {})
                    has_log_input = 'log-input' in deny_config or deny_config.get('log-input') is not None
                    
                    deny_rules_found.append({
                        'sequence': sequence,
                        'type': 'standard',
                        'has_log_input': has_log_input
                    })
                    
                    if has_log_input:
                        deny_rules_with_log_input.append(sequence)
                    else:
                        deny_rules_without_log_input.append(sequence)
                
                # Check for deny in extended ACL (ace-rule with action='deny')
                elif 'ace-rule' in rule:
                    ace_rule = rule.get('ace-rule', {})
                    action = ace_rule.get('action', '')
                    
                    if action == 'deny':
                        # Check for log-input
                        has_log_input = 'log-input' in ace_rule or ace_rule.get('log-input') is not None
                        
                        deny_rules_found.append({
                            'sequence': sequence,
                            'type': 'extended',
                            'has_log_input': has_log_input
                        })
                        
                        if has_log_input:
                            deny_rules_with_log_input.append(sequence)
                        else:
                            deny_rules_without_log_input.append(sequence)
    
    else:  # NSO format
        # NSO extended ACL
        ext_rules = acl_config.get('ext-access-list-rule', [])
        for rule in ext_rules:
            rule_text = rule.get('rule', '')
            if 'deny' in rule_text.lower():
                has_log_input = 'log-input' in rule_text.lower()
                
                deny_rules_found.append({
                    'rule': rule_text,
                    'type': 'extended',
                    'has_log_input': has_log_input
                })
                
                if has_log_input:
                    deny_rules_with_log_input.append(rule_text)
                else:
                    deny_rules_without_log_input.append(rule_text)
        
        # NSO standard ACL
        std_rules = acl_config.get('std-access-list-rule', [])
        for rule in std_rules:
            rule_text = rule.get('rule', '')
            if 'deny' in rule_text.lower():
                has_log_input = 'log-input' in rule_text.lower()
                
                deny_rules_found.append({
                    'rule': rule_text,
                    'type': 'standard',
                    'has_log_input': has_log_input
                })
                
                if has_log_input:
                    deny_rules_with_log_input.append(rule_text)
                else:
                    deny_rules_without_log_input.append(rule_text)
    
    return deny_rules_found, deny_rules_with_log_input, deny_rules_without_log_input


def test_acl_log_input():
    """
    Test that ACL deny statements are configured with log-input parameter.
    
    STIG V-215673 (CISC-ND-000290) requires that the router produces audit log records 
    containing information to establish where the events occurred. This is accomplished by 
    configuring the log-input parameter on deny statements in ACLs, which logs:
    - Interface where packet was received
    - Source MAC address
    - Source IP address
    
    The test validates that:
    1. ACLs with deny rules are identified
    2. Deny rules have log-input configured
    
    This ensures dropped packets can be traced to their source for forensic analysis.
    
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
            
            # Track ACLs and deny rules
            acls_checked = {}
            acls_with_non_compliant_denies = []
            
            # Get ACL configurations
            if data_format == 'native':
                # Native format ACLs
                ip_config = config.get('ip', {})
                access_list_config = ip_config.get('access-list', {})
                
                # Standard ACLs
                std_acls = access_list_config.get('Cisco-IOS-XE-acl:standard', [])
                for acl in std_acls:
                    acl_name = acl.get('name', '')
                    deny_found, with_log, without_log = check_acl_deny_rules_for_log_input(
                        acl_name, acl, data_format
                    )
                    
                    if deny_found:
                        acls_checked[acl_name] = {
                            'type': 'standard',
                            'deny_rules_total': len(deny_found),
                            'deny_rules_with_log_input': len(with_log),
                            'deny_rules_without_log_input': len(without_log),
                            'non_compliant_sequences': without_log
                        }
                        
                        if without_log:
                            acls_with_non_compliant_denies.append(acl_name)
                
                # Extended ACLs
                ext_acls = access_list_config.get('Cisco-IOS-XE-acl:extended', [])
                for acl in ext_acls:
                    acl_name = acl.get('name', '')
                    deny_found, with_log, without_log = check_acl_deny_rules_for_log_input(
                        acl_name, acl, data_format
                    )
                    
                    if deny_found:
                        acls_checked[acl_name] = {
                            'type': 'extended',
                            'deny_rules_total': len(deny_found),
                            'deny_rules_with_log_input': len(with_log),
                            'deny_rules_without_log_input': len(without_log),
                            'non_compliant_sequences': without_log
                        }
                        
                        if without_log:
                            acls_with_non_compliant_denies.append(acl_name)
            
            else:  # NSO format
                ip_config = config.get('tailf-ned-cisco-ios:ip', {})
                access_list_config = ip_config.get('access-list', {})
                
                # Standard ACLs
                std_acls = access_list_config.get('standard', {}).get('std-named-acl', [])
                for acl in std_acls:
                    acl_name = acl.get('name', '')
                    deny_found, with_log, without_log = check_acl_deny_rules_for_log_input(
                        acl_name, acl, data_format
                    )
                    
                    if deny_found:
                        acls_checked[acl_name] = {
                            'type': 'standard',
                            'deny_rules_total': len(deny_found),
                            'deny_rules_with_log_input': len(with_log),
                            'deny_rules_without_log_input': len(without_log),
                            'non_compliant_rules': without_log
                        }
                        
                        if without_log:
                            acls_with_non_compliant_denies.append(acl_name)
                
                # Extended ACLs
                ext_acls = access_list_config.get('extended', {}).get('ext-named-acl', [])
                for acl in ext_acls:
                    acl_name = acl.get('name', '')
                    deny_found, with_log, without_log = check_acl_deny_rules_for_log_input(
                        acl_name, acl, data_format
                    )
                    
                    if deny_found:
                        acls_checked[acl_name] = {
                            'type': 'extended',
                            'deny_rules_total': len(deny_found),
                            'deny_rules_with_log_input': len(with_log),
                            'deny_rules_without_log_input': len(without_log),
                            'non_compliant_rules': without_log
                        }
                        
                        if without_log:
                            acls_with_non_compliant_denies.append(acl_name)
            
            # Overall compliance
            overall_compliant = len(acls_with_non_compliant_denies) == 0
            
            results[device_name] = {
                'acls_with_denies': len(acls_checked),
                'acls_checked': acls_checked,
                'acls_with_non_compliant_denies': acls_with_non_compliant_denies,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append(f"\nACLs with deny rules missing log-input:")
                
                for acl_name in acls_with_non_compliant_denies:
                    acl_info = acls_checked[acl_name]
                    error_parts.append(f"\n  ACL: {acl_name} ({acl_info['type']})")
                    error_parts.append(f"    Total deny rules: {acl_info['deny_rules_total']}")
                    error_parts.append(f"    With log-input: {acl_info['deny_rules_with_log_input']}")
                    error_parts.append(f"    WITHOUT log-input: {acl_info['deny_rules_without_log_input']}")
                    
                    non_compliant = acl_info.get('non_compliant_sequences') or acl_info.get('non_compliant_rules', [])
                    if non_compliant:
                        error_parts.append(f"    Non-compliant sequences/rules: {', '.join(str(x) for x in non_compliant)}")
                
                error_parts.append("\nDeny statements must have log-input to establish where events occurred!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# ip access-list extended BLOCK_INBOUND")
                error_parts.append("  R1(config-ext-nacl)# deny icmp any any log-input")
                error_parts.append("  R1(config-ext-nacl)# end")
                error_parts.append("\nlog-input provides:")
                error_parts.append("  - Interface where packet was received")
                error_parts.append("  - Source MAC address")
                error_parts.append("  - This information is critical for forensic analysis")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking ACL log-input configuration on {device_name}: {e}"
    
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
            acls_with_denies = result.get('acls_with_denies', 0)
            if acls_with_denies > 0:
                print(f"  ✓ {acls_with_denies} ACL(s) with deny rules checked")
                print(f"  ✓ All deny rules have log-input configured")
                for acl_name, acl_info in result.get('acls_checked', {}).items():
                    print(f"  ✓ {acl_name}: {acl_info['deny_rules_with_log_input']} deny rule(s) with log-input")
            else:
                print(f"  ℹ No ACLs with deny rules found (compliance not applicable)")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  ACLs with deny rules: {result.get('acls_with_denies', 0)}")
                print(f"  ACLs with non-compliant denies: {len(result.get('acls_with_non_compliant_denies', []))}")
                for acl_name in result.get('acls_with_non_compliant_denies', []):
                    print(f"  ✗ {acl_name}")


if __name__ == "__main__":
    test_acl_log_input()
