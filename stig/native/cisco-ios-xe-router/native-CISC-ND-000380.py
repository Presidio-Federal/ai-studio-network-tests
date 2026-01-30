"""
STIG ID: CISC-ND-000380
Finding ID: V-215675
Rule ID: SV-215675r960933_rule
Version: 3, Release: 4
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Group Title: SRG-APP-000119-NDM-000236

Rule Title: The Cisco router must be configured to protect audit information 
            from unauthorized modification.

Discussion:
Audit information includes all information (e.g., audit records, audit settings, 
and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery 
of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the network device must protect audit 
information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon 
system architecture and design. Some commonly employed methods include ensuring 
log files receive the proper file system permissions and limiting log data locations.

Network devices providing a user interface to audit data will leverage user 
permissions and roles identifying the user accessing the data and the corresponding 
rights that the user enjoys in order to make access decisions regarding the 
modification of audit data.

Check Text:
Review the Cisco router configuration to verify that it is compliant with this 
requirement.

Step 1: If persistent logging is enabled as shown in the example below, go to 
step 2. Otherwise, this requirement is not applicable.

logging persistent url disk0:/logfile size 134217728 filesize 16384

Step 2: Verify that the router is not configured with a privilege level other 
than "15" to allow access to the file system as shown in the example below.

file privilege 10

Note: The default privilege level required for access to the file system is "15"; 
hence, the command "file privilege 15" will not be shown in the configuration.

If the router is configured with a privilege level other than "15" to allow access 
to the file system, this is a finding.

Fix Text:
If persistent logging is enabled, configure the router to only allow administrators 
with privilege level "15" access to the file system as shown in the example below.

Router(config)# file privilege 15
Router(config)# end

References:
CCI: CCI-000163: Protect audit information from unauthorized modification.
NIST SP 800-53 :: AU-9
NIST SP 800-53 Revision 4 :: AU-9
NIST SP 800-53 Revision 5 :: AU-9 a
NIST SP 800-53A :: AU-9.1

Cisco IOS Router NDM Security Technical Implementation Guide
Version 3, Release: 4
Benchmark Date: 02 Apr 2025
Vul ID: V-215675
Rule ID: SV-215675r960933_rule
STIG ID: CISC-ND-000380
Severity: CAT II
Classification: Unclass
Legacy IDs: V-96049; SV-105187
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000380"
FINDING_ID = "V-215675"
RULE_ID = "SV-215675r960933_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"


def load_test_data(file_path):
    """Load test data from JSON or YAML file (NSO format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle unwrapped NSO config (config directly at top level)
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    # Handle NSO config without device wrapper
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_audit_information_protection():
    """
    Test that audit information is protected from unauthorized modification.
    
    STIG CISC-ND-000380 requires that if persistent logging is enabled, the 
    router must be configured to only allow privilege level 15 access to the 
    file system to protect audit logs from unauthorized modification.
    
    This test validates:
    1. Checks if persistent logging is configured
    2. If persistent logging is enabled, verifies file privilege is NOT set to 
       a level other than 15
    3. If persistent logging is not enabled, test is not applicable (passes)
    
    Note: Default privilege for file system access is 15. The command "file 
    privilege 15" will not appear in configuration as it's the default.
    
    Native extraction method: Tests against native API/CLI JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            
            persistent_logging_enabled = False
            persistent_logging_url = None
            file_privilege_configured = False
            file_privilege_level = None
            improper_privilege_configured = False
            
            # Step 1: Check if persistent logging is enabled
            logging_config = config.get('tailf-ned-cisco-ios:logging', {})
            
            if 'persistent' in logging_config:
                persistent_logging_enabled = True
                persistent_config = logging_config['persistent']
                
                if isinstance(persistent_config, dict):
                    persistent_logging_url = persistent_config.get('url', 'configured')
            
            # Step 2: Only check file privilege if persistent logging is enabled
            if persistent_logging_enabled:
                # Check file privilege configuration
                file_config = config.get('tailf-ned-cisco-ios:file', {})
                
                if 'privilege' in file_config:
                    file_privilege_configured = True
                    file_privilege_level = file_config.get('privilege')
                    
                    # Finding if privilege level is set to anything other than 15
                    # (Note: privilege 15 is default and won't appear in config)
                    if file_privilege_level is not None and file_privilege_level != 15:
                        improper_privilege_configured = True
                
                # Compliant if persistent logging is enabled AND 
                # (no file privilege configured OR file privilege is 15)
                overall_compliant = not improper_privilege_configured
            else:
                # Not applicable if persistent logging is not enabled
                overall_compliant = True  # N/A = Pass
            
            results[device_name] = {
                'persistent_logging_enabled': persistent_logging_enabled,
                'persistent_logging_url': persistent_logging_url,
                'file_privilege_configured': file_privilege_configured,
                'file_privilege_level': file_privilege_level,
                'improper_privilege_configured': improper_privilege_configured,
                'compliant': overall_compliant,
                'not_applicable': not persistent_logging_enabled
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                error_parts.append(f"  File privilege is set to level {file_privilege_level} (should be 15)")
                error_parts.append("\nFinding:")
                error_parts.append("  The router allows unauthorized access to the file system")
                error_parts.append("  which could permit modification of persistent audit logs.")
                error_parts.append("\nRisk:")
                error_parts.append("  Audit data could be tampered with by users with insufficient")
                error_parts.append("  privileges, compromising forensic analysis capabilities.")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  Router(config)# file privilege 15")
                error_parts.append("\nNote:")
                error_parts.append("  Privilege level 15 is the default. Remove any 'file privilege'")
                error_parts.append("  command that sets a level other than 15.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking audit information protection on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Audit information protected from unauthorized modification")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        
        if result.get('not_applicable'):
            print(f"  Status: Not Applicable (persistent logging not enabled)")
        elif result.get('compliant'):
            print(f"  Persistent logging: {'Enabled' if result.get('persistent_logging_enabled') else 'Disabled'}")
            if result.get('persistent_logging_enabled'):
                print(f"  Logging URL: {result.get('persistent_logging_url')}")
                if result.get('file_privilege_configured'):
                    print(f"  File privilege level: {result.get('file_privilege_level')}")
                else:
                    print(f"  File privilege level: 15 (default)")
            print(f"  STIG {STIG_ID}: COMPLIANT")
        else:
            if 'error' not in result:
                print(f"  Persistent logging: {'Enabled' if result.get('persistent_logging_enabled') else 'Disabled'}")
                print(f"  File privilege configured: {'Yes' if result.get('file_privilege_configured') else 'No'}")
                if result.get('file_privilege_level') is not None:
                    print(f"  Current privilege level: {result.get('file_privilege_level')}")
                print(f"  Required privilege level: 15")


if __name__ == "__main__":
    test_audit_information_protection()
