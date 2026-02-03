"""
STIG ID: CISC-ND-000880
Finding ID: V-215689
Rule ID: SV-215689r961290_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96103; SV-105241

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to automatically audit account enabling actions.

Discussion:
Once an attacker establishes initial access to a system, the attacker often attempts to create 
a persistent method of reestablishing access. One way to accomplish this is for the attacker to 
enable an existing disabled account. Auditing account enabling actions provides logging that can 
be used for forensic purposes.

Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events relating 
to an incident, or identify those responsible for one.

The archive log config command captures all configuration changes, including account enabling 
actions such as removing the "shutdown" state from user accounts or enabling previously disabled 
authentication methods. This audit trail is essential for detecting unauthorized account 
manipulation and investigating security incidents.

Check Text:
Review the router configuration to verify that it automatically audits account enabling actions.

archive
  log config
    logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account enabling is not automatically audited, this is a finding.

Fix Text:
Configure the router to log account enabling using the following commands:

R4(config)# archive
R4(config-archive)# log config
R4(config-archive-log-cfg)# logging enable
R4(config-archive-log-cfg)# end

References:
CCI: CCI-002130
NIST SP 800-53 Revision 4 :: AC-2 (4)
NIST SP 800-53 Revision 5 :: AC-2 (4)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000880"
FINDING_ID = "V-215689"
RULE_ID = "SV-215689r961290_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must automatically audit account enabling actions"


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


def test_account_enabling_audit():
    """
    Test that archive log config logging is enabled to automatically audit account enabling actions.
    
    STIG V-215689 (CISC-ND-000880) requires that the router automatically audits account 
    enabling actions. This is accomplished by enabling configuration archiving with logging, 
    which records all configuration changes including:
    - Account enabling actions (removing shutdown, enabling auth methods)
    - Who made the changes
    - When the changes were made
    - Full context of the changes
    
    The test validates that:
    1. Archive logging is configured
    2. Logging is enabled
    
    This ensures account manipulation can be detected and investigated for security incidents.
    
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
            archive_configured = False
            log_config_configured = False
            logging_enabled = False
            
            # Check archive configuration
            # Native format: archive -> log -> config -> logging -> enable
            # NSO format: tailf-ned-cisco-ios:archive -> log -> config -> logging -> enable
            
            if data_format == 'nso':
                archive_config = config.get('tailf-ned-cisco-ios:archive', {})
            else:
                archive_config = config.get('archive', {})
            
            if archive_config:
                archive_configured = True
                
                # Check log config
                log_config = archive_config.get('log', {})
                if log_config:
                    log_config_configured = True
                    
                    # Check config logging
                    config_logging = log_config.get('config', {})
                    if config_logging:
                        # Check if logging is enabled
                        logging_config = config_logging.get('logging', {})
                        
                        # The 'enable' key can be a list with [None] or just present as a key
                        if 'enable' in logging_config:
                            logging_enabled = True
            
            # Overall compliance - logging must be enabled
            overall_compliant = logging_enabled
            
            results[device_name] = {
                'archive_configured': archive_configured,
                'log_config_configured': log_config_configured,
                'logging_enabled': logging_enabled,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not archive_configured:
                    error_parts.append("  ✗ Archive is NOT configured")
                elif not log_config_configured:
                    error_parts.append("  ✗ Archive log config is NOT configured")
                elif not logging_enabled:
                    error_parts.append("  ✗ Archive log config logging is NOT enabled")
                
                error_parts.append("\nAccount enabling actions are NOT being automatically audited!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R4(config)# archive")
                error_parts.append("  R4(config-archive)# log config")
                error_parts.append("  R4(config-archive-log-cfg)# logging enable")
                error_parts.append("  R4(config-archive-log-cfg)# end")
                error_parts.append("\nNote: View logs with 'show archive log config all'")
                error_parts.append("\nThis captures:")
                error_parts.append("  - Account enabling actions (removing shutdown, enabling auth)")
                error_parts.append("  - Who made the changes")
                error_parts.append("  - When the changes were made")
                error_parts.append("  - Full context for security incident investigation")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking archive log config for account enabling audit on {device_name}: {e}"
    
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
            print(f"  ✓ Archive configured")
            print(f"  ✓ Log config configured")
            print(f"  ✓ Logging enabled")
            print(f"  ✓ Account enabling actions are automatically audited")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Archive configured: {'✓' if result.get('archive_configured') else '✗'}")
                print(f"  Log config configured: {'✓' if result.get('log_config_configured') else '✗'}")
                print(f"  Logging enabled: {'✓' if result.get('logging_enabled') else '✗'}")


if __name__ == "__main__":
    test_account_enabling_audit()
