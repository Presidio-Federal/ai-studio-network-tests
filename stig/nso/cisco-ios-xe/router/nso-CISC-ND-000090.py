"""
STIG ID: CISC-ND-000090
Finding ID: V-215663
Rule ID: SV-215663r960777_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96015; SV-105153

Extraction Method: NSO
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to automatically audit account creation.

Discussion:
Since the accounts in the network device are privileged or system-level accounts, account 
management is vital to the security of the network device. Account management by a 
designated authority ensures access to the network device is being controlled in a secure 
manner by granting access to only authorized personnel with the appropriate and necessary 
privileges.

Auditing account creation along with an automatic notification to appropriate individuals 
will provide the necessary reconciliation that account management procedures are being 
followed. If account creation is not audited, reconciliation of account management 
procedures cannot be tracked, and unauthorized accounts may be created without detection.

Check Text:
Review the router configuration to determine if it automatically audits account creation. 
The configuration should look similar to the example below:

archive
  log config
    logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account creation is not automatically audited, this is a finding.

Fix Text:
Configure the router to log account creation using the following commands:

R4(config)# archive
R4(config-archive)# log config
R4(config-archive-log-cfg)# logging enable
R4(config-archive-log-cfg)# end

References:
CCI: CCI-000018
NIST SP 800-53 :: AC-2 (4)
NIST SP 800-53 Revision 4 :: AC-2 (4)
NIST SP 800-53 Revision 5 :: AC-2 (4)
NIST SP 800-53A :: AC-2 (4).1 (i and ii)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000090"
FINDING_ID = "V-215663"
RULE_ID = "SV-215663r960777_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
TITLE = "Router must automatically audit account creation"


def load_test_data(file_path):
    """Load test data from JSON or YAML file (NSO format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle multiple formats
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_archive_log_config_enabled():
    """
    Test that archive log config logging is enabled to audit account creation.
    
    STIG V-215663 (CISC-ND-000090) requires that the router automatically audits 
    account creation. This is accomplished by enabling configuration archiving 
    with logging, which records all configuration changes including account creation.
    
    The test validates that:
    1. Archive logging is configured
    2. Logging is enabled
    
    This ensures all account creation actions are automatically tracked and can be 
    audited using "show archive log config all" command.
    
    NSO extraction method: Tests against NSO data models.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            archive_configured = False
            log_config_configured = False
            logging_enabled = False
            
            # Check archive configuration
            # Path: archive -> log -> config -> logging -> enable
            archive_config = config.get('tailf-ned-cisco-ios:archive', {})
            
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
                
                error_parts.append("\nAccount creation is NOT being automatically audited!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R4(config)# archive")
                error_parts.append("  R4(config-archive)# log config")
                error_parts.append("  R4(config-archive-log-cfg)# logging enable")
                error_parts.append("  R4(config-archive-log-cfg)# end")
                error_parts.append("\nNote: View logs with 'show archive log config all'")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking archive log config on {device_name}: {e}"
    
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
            print(f"  ✓ Account creation is automatically audited")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Archive configured: {'✓' if result.get('archive_configured') else '✗'}")
                print(f"  Log config configured: {'✓' if result.get('log_config_configured') else '✗'}")
                print(f"  Logging enabled: {'✓' if result.get('logging_enabled') else '✗'}")


if __name__ == "__main__":
    test_archive_log_config_enabled()
