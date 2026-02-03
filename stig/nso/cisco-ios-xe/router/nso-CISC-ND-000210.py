"""
STIG ID: CISC-ND-000210
Finding ID: V-215670
Rule ID: SV-215670r984088_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96035; SV-105173

Extraction Method: NSO
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to generate audit records for privileged activities 
or other system-level access.

Discussion:
Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events relating 
to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., 
module or policy filter). Privileged activities include, for example, establishing accounts, 
performing system integrity checks, or configuring access authorizations (i.e., permissions, 
privileges).

The logging userinfo global configuration command will generate a log when a user increases his 
or her privilege level. The archive log config command will log all configuration changes to the 
router, ensuring that administrative activities are captured and can be audited.

Check Text:
Review the router configuration to verify that logging is configured to audit privileged activities.

hostname R1
!
logging userinfo
!
archive
  log config
    logging enable
!

Note: The logging userinfo global configuration command will generate a log when a user increases 
his or her privilege level.

If logging of administrator activity is not configured, this is a finding.

Fix Text:
Configure the router to log administrator activity as shown in the example below.

R1(config)# logging userinfo
R1(config)# archive
R1(config-archive)# log config
R1(config-archive-log-cfg)# logging enable
R1(config-archive-log-cfg)# end

References:
CCI: CCI-000166, CCI-002234, CCI-000172
NIST SP 800-53 :: AU-10, AU-12 c
NIST SP 800-53 Revision 4 :: AU-10, AU-12 c, AC-6 (9)
NIST SP 800-53 Revision 5 :: AU-10, AU-12 c, AC-6 (9)
NIST SP 800-53A :: AU-10.1, AU-12.1 (iv)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000210"
FINDING_ID = "V-215670"
RULE_ID = "SV-215670r984088_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "nso"
TITLE = "Router must generate audit records for privileged activities"


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


def test_admin_activity_logging():
    """
    Test that logging is configured to audit privileged activities and administrator actions.
    
    STIG V-215670 (CISC-ND-000210) requires that the router generates audit records for 
    privileged activities or other system-level access. This is accomplished by:
    1. Enabling logging userinfo to log privilege level changes
    2. Enabling archive log config to log configuration changes
    
    The test validates that:
    1. logging userinfo is configured
    2. Archive log config logging is enabled
    
    This ensures all privileged and administrative activities are logged for audit purposes.
    
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
            logging_userinfo_enabled = False
            archive_configured = False
            log_config_configured = False
            archive_logging_enabled = False
            
            # Check logging userinfo
            # NSO format: tailf-ned-cisco-ios:logging -> userinfo
            logging_config = config.get('tailf-ned-cisco-ios:logging', {})
            if logging_config:
                userinfo = logging_config.get('userinfo')
                if userinfo is not None:
                    logging_userinfo_enabled = True
            
            # Check archive configuration
            # Path: tailf-ned-cisco-ios:archive -> log -> config -> logging -> enable
            archive_config = config.get('tailf-ned-cisco-ios:archive', {})
            
            if archive_config:
                archive_configured = True
                
                log_config = archive_config.get('log', {})
                if log_config:
                    log_config_configured = True
                    
                    config_logging = log_config.get('config', {})
                    if config_logging:
                        logging_config_section = config_logging.get('logging', {})
                        if 'enable' in logging_config_section:
                            archive_logging_enabled = True
            
            # Overall compliance - both logging userinfo and archive logging must be enabled
            overall_compliant = logging_userinfo_enabled and archive_logging_enabled
            
            results[device_name] = {
                'logging_userinfo_enabled': logging_userinfo_enabled,
                'archive_configured': archive_configured,
                'log_config_configured': log_config_configured,
                'archive_logging_enabled': archive_logging_enabled,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not logging_userinfo_enabled:
                    error_parts.append("  ✗ logging userinfo is NOT configured")
                    error_parts.append("    (Required to log privilege level changes)")
                
                if not archive_configured:
                    error_parts.append("  ✗ Archive is NOT configured")
                elif not log_config_configured:
                    error_parts.append("  ✗ Archive log config is NOT configured")
                elif not archive_logging_enabled:
                    error_parts.append("  ✗ Archive log config logging is NOT enabled")
                
                error_parts.append("\nAdministrator activity is NOT being fully logged!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# logging userinfo")
                error_parts.append("  R1(config)# archive")
                error_parts.append("  R1(config-archive)# log config")
                error_parts.append("  R1(config-archive-log-cfg)# logging enable")
                error_parts.append("  R1(config-archive-log-cfg)# end")
                error_parts.append("\nNote:")
                error_parts.append("  - 'logging userinfo' logs privilege level changes")
                error_parts.append("  - 'archive log config' logs all configuration changes")
                error_parts.append("  - View logs with 'show archive log config all'")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking admin activity logging on {device_name}: {e}"
    
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
            print(f"  ✓ logging userinfo configured")
            print(f"  ✓ Archive configured")
            print(f"  ✓ Log config configured")
            print(f"  ✓ Archive logging enabled")
            print(f"  ✓ Administrator activities are being logged")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  logging userinfo: {'✓' if result.get('logging_userinfo_enabled') else '✗'}")
                print(f"  Archive configured: {'✓' if result.get('archive_configured') else '✗'}")
                print(f"  Log config configured: {'✓' if result.get('log_config_configured') else '✗'}")
                print(f"  Archive logging enabled: {'✓' if result.get('archive_logging_enabled') else '✗'}")


if __name__ == "__main__":
    test_admin_activity_logging()
