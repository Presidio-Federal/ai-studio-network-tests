"""
STIG ID: CISC-ND-000280
Finding ID: V-215672
Rule ID: SV-215672r960894_rule
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must produce audit records containing information to 
            establish when (date and time) the events occurred.

Discussion:
It is essential for security personnel to know what is being done, what was attempted, 
where it was done, when it was done, and by whom it was done in order to compile an 
accurate risk assessment. Logging the date and time of each detected event provides a 
means of investigating an attack; recognizing resource utilization or capacity thresholds; 
or identifying an improperly configured network device.

In order to establish and correlate the series of events leading up to an outage or attack, 
it is imperative the date and time are recorded in all log records.

Check Text:
Verify that the router is configured to include the date and time on all log records.

service timestamps log datetime localtime

If time stamps is not configured, this is a finding.

Fix Text:
Configure the router to include the date and time on all log records.

R1(config)# service timestamps log datetime localtime

References:
CCI: CCI-000131
NIST SP 800-53 :: AU-3
NIST SP 800-53 Revision 4 :: AU-3
NIST SP 800-53 Revision 5 :: AU-3 b
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000280"
FINDING_ID = "V-215672"
RULE_ID = "SV-215672r960894_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must produce audit records with date and time stamps"


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
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_service_timestamps_log_configured():
    """
    Test that service timestamps log datetime is configured.
    
    STIG V-215672 (CISC-ND-000280) requires that the router produces audit records 
    containing date and time information for all logged events. This is accomplished 
    by configuring service timestamps for log messages.
    
    The test validates that:
    1. Service timestamps is configured
    2. Log timestamps are enabled
    3. Datetime format is used
    
    This ensures all log records include when events occurred, which is essential for 
    security investigations, correlation, and compliance.
    
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
            
            # Initialize compliance flags
            service_timestamps_configured = False
            log_timestamps_configured = False
            datetime_configured = False
            
            # Check service timestamps configuration
            # Path: service -> timestamps -> log -> datetime
            service_config = config.get('tailf-ned-cisco-ios:service', {})
            
            if 'timestamps' in service_config:
                service_timestamps_configured = True
                timestamps = service_config['timestamps']
                
                # Check log timestamps
                if 'log' in timestamps:
                    log_timestamps_configured = True
                    log_config = timestamps['log']
                    
                    # Check datetime format
                    # Can be: datetime with localtime, msec, or other options
                    if 'datetime' in log_config:
                        datetime_configured = True
            
            # Overall compliance - datetime timestamps must be configured for logs
            overall_compliant = datetime_configured
            
            results[device_name] = {
                'service_timestamps_configured': service_timestamps_configured,
                'log_timestamps_configured': log_timestamps_configured,
                'datetime_configured': datetime_configured,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not service_timestamps_configured:
                    error_parts.append("  ✗ Service timestamps is NOT configured")
                elif not log_timestamps_configured:
                    error_parts.append("  ✗ Log timestamps are NOT configured")
                elif not datetime_configured:
                    error_parts.append("  ✗ Datetime format is NOT configured for log timestamps")
                
                error_parts.append("\nLog records do NOT contain date/time information!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R1(config)# service timestamps log datetime localtime")
                error_parts.append("\nThis ensures:")
                error_parts.append("  - All log messages include timestamp")
                error_parts.append("  - Date and time are recorded for security investigations")
                error_parts.append("  - Events can be correlated chronologically")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking service timestamps on {device_name}: {e}"
    
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
            print(f"  ✓ Service timestamps configured")
            print(f"  ✓ Log timestamps configured")
            print(f"  ✓ Datetime format enabled")
            print(f"  ✓ All log records include date/time")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Service timestamps: {'✓' if result.get('service_timestamps_configured') else '✗'}")
                print(f"  Log timestamps: {'✓' if result.get('log_timestamps_configured') else '✗'}")
                print(f"  Datetime format: {'✓' if result.get('datetime_configured') else '✗'}")


if __name__ == "__main__":
    test_service_timestamps_log_configured()
