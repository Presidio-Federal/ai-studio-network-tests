"""
PCI-DSS Requirement: 10.3.4
Version: 4.0
Severity: High
Classification: CDE Network Security

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Requirement Title: Date and time are included in all audit log entries.

Discussion:
PCI-DSS requires that all audit logs include date and time stamps to establish when 
events occurred. This is critical for:
- Forensic investigation of security incidents
- Correlating events across multiple systems
- Compliance auditing and reporting
- Incident response and root cause analysis

Without accurate timestamps, it is impossible to establish a timeline of events 
during a security incident or breach investigation.

Check Text:
Review the router configuration to verify timestamps are configured on all logs.

service timestamps log datetime localtime
service timestamps debug datetime localtime

Note: At minimum, log timestamps must be configured. Debug timestamps are recommended 
but not strictly required by PCI-DSS.

If timestamps are not configured on logs, this is a PCI-DSS finding.

Fix Text:
Configure timestamps on all logs.

Router(config)# service timestamps log datetime localtime
Router(config)# service timestamps debug datetime localtime
Router(config)# end

References:
PCI-DSS v4.0 Requirement 10.3.4
CCI: CCI-000131 (NIST AU-3)
"""

import os
import json
import yaml
import pytest

PCI_REQUIREMENT = "10.3.4"
PCI_VERSION = "4.0"
SEVERITY = "High"
CATEGORY = "PCI-DSS"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Date and time included in audit log entries"


def load_test_data(file_path):
    """Load test data from JSON or YAML file (NSO format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: data}
    
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-ios:') for k in data.keys()):
        device_name = data.get('tailf-ned-cisco-ios:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_pci_log_timestamps():
    """
    Test that log timestamps are configured to meet PCI-DSS requirements.
    
    PCI-DSS v4.0 Requirement 10.3.4 mandates that all audit log entries include 
    date and time information. This is essential for security monitoring, incident 
    investigation, and compliance auditing.
    
    This test validates:
    1. Service timestamps is configured
    2. Log timestamps are enabled
    3. Datetime format is used
    
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
            
            service_timestamps_configured = False
            log_timestamps_configured = False
            datetime_configured = False
            
            # Check service timestamps
            service_config = config.get('tailf-ned-cisco-ios:service', {})
            
            if 'timestamps' in service_config:
                service_timestamps_configured = True
                timestamps = service_config['timestamps']
                
                if 'log' in timestamps:
                    log_timestamps_configured = True
                    log_config = timestamps['log']
                    
                    if 'datetime' in log_config:
                        datetime_configured = True
            
            overall_compliant = datetime_configured
            
            results[device_name] = {
                'service_timestamps_configured': service_timestamps_configured,
                'log_timestamps_configured': log_timestamps_configured,
                'datetime_configured': datetime_configured,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is NOT compliant with PCI-DSS {PCI_REQUIREMENT}:"]
                
                if not service_timestamps_configured:
                    error_parts.append("  Service timestamps is NOT configured")
                elif not log_timestamps_configured:
                    error_parts.append("  Log timestamps are NOT configured")
                elif not datetime_configured:
                    error_parts.append("  Datetime format is NOT configured")
                
                error_parts.append("\nPCI-DSS v4.0 Requirement 10.3.4 Violation:")
                error_parts.append("  All audit log entries must include date and time to establish")
                error_parts.append("  when logged events occurred. This is required for:")
                error_parts.append("    - Security incident investigation")
                error_parts.append("    - Event correlation across systems")
                error_parts.append("    - Compliance auditing")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  Router(config)# service timestamps log datetime localtime")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking timestamps on {device_name}: {e}"
    
    print("\nPCI-DSS Compliance Summary:")
    print(f"PCI-DSS Requirement: {PCI_REQUIREMENT}")
    print(f"Version: {PCI_VERSION}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  Service timestamps: Configured")
            print(f"  Log timestamps: Enabled")
            print(f"  Format: datetime")
            print(f"  PCI-DSS 10.3.4: COMPLIANT")
        else:
            if 'error' not in result:
                print(f"  Service timestamps: {'Yes' if result.get('service_timestamps_configured') else 'No'}")
                print(f"  Log timestamps: {'Yes' if result.get('log_timestamps_configured') else 'No'}")
                print(f"  Datetime format: {'Yes' if result.get('datetime_configured') else 'No'}")


if __name__ == "__main__":
    test_pci_log_timestamps()
