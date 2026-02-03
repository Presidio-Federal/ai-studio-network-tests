"""
STIG ID: CISC-ND-000980
Finding ID: V-215691
Rule ID: SV-215691r961392_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96115; SV-105253

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to allocate audit record storage capacity in 
accordance with organization-defined audit record storage requirements.

Discussion:
In order to ensure network devices have a sufficient storage capacity in which to write the 
audit logs, they must be able to allocate audit record storage capacity. The task of allocating 
audit record storage capacity is usually performed during initial installation of the network 
device and is closely associated with the storage capacity requirements.

Network devices must have the capability to allocate audit log storage capacity when needed. 
Without the ability to allocate sufficient storage capacity for audit logs, network devices 
may not be able to capture the required audit information. This could lead to critical security 
events going unrecorded, hindering incident detection and forensic investigation.

The logging buffer size determines how many log entries can be stored locally on the device. 
Organizations should define appropriate buffer sizes based on their audit retention requirements, 
logging volume, and available device memory. A properly sized logging buffer ensures that 
important security events are captured and retained until they can be forwarded to central 
logging systems or reviewed by administrators.

Check Text:
Verify that the Cisco router is configured with a logging buffer size.

logging buffered <size> informational

If a logging buffer size is not configured, this is a finding.

If the Cisco router is not configured to allocate audit record storage capacity in accordance 
with organization-defined audit record storage requirements, this is a finding.

Fix Text:
Configure the buffer size for logging as shown in the example below.

R2(config)# logging buffered <size> informational
R2(config)# end

Note: Replace <size> with an appropriate value based on organization-defined requirements.
Common values range from 16384 to 64000 or higher depending on device capabilities and 
audit retention needs.

References:
CCI: CCI-001849
NIST SP 800-53 Revision 4 :: AU-4
NIST SP 800-53 Revision 5 :: AU-4
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000980"
FINDING_ID = "V-215691"
RULE_ID = "SV-215691r961392_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must allocate audit record storage capacity per org requirements"

# Minimum buffer size (in bytes) - organizations may require higher values
# This is a baseline to ensure some buffer is configured
MIN_BUFFER_SIZE = 4096


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


def test_logging_buffer_allocation():
    """
    Test that logging buffer is configured to allocate audit record storage capacity.
    
    STIG V-215691 (CISC-ND-000980) requires that the router allocates audit record storage 
    capacity in accordance with organization-defined requirements. This is accomplished by 
    configuring a logging buffer with an appropriate size.
    
    The test validates that:
    1. Logging buffered configuration is present
    2. A buffer size is configured (minimum baseline check)
    3. Organizations should verify the size meets their specific requirements
    
    The logging buffer stores audit records locally on the device, ensuring critical security 
    events are captured and retained. A properly sized buffer prevents audit record loss and 
    enables effective incident detection and forensic investigation.
    
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
            logging_configured = False
            buffered_configured = False
            buffer_size = None
            severity_level = None
            size_adequate = False
            
            # Check logging configuration
            if data_format == 'nso':
                # NSO format: tailf-ned-cisco-ios:logging -> buffered -> buffer-size
                logging_config = config.get('tailf-ned-cisco-ios:logging', {})
            else:
                # Native format: logging -> buffered -> size-value
                logging_config = config.get('logging', {})
            
            if logging_config:
                logging_configured = True
                
                # Check buffered configuration
                buffered_config = logging_config.get('buffered', {})
                if buffered_config:
                    buffered_configured = True
                    
                    # Get buffer size - different key names in different formats
                    if data_format == 'nso':
                        buffer_size = buffered_config.get('buffer-size')
                    else:
                        buffer_size = buffered_config.get('size-value')
                    
                    severity_level = buffered_config.get('severity-level')
                    
                    # Check if buffer size meets minimum requirement
                    if buffer_size is not None and buffer_size >= MIN_BUFFER_SIZE:
                        size_adequate = True
            
            # Overall compliance - buffer must be configured with adequate size
            overall_compliant = buffered_configured and size_adequate
            
            results[device_name] = {
                'logging_configured': logging_configured,
                'buffered_configured': buffered_configured,
                'buffer_size': buffer_size,
                'severity_level': severity_level,
                'size_adequate': size_adequate,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not logging_configured:
                    error_parts.append("  ✗ Logging is NOT configured")
                elif not buffered_configured:
                    error_parts.append("  ✗ Logging buffered is NOT configured")
                elif not size_adequate:
                    if buffer_size is None:
                        error_parts.append("  ✗ Buffer size is NOT configured")
                    else:
                        error_parts.append(f"  ✗ Buffer size {buffer_size} is below minimum {MIN_BUFFER_SIZE} bytes")
                
                error_parts.append("\nAudit record storage capacity is NOT properly allocated!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R2(config)# logging buffered <size> informational")
                error_parts.append("  R2(config)# end")
                error_parts.append("\nRecommended buffer sizes:")
                error_parts.append("  - Minimum: 16384 bytes (16 KB)")
                error_parts.append("  - Typical: 32768-64000 bytes (32-64 KB)")
                error_parts.append("  - High volume: 128000+ bytes (128+ KB)")
                error_parts.append("\nNote: Configure size based on organization-defined audit record")
                error_parts.append("      retention requirements and expected logging volume.")
                error_parts.append("\nWithout adequate buffer capacity:")
                error_parts.append("  - Critical security events may not be captured")
                error_parts.append("  - Audit records may be lost before forwarding")
                error_parts.append("  - Forensic investigation may be hindered")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking logging buffer configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Minimum Buffer Size: {MIN_BUFFER_SIZE} bytes")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ Logging configured")
            print(f"  ✓ Buffered logging configured")
            print(f"  ✓ Buffer size: {result['buffer_size']} bytes")
            if result.get('severity_level'):
                print(f"  ✓ Severity level: {result['severity_level']}")
            print(f"  ✓ Audit record storage capacity properly allocated")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Logging configured: {'✓' if result.get('logging_configured') else '✗'}")
                print(f"  Buffered configured: {'✓' if result.get('buffered_configured') else '✗'}")
                if result.get('buffer_size') is not None:
                    print(f"  Buffer size: {result['buffer_size']} bytes")
                if result.get('severity_level'):
                    print(f"  Severity level: {result['severity_level']}")


if __name__ == "__main__":
    test_logging_buffer_allocation()
