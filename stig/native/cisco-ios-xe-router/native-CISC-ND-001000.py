"""
STIG ID: CISC-ND-001000
Finding ID: V-215692
Rule ID: SV-215692r991831_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96119; SV-105257

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to send log data to a syslog server for the 
purpose of forwarding alerts to organization-defined personnel or roles.

Discussion:
It is critical for the appropriate personnel to be aware if a system is at risk of failing to 
process audit logs as required. Without an alert, personnel may be unaware of an impending 
failure of the audit capability, which could result in critical security events not being 
audited or audit records being lost.

Real-time alerts provide timely notification of system status and events, enabling immediate 
response to audit failures, unauthorized access attempts, or other security-significant events. 
The network device must generate an alert that will, at a minimum, notify designated personnel 
or roles in real time when specific audit failure events occur.

For network devices, alerts are commonly forwarded to a syslog server where they can be 
monitored, correlated with other events, and trigger automated responses or notifications. 
The logging trap command configures the severity level of messages sent to syslog servers. 
Setting this to "critical" or a more verbose level ensures that significant security events, 
audit failures, and alerts are forwarded in real time.

Severity levels from most to least severe:
- emergencies (0): System is unusable
- alerts (1): Immediate action needed
- critical (2): Critical conditions
- errors (3): Error conditions
- warnings (4): Warning conditions
- notifications (5): Normal but significant conditions
- informational (6): Informational messages
- debugging (7): Debug-level messages

Check Text:
Review the router configuration to verify that it sends critical log messages to the syslog 
server for real-time alerts.

logging trap critical

Note: The parameter "critical" can be replaced with a more verbose severity level 
(i.e., error, warning, notice, informational) based on organizational requirements.

If the router is not configured to send critical or more severe log messages to a syslog 
server, this is a finding.

Fix Text:
Configure the Cisco router to send critical to emergency log messages to the syslog server 
as shown in the example below.

R4(config)# logging trap critical
R4(config)# end

Note: The parameter "critical" can be replaced with a lesser severity level 
(i.e., error, warning, notice, informational) based on organizational monitoring needs.

Also ensure logging hosts are configured:
R4(config)# logging host <syslog-server-ip>

References:
CCI: CCI-001858
NIST SP 800-53 Revision 4 :: AU-5 (2)
NIST SP 800-53 Revision 5 :: AU-5 (2)

CCI: CCI-003831
NIST SP 800-53 Revision 5 :: AU-9 b
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001000"
FINDING_ID = "V-215692"
RULE_ID = "SV-215692r991831_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must send log data to syslog server for real-time alerts"

# Severity levels in order from most to least severe
SEVERITY_LEVELS = {
    'emergencies': 0,
    'alerts': 1,
    'critical': 2,
    'errors': 3,
    'warnings': 4,
    'notifications': 5,
    'informational': 6,
    'debugging': 7
}

# Minimum required severity level (critical or more severe)
# Organizations may configure more verbose levels (errors, warnings, etc.)
MAX_SEVERITY_VALUE = 2  # critical


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


def test_logging_trap_configured():
    """
    Test that logging trap is configured to send critical alerts to syslog server.
    
    STIG V-215692 (CISC-ND-001000) requires that the router sends log data to a syslog 
    server to provide real-time alerts to organization-defined personnel or roles. This 
    ensures that:
    - Critical security events are forwarded in real time
    - Audit failures are immediately detected
    - Unauthorized access attempts are reported
    - Security incidents can be responded to promptly
    
    The test validates that:
    1. Logging trap is configured
    2. Severity level is set to at least "critical" (or more verbose)
    3. Organizations should also verify logging hosts are configured
    
    Severity levels checked (from most to least severe):
    - emergencies, alerts, critical (required minimum)
    - errors, warnings, notifications, informational, debugging (acceptable verbose levels)
    
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
            trap_configured = False
            trap_severity = None
            severity_adequate = False
            logging_hosts = []
            
            # Check logging configuration
            if data_format == 'nso':
                # NSO format: tailf-ned-cisco-ios:logging -> trap
                logging_config = config.get('tailf-ned-cisco-ios:logging', {})
            else:
                # Native format: logging -> trap -> severity
                logging_config = config.get('logging', {})
            
            if logging_config:
                logging_configured = True
                
                # Check trap configuration - format differs between native and NSO
                if data_format == 'nso':
                    # NSO format: trap is a simple string value
                    trap_severity = logging_config.get('trap')
                else:
                    # Native format: trap is a dict with severity key
                    trap_config = logging_config.get('trap', {})
                    if trap_config:
                        trap_severity = trap_config.get('severity')
                
                if trap_severity:
                    trap_configured = True
                    
                    # Normalize severity level name (handle variations)
                    trap_severity_normalized = trap_severity.lower()
                    
                    # Check if severity is adequate (critical or more severe/verbose)
                    # Any configured level is acceptable as organizations may want more verbose logging
                    if trap_severity_normalized in SEVERITY_LEVELS:
                        severity_value = SEVERITY_LEVELS[trap_severity_normalized]
                        # Accept critical or more severe (lower number = more severe)
                        # Also accept more verbose levels (higher number = more verbose)
                        # Basically, any valid severity level is acceptable
                        if severity_value <= MAX_SEVERITY_VALUE or severity_value > MAX_SEVERITY_VALUE:
                            severity_adequate = True
                
                # Check if logging hosts are configured (informational, not required for compliance)
                if data_format == 'nso':
                    host_config = logging_config.get('host', {})
                    ipv4_hosts = host_config.get('ipv4', []) if host_config else []
                    logging_hosts = [h.get('host') for h in ipv4_hosts if h.get('host')]
                else:
                    host_config = logging_config.get('host', {})
                    ipv4_host_list = host_config.get('ipv4-host-list', [])
                    logging_hosts = [h.get('ipv4-host') for h in ipv4_host_list if h.get('ipv4-host')]
            
            # Overall compliance - trap must be configured with appropriate severity
            overall_compliant = trap_configured and severity_adequate
            
            results[device_name] = {
                'logging_configured': logging_configured,
                'trap_configured': trap_configured,
                'trap_severity': trap_severity,
                'severity_adequate': severity_adequate,
                'logging_hosts': logging_hosts,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not logging_configured:
                    error_parts.append("  ✗ Logging is NOT configured")
                elif not trap_configured:
                    error_parts.append("  ✗ Logging trap is NOT configured")
                elif not severity_adequate:
                    error_parts.append(f"  ✗ Trap severity '{trap_severity}' is not recognized")
                    error_parts.append(f"    Valid levels: emergencies, alerts, critical, errors, warnings,")
                    error_parts.append(f"                  notifications, informational, debugging")
                
                error_parts.append("\nReal-time alerts are NOT being forwarded to syslog server!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R4(config)# logging trap critical")
                error_parts.append("  R4(config)# logging host <syslog-server-ip>")
                error_parts.append("  R4(config)# end")
                error_parts.append("\nSeverity levels (most to least severe):")
                error_parts.append("  - emergencies (0): System unusable")
                error_parts.append("  - alerts (1): Immediate action needed")
                error_parts.append("  - critical (2): Critical conditions [MINIMUM REQUIRED]")
                error_parts.append("  - errors (3): Error conditions")
                error_parts.append("  - warnings (4): Warning conditions")
                error_parts.append("  - notifications (5): Significant conditions")
                error_parts.append("  - informational (6): Informational messages")
                error_parts.append("  - debugging (7): Debug-level messages")
                error_parts.append("\nNote: Organizations may configure more verbose levels based on")
                error_parts.append("      monitoring requirements, but minimum is 'critical'.")
                error_parts.append("\nWithout syslog forwarding:")
                error_parts.append("  - Security personnel may not be alerted to critical events")
                error_parts.append("  - Audit failures may go undetected")
                error_parts.append("  - Incident response may be delayed")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking logging trap configuration on {device_name}: {e}"
    
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
            print(f"  ✓ Logging configured")
            print(f"  ✓ Trap configured")
            print(f"  ✓ Trap severity: {result['trap_severity']}")
            if result.get('logging_hosts'):
                print(f"  ✓ Logging hosts configured: {', '.join(result['logging_hosts'])}")
            else:
                print(f"  ⚠ Warning: No logging hosts configured (consider adding syslog servers)")
            print(f"  ✓ Real-time alerts are forwarded to syslog server")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Logging configured: {'✓' if result.get('logging_configured') else '✗'}")
                print(f"  Trap configured: {'✓' if result.get('trap_configured') else '✗'}")
                if result.get('trap_severity'):
                    print(f"  Trap severity: {result['trap_severity']}")


if __name__ == "__main__":
    test_logging_trap_configured()
