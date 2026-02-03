"""
STIG ID: JUSX-DM-000106
Finding ID: V-229028
Rule ID: SV-229028r961863_rule
Version: 3, Release: 3
Severity: CAT II (Medium)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000359-NDM-000298

Rule Title: The Juniper SRX Services Gateway must be configured to send critical 
            and emergency log messages to user terminals to alert authorized 
            personnel of issues requiring immediate attention.

Discussion:
It is critical for the appropriate personnel to be aware of system events that 
may be an indication of a compromised system, ongoing attack, or imminent system 
failure. Without real-time alerting, critical security events may go unnoticed, 
delaying incident response and potentially allowing security breaches to persist.

User terminal logging sends messages directly to logged-in users' terminals, 
providing immediate notification of critical and emergency events without 
requiring users to actively monitor log files.

Critical message types to monitor:
- Emergency (any): System is unusable - immediate action required
- Critical (daemon): Critical conditions requiring urgent attention
- Alert (daemon): Immediate action needed for daemon processes

The asterisk (*) in "user *" sends messages to all logged-in users, ensuring 
that any administrator currently accessing the device will be immediately 
notified of critical events.

Benefits of user terminal logging:
- Immediate visibility of critical events to logged-in administrators
- No delay waiting for log aggregation or SIEM processing
- Direct notification without requiring log file monitoring
- Real-time alerting for emergency conditions
- Complements centralized logging by providing instant local notification

Check Text:
Verify the Juniper SRX is configured to send critical and emergency log messages 
to user terminals.

[edit]
show system syslog user

The configuration should include:
user * {
    any emergency;
    daemon critical;
    daemon alert;
}

If the device is not configured to send critical and emergency messages to user 
terminals, this is a finding.

Fix Text:
Configure the Juniper SRX to send critical and emergency log messages to user 
terminals.

[edit]
set system syslog user * any emergency
set system syslog user * daemon critical
set system syslog user * daemon alert
commit

References:
CCI: CCI-000366: Implement the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53 Revision 4 :: CM-6 b
NIST SP 800-53 Revision 5 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)

CCI: CCI-000372: Verify configuration settings for organization-defined system 
                 components using organization-defined automated mechanisms.
NIST SP 800-53 :: CM-6 (1)
NIST SP 800-53 Revision 4 :: CM-6 (1)
NIST SP 800-53 Revision 5 :: CM-6 (1)
NIST SP 800-53A :: CM-6 (1).1

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-229028
Rule ID: SV-229028r961863_rule
STIG ID: JUSX-DM-000106
Severity: CAT II
Classification: Unclass
Legacy IDs: V-66495; SV-80985
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000106"
FINDING_ID = "V-229028"
RULE_ID = "SV-229028r961863_rule"
SEVERITY = "CAT II"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Required syslog user configurations
REQUIRED_SYSLOG_USER_CONFIGS = [
    {"facility": "any", "severity": "emergency"},
    {"facility": "daemon", "severity": "critical"},
    {"facility": "daemon", "severity": "alert"}
]


def load_test_data(file_path):
    """Load test data from JSON or YAML file (Native Juniper format)."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle Juniper native JSON format
    # Expected structure: {"configuration": {...}}
    if isinstance(data, dict) and 'configuration' in data:
        # Extract hostname if available
        hostname = data.get('configuration', {}).get('system', {}).get('host-name', 'unknown-device')
        return {hostname: data}
    
    # If data is already wrapped with device names
    return data


def test_syslog_user_terminal_notification():
    """
    Test that critical and emergency log messages are sent to user terminals.
    
    STIG JUSX-DM-000106 requires that the Juniper SRX be configured to send 
    critical and emergency log messages to logged-in user terminals for immediate 
    notification of serious system events.
    
    This test validates that syslog is configured with:
    1. user * any emergency - All emergency messages to all users
    2. user * daemon critical - Critical daemon messages to all users
    3. user * daemon alert - Alert daemon messages to all users
    
    Required configuration ensures:
    - Immediate visibility of critical events to administrators
    - Real-time alerting without log file monitoring
    - Notification of system-critical conditions
    - Alert on daemon process issues requiring immediate action
    
    Juniper syslog user configuration structure:
    configuration.system.syslog.user.* (wildcard for all users)
    - Each facility can have one or more severity levels
    - Structure varies: can be single severity or list of severities
    
    Native extraction method: Tests against native Juniper CLI/API JSON output.
    """
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    devices = load_test_data(test_input_file)
    results = {}
    
    for device_name, device_data in devices.items():
        try:
            config = device_data.get('configuration', {})
            
            user_syslog_configured = False
            wildcard_user_found = False
            configured_rules = []
            missing_rules = []
            
            # Check syslog configuration
            # Path: configuration.system.syslog.user.*
            system_config = config.get('system', {})
            syslog_config = system_config.get('syslog', {})
            
            if 'user' in syslog_config:
                user_syslog_configured = True
                user_config = syslog_config.get('user', [])
                
                # user_config is an array of user objects
                # Find the wildcard user (*) in the array
                for user_entry in user_config:
                    if isinstance(user_entry, dict) and user_entry.get('name') == '*':
                        wildcard_user_found = True
                        
                        # Get the contents array which contains facility/severity configs
                        contents = user_entry.get('contents', [])
                        
                        # Check each required configuration
                        for required in REQUIRED_SYSLOG_USER_CONFIGS:
                            facility = required['facility']
                            severity = required['severity']
                            
                            found = False
                            
                            # Search through contents array for matching facility
                            for content in contents:
                                if isinstance(content, dict) and content.get('name') == facility:
                                    # Check if the severity exists as a key
                                    if severity in content:
                                        found = True
                                        break
                            
                            if found:
                                configured_rules.append(f"{facility} {severity}")
                            else:
                                missing_rules.append(f"{facility} {severity}")
                        
                        break  # Found wildcard user, no need to continue
            
            # Determine compliance
            # Must have user syslog configured, wildcard user (*), and all required rules
            overall_compliant = (
                user_syslog_configured and 
                wildcard_user_found and 
                len(missing_rules) == 0
            )
            
            results[device_name] = {
                'user_syslog_configured': user_syslog_configured,
                'wildcard_user_found': wildcard_user_found,
                'configured_rules': configured_rules,
                'missing_rules': missing_rules,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not user_syslog_configured:
                    error_parts.append("  Syslog user configuration is NOT configured")
                elif not wildcard_user_found:
                    error_parts.append("  Syslog user wildcard (*) is NOT configured")
                    error_parts.append("  Wildcard ensures all logged-in users receive alerts")
                
                if missing_rules:
                    error_parts.append(f"\n  Missing required syslog rules ({len(missing_rules)}):")
                    for rule in missing_rules:
                        error_parts.append(f"    - user * {rule}")
                
                if configured_rules:
                    error_parts.append(f"\n  Configured rules found ({len(configured_rules)}):")
                    for rule in configured_rules:
                        error_parts.append(f"    ✓ user * {rule}")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without user terminal logging for critical and emergency events,")
                error_parts.append("  administrators may not be immediately aware of serious system")
                error_parts.append("  conditions requiring urgent attention.")
                error_parts.append("\nSeverity Levels and Their Importance:")
                error_parts.append("  - emergency (0): System is unusable - immediate action required")
                error_parts.append("  - alert (1):     Action must be taken immediately")
                error_parts.append("  - critical (2):  Critical conditions requiring urgent attention")
                error_parts.append("\nWhy User Terminal Logging Matters:")
                error_parts.append("  - Immediate notification to all logged-in administrators")
                error_parts.append("  - No delay from log aggregation or SIEM processing")
                error_parts.append("  - Real-time alerting during active management sessions")
                error_parts.append("  - Critical for detecting ongoing attacks or failures")
                error_parts.append("  - Complements but doesn't replace centralized logging")
                error_parts.append("\nExamples of Critical Events:")
                error_parts.append("  - System hardware failures")
                error_parts.append("  - Security policy violations")
                error_parts.append("  - Authentication system failures")
                error_parts.append("  - Critical daemon crashes")
                error_parts.append("  - System resource exhaustion")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system syslog user * any emergency")
                error_parts.append("  set system syslog user * daemon critical")
                error_parts.append("  set system syslog user * daemon alert")
                error_parts.append("  commit")
                error_parts.append("\nVerification:")
                error_parts.append("  show system syslog user")
                error_parts.append("  show log messages | match emergency")
                error_parts.append("  show log messages | match critical")
                error_parts.append("\nNote: Messages will appear on terminal sessions of all logged-in")
                error_parts.append("      users when critical events occur.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking syslog user terminal configuration on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: User terminal notification for critical events")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  User syslog configured: Yes")
            print(f"  Wildcard user (*) configured: Yes")
            print(f"  Required rules configured: {len(result.get('configured_rules', []))}/{len(REQUIRED_SYSLOG_USER_CONFIGS)}")
            for rule in result.get('configured_rules', []):
                print(f"    ✓ {rule}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Security: Critical events will alert all logged-in users")
        else:
            if 'error' not in result:
                print(f"  User syslog configured: {'Yes' if result.get('user_syslog_configured') else 'No'}")
                print(f"  Wildcard user (*) found: {'Yes' if result.get('wildcard_user_found') else 'No'}")
                if result.get('missing_rules'):
                    print(f"  Missing rules: {len(result.get('missing_rules'))}")


if __name__ == "__main__":
    test_syslog_user_terminal_notification()
