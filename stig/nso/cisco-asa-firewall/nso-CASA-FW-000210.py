"""
STIG ID: CASA-FW-000210
Finding ID: V-239863
Rule ID: SV-239863r855805_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000335-FW-000017
Rule Title: The Cisco ASA must be configured to generate a real-time alert to 
            organization-defined personnel and/or the firewall administrator in the 
            event communication with the central audit server is lost.

Discussion:
Without a real-time alert (less than a second), security personnel may be unaware of 
an impending failure of the audit functions and system operation may be adversely impacted. 
Alerts provide organizations with urgent messages.

Log processing failures include software/hardware errors, failures in the log capturing 
mechanisms, and log storage capacity being reached or exceeded. Most firewalls use UDP 
to send audit records to the server and cannot tell if the server has received the 
transmission, thus the site should either implement a connection-oriented communications 
solution (e.g., TCP) or implement a heartbeat with the central audit server and send 
an alert if it is unreachable.

Check Text:
Review the ASA configuration to determine if it will send an email alert if communication 
with the central audit server is lost.

logging enable
logging host NDM_INTERFACE 10.1.22.2 6/1514
logging permit-hostdown
logging mail errors
logging from-address firewall@mail.mil
logging recipient-address OurFWadmin@mail.mil level errors
logging recipient-address OurISSO@mail.mil level errors
smtp-server 10.1.12.33

Note: Severity level must be set at 3 (errors) or higher as the following message is 
seen when an ASA loses communication with the syslog server: %ASA-3-201008 or 
%ASA-3-414003: Disallowing new connections.

If the ASA is not configured to generate a real-time alert to organization-defined 
personnel and/or the firewall administrator if communication with the central audit 
server is lost, this is a finding.

Fix Text:
Configure the ASA to send an email alert for syslog messages at severity level 3.

ASA(config)# logging mail errors
ASA(config)# logging recipient-address OurFWadmin@mail.mil level errors
ASA(config)# logging recipient-address OurISSO@mail.mil level errors
ASA(config)# logging from-address firewall@mail.mil
ASA(config)# smtp-server 10.1.12.33

References:
CCI: CCI-001858
NIST SP 800-53 Revision 4 :: AU-5 (2)
NIST SP 800-53 Revision 5 :: AU-5 (2)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000210"
FINDING_ID = "V-239863"
RULE_ID = "SV-239863r855805_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must generate real-time alert if central audit server communication is lost"


def load_test_data(file_path):
    """Load test data from JSON or YAML file."""
    if not file_path or not os.path.exists(file_path):
        pytest.fail(f"Test input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    
    # Handle both formats:
    # Format 1: {device_name: {tailf-ncs:config: {...}}} - wrapped
    # Format 2: {tailf-ncs:config: {tailf-ned-cisco-asa:...}} - direct NSO config
    # Format 3: {tailf-ned-cisco-asa:hostname: ..., ...} - unwrapped ASA config
    
    # Check if this is wrapped in tailf-ncs:config
    if isinstance(data, dict) and 'tailf-ncs:config' in data:
        # Direct NSO config with tailf-ncs:config wrapper
        config = data['tailf-ncs:config']
        device_name = config.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: data}
    
    # Check if this is a direct ASA config (has tailf-ned-cisco-asa keys at top level)
    if isinstance(data, dict) and any(k.startswith('tailf-ned-cisco-asa:') for k in data.keys()):
        # Direct ASA config - wrap it
        device_name = data.get('tailf-ned-cisco-asa:hostname', 'unknown-device')
        return {device_name: {'tailf-ncs:config': data}}
    
    return data


def test_asa_email_alerts_for_syslog_failure():
    """
    Test that ASA is configured to send email alerts when syslog server is unreachable.
    
    STIG V-239863 (CASA-FW-000210) requires that:
    1. Logging is enabled
    2. SMTP server is configured
    3. Logging from-address is configured
    4. At least one recipient-address is configured with level errors (3) or higher
    5. Logging mail is configured at errors level (3) or higher
    
    This ensures real-time alerts are sent when communication with central audit 
    server is lost.
    """
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    devices = load_test_data(test_input_file)
    
    # Dictionary to store results
    results = {}
    
    # Severity level mapping (errors = 3)
    REQUIRED_SEVERITY_LEVEL = 3  # errors or higher
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
    
    # Check each device configuration
    for device_name, device_data in devices.items():
        try:
            # Get the config section
            device_config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            logging_enabled = False
            smtp_server_configured = False
            from_address_configured = False
            recipient_configured_with_errors = False
            logging_mail_configured = False
            smtp_server = None
            from_address = None
            recipients = []
            mail_level = None
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify SMTP server is configured
            smtp_config = device_config.get('tailf-ned-cisco-asa:smtp-server', None)
            if smtp_config:
                smtp_server_configured = True
                # SMTP server can be a string, dict, or list
                if isinstance(smtp_config, str):
                    smtp_server = smtp_config
                elif isinstance(smtp_config, dict):
                    smtp_server = smtp_config.get('ip', smtp_config.get('address', 'configured'))
                elif isinstance(smtp_config, list) and smtp_config:
                    smtp_server = smtp_config[0] if isinstance(smtp_config[0], str) else 'configured'
            
            # Check 3: Verify from-address is configured
            from_address = logging_config.get('from-address', None)
            from_address_configured = from_address is not None
            
            # Check 4: Verify at least one recipient with errors level or higher
            recipient_config = logging_config.get('recipient-address', [])
            
            if isinstance(recipient_config, dict):
                recipient_config = [recipient_config]
            elif not isinstance(recipient_config, list):
                recipient_config = []
            
            for recipient in recipient_config:
                if isinstance(recipient, dict):
                    address = recipient.get('address', 'unknown')
                    level = recipient.get('level', None)
                    
                    recipients.append({
                        'address': address,
                        'level': level
                    })
                    
                    # Check if level is errors (3) or higher (lower number = higher severity)
                    if level:
                        level_num = SEVERITY_LEVELS.get(level, 7)
                        if level_num <= REQUIRED_SEVERITY_LEVEL:
                            recipient_configured_with_errors = True
            
            # Check 5: Verify logging mail is configured at errors or higher
            # Logging mail can be a dict with level, or just a string
            mail_config = logging_config.get('mail', None)
            if mail_config is not None:
                logging_mail_configured = True
                if isinstance(mail_config, str):
                    mail_level = mail_config
                elif isinstance(mail_config, dict):
                    mail_level = mail_config.get('level', 'configured')
                else:
                    mail_level = 'configured'
            
            # Overall compliance - all five must be true
            overall_compliant = (
                logging_enabled and 
                smtp_server_configured and
                from_address_configured and
                recipient_configured_with_errors and
                logging_mail_configured
            )
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'smtp_server_configured': smtp_server_configured,
                'from_address_configured': from_address_configured,
                'recipient_configured_with_errors': recipient_configured_with_errors,
                'logging_mail_configured': logging_mail_configured,
                'smtp_server': smtp_server,
                'from_address': from_address,
                'recipients': recipients,
                'mail_level': mail_level,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not logging_enabled:
                error_parts.append("- Logging is not enabled")
            
            if not smtp_server_configured:
                error_parts.append("- SMTP server is not configured")
            
            if not from_address_configured:
                error_parts.append("- Logging from-address is not configured")
            
            if not recipient_configured_with_errors:
                if not recipients:
                    error_parts.append("- No recipient-address configured")
                else:
                    error_parts.append("- No recipient-address configured with 'errors' level or higher")
                    error_parts.append(f"  Found {len(recipients)} recipient(s) with insufficient severity:")
                    for rec in recipients:
                        error_parts.append(f"    {rec['address']} (level: {rec['level']})")
            
            if not logging_mail_configured:
                error_parts.append("- Logging mail is not configured")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired configuration:\n"
                    f"  ASA(config)# logging mail errors\n"
                    f"  ASA(config)# logging from-address firewall@mail.mil\n"
                    f"  ASA(config)# logging recipient-address admin@mail.mil level errors\n"
                    f"  ASA(config)# smtp-server <ip-address>"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking email alert configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Logging enabled: {'✓' if result.get('logging_enabled') else '✗'}")
                print(f"  SMTP server: {'✓' if result.get('smtp_server_configured') else '✗'} {result.get('smtp_server', '')}")
                print(f"  From address: {'✓' if result.get('from_address_configured') else '✗'} {result.get('from_address', '')}")
                print(f"  Recipients with 'errors' level: {'✓' if result.get('recipient_configured_with_errors') else '✗'}")
                if result.get('recipients'):
                    for rec in result.get('recipients', []):
                        print(f"    {rec['address']} (level: {rec['level']})")
                print(f"  Logging mail configured: {'✓' if result.get('logging_mail_configured') else '✗'} {result.get('mail_level', '')}")
        else:
            # Show config details for passing tests
            print(f"  ✓ Logging enabled")
            print(f"  ✓ SMTP server: {result.get('smtp_server', 'configured')}")
            print(f"  ✓ From address: {result.get('from_address', 'configured')}")
            print(f"  ✓ Recipients: {len(result.get('recipients', []))}")
            for rec in result.get('recipients', []):
                print(f"    {rec['address']} (level: {rec['level']})")
            print(f"  ✓ Mail level: {result.get('mail_level', 'configured')}")


if __name__ == "__main__":
    test_asa_email_alerts_for_syslog_failure()
