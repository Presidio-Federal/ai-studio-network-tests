"""
STIG ID: CASA-FW-000090
Finding ID: V-239857
Rule ID: SV-239857r665857_rule
Severity: CAT II (Medium)
Classification: Unclass

Group Title: SRG-NET-000089-FW-000019
Rule Title: The Cisco ASA must be configured to queue log records locally in the 
            event that the central audit server is down or not reachable.

Discussion:
It is critical that when the network element is at risk of failing to process traffic 
logs as required, it takes action to mitigate the failure. Audit processing failures 
include software/hardware errors, failures in the audit capturing mechanisms, and audit 
storage capacity being reached or exceeded.

In accordance with DoD policy, the traffic log must be sent to a central audit server. 
When logging functions are lost, system processing cannot be shut down because firewall 
availability is an overriding concern. The system should either log events to an 
alternative server or queue log records locally. Upon restoration of the connection to 
the central audit server, action should be taken to synchronize the local log data.

Check Text:
Review the ASA configuration and verify that logging to the buffer is enabled and that 
the queue size has been increased as shown in the example below.

logging enable
logging buffered informational
logging queue 8192

Note: Configuring a value of 0 for the queue size will set it to maximum size for the 
specific platform.

If the ASA is not configured to queue log records locally in the event that the central 
audit server is down or not reachable, this is a finding.

Fix Text:
Configure logging buffered and increase the queue size as shown in the example below.

ASA(config)# logging buffered informational
ASA(config)# logging queue 8192

References:
CCI: CCI-000140
NIST SP 800-53 :: AU-5 b
NIST SP 800-53 Revision 4 :: AU-5 b
NIST SP 800-53 Revision 5 :: AU-5 b
NIST SP 800-53A :: AU-5.1 (iv)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CASA-FW-000090"
FINDING_ID = "V-239857"
RULE_ID = "SV-239857r665857_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "cisco-asa-firewall"
TITLE = "ASA must queue log records locally when central audit server is down"


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


def test_asa_logging_buffered_and_queue():
    """
    Test that ASA logging buffered and queue are configured.
    
    STIG V-239857 (CASA-FW-000090) requires that:
    1. Logging is enabled globally
    2. Logging buffered is configured (to queue logs locally)
    3. Logging queue size is increased (recommended >= 512, STIG example shows 8192)
    
    This ensures log records are queued locally when the central audit server 
    is down or not reachable.
    """
    # Get the path to the test input file
    test_input_file = os.environ.get('TEST_INPUT_JSON', None)
    
    if not test_input_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Load the data (supports both JSON and YAML)
    devices = load_test_data(test_input_file)
    
    # Dictionary to store results
    results = {}
    
    # Minimum recommended queue size (STIG shows 8192, but 512 is often acceptable)
    MIN_QUEUE_SIZE = 512
    
    # Check each device configuration
    for device_name, device_data in devices.items():
        try:
            # Get the config section
            device_config = device_data.get('tailf-ncs:config', {})
            
            # Initialize compliance flags
            logging_enabled = False
            logging_buffered_configured = False
            logging_queue_configured = False
            queue_size = 0
            buffered_level = None
            
            # Check 1: Verify logging is enabled
            logging_config = device_config.get('tailf-ned-cisco-asa:logging', {})
            logging_enabled = 'enable' in logging_config
            
            # Check 2: Verify logging buffered is configured
            # Can be a dict with level config or just presence indicates it's enabled
            buffered_config = logging_config.get('buffered', None)
            if buffered_config is not None:
                logging_buffered_configured = True
                # Try to get the level if it's a dict
                if isinstance(buffered_config, dict):
                    # Could have 'level' key or specific level keys like 'informational'
                    buffered_level = buffered_config.get('level', 
                                    buffered_config.get('informational', 
                                    'configured'))
                else:
                    buffered_level = 'configured'
            
            # Check 3: Verify logging queue is configured and meets minimum size
            queue_config = logging_config.get('queue', None)
            if queue_config is not None:
                logging_queue_configured = True
                # Queue can be a dict with size, or an integer
                if isinstance(queue_config, dict):
                    queue_size = int(queue_config.get('size', 0))
                elif isinstance(queue_config, (int, str)):
                    try:
                        queue_size = int(queue_config)
                    except (ValueError, TypeError):
                        queue_size = 0
            
            # Note: Queue size of 0 means maximum size per STIG notes
            # So 0 is acceptable, or >= MIN_QUEUE_SIZE
            queue_size_acceptable = (queue_size == 0 or queue_size >= MIN_QUEUE_SIZE)
            
            # Overall compliance - all three must be true
            overall_compliant = (
                logging_enabled and 
                logging_buffered_configured and 
                logging_queue_configured and
                queue_size_acceptable
            )
            
            # Store results
            results[device_name] = {
                'logging_enabled': logging_enabled,
                'logging_buffered_configured': logging_buffered_configured,
                'logging_queue_configured': logging_queue_configured,
                'queue_size': queue_size,
                'queue_size_acceptable': queue_size_acceptable,
                'buffered_level': buffered_level,
                'compliant': overall_compliant
            }
            
            # Build detailed error message
            error_parts = []
            if not logging_enabled:
                error_parts.append("- Logging is not enabled")
            
            if not logging_buffered_configured:
                error_parts.append("- Logging buffered is not configured")
            
            if not logging_queue_configured:
                error_parts.append("- Logging queue is not configured")
            elif not queue_size_acceptable:
                error_parts.append(f"- Logging queue size ({queue_size}) is below minimum ({MIN_QUEUE_SIZE})")
                error_parts.append(f"  Note: Queue size of 0 = maximum size (acceptable)")
            
            # Assert that the device is compliant
            if not overall_compliant:
                error_message = (
                    f"Device {device_name} is not compliant with STIG {STIG_ID}:\n" +
                    "\n".join(error_parts) +
                    f"\n\nRequired configuration:\n"
                    f"  ASA(config)# logging enable\n"
                    f"  ASA(config)# logging buffered informational\n"
                    f"  ASA(config)# logging queue 8192"
                )
                assert False, error_message
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking logging queue configuration on {device_name}: {e}"
    
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
                if result.get('logging_enabled'):
                    print("  ✓ Logging is enabled")
                else:
                    print("  ✗ Logging is not enabled")
                
                if result.get('logging_buffered_configured'):
                    print(f"  ✓ Logging buffered is configured ({result.get('buffered_level', 'unknown')})")
                else:
                    print("  ✗ Logging buffered is not configured")
                
                if result.get('logging_queue_configured'):
                    queue_size = result.get('queue_size', 0)
                    if result.get('queue_size_acceptable'):
                        size_note = "maximum" if queue_size == 0 else queue_size
                        print(f"  ✓ Logging queue is configured (size: {size_note})")
                    else:
                        print(f"  ✗ Logging queue size ({queue_size}) is below minimum ({MIN_QUEUE_SIZE})")
                else:
                    print("  ✗ Logging queue is not configured")
        else:
            # Show config details for passing tests
            queue_size = result.get('queue_size', 0)
            size_note = "maximum (0)" if queue_size == 0 else queue_size
            print(f"  ✓ Logging enabled")
            print(f"  ✓ Logging buffered: {result.get('buffered_level', 'configured')}")
            print(f"  ✓ Logging queue: {size_note}")


if __name__ == "__main__":
    test_asa_logging_buffered_and_queue()
