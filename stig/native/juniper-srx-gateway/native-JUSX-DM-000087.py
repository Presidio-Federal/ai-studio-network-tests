"""
STIG ID: JUSX-DM-000087
Finding ID: V-223204
Rule ID: SV-223204r961863_rule
Version: 3, Release: 3
Severity: CAT III (Low)
Classification: Unclass

Extraction Method: Native (CLI/API JSON)
Platform: Juniper SRX Services Gateway

Group Title: SRG-APP-000516-NDM-000340

Rule Title: The Juniper SRX Services Gateway must be configured to limit the number 
            of configuration rollbacks that are stored.

Discussion:
Configuration rollbacks allow administrators to revert to previous known-good 
configurations in case of errors or security incidents. However, storing excessive 
rollback files can consume disk space and potentially expose sensitive configuration 
data over extended periods.

The organization should define an appropriate number of rollbacks to retain based on:
- Available storage capacity
- Change management frequency
- Compliance and audit requirements
- Operational needs for configuration recovery

Juniper SRX default is to store 49 rollback configurations (numbered 0-49), which may 
be excessive for most environments. Organizations typically configure between 5-15 
rollbacks based on their change management practices.

Benefits of limiting rollbacks:
- Reduces disk space consumption
- Limits exposure window for sensitive configuration data
- Simplifies configuration management and auditing
- Aligns storage with actual operational recovery needs
- Prevents partition full conditions that could impact operations

Check Text:
Verify the Juniper SRX limits the number of rollback configuration files stored.

[edit]
show system max-configuration-rollbacks

If the maximum number of configuration rollbacks is not configured to an 
organization-defined number, this is a finding.

Fix Text:
To configure number of backup configurations to be stored in the configuration 
partition enter the following command at the configuration hierarchy.

[edit]
set system max-configuration-rollbacks <organization-defined number>

Example:
set system max-configuration-rollbacks 10

References:
CCI: CCI-000366: Implement the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53 Revision 4 :: CM-6 b
NIST SP 800-53 Revision 5 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)

Juniper SRX Services Gateway NDM Security Technical Implementation Guide
Version 3, Release: 3
Benchmark Date: 30 Jan 2025
Vul ID: V-223204
Rule ID: SV-223204r961863_rule
STIG ID: JUSX-DM-000087
Severity: CAT III
Classification: Unclass
Legacy IDs: V-66595; SV-81085
"""

import os
import json
import yaml
import pytest

STIG_ID = "JUSX-DM-000087"
FINDING_ID = "V-223204"
RULE_ID = "SV-223204r961863_rule"
SEVERITY = "CAT III"
CLASSIFICATION = "Unclass"
CATEGORY = "STIG"
PLATFORM = "juniper-srx-gateway"
EXTRACTION_METHOD = "native"

# Juniper default is 49, but organizations should define a reasonable limit
# Common practice is 5-15 rollbacks based on change frequency
# For this test, we check that it's configured (not default) and is reasonable (<=20)
MAX_ROLLBACKS_LIMIT = 20  # Upper bound for "reasonable" value


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


def test_configuration_rollback_limit():
    """
    Test that the maximum number of configuration rollbacks is configured.
    
    STIG JUSX-DM-000087 requires that the Juniper SRX be configured to limit the 
    number of configuration rollbacks stored. This prevents excessive disk usage, 
    reduces exposure of sensitive configuration data, and aligns with organizational 
    change management practices.
    
    This test validates:
    1. max-configuration-rollbacks is explicitly configured
    2. The value is reasonable (not default 49)
    3. The value is within organizational limits (<=20 for this test)
    
    Note: Organizations should define their own appropriate limit based on:
    - Change management frequency
    - Available disk space
    - Audit/compliance requirements
    - Operational recovery needs
    
    Common practice: 5-15 rollbacks
    
    Benefits of limiting rollbacks:
    - Reduces disk space consumption
    - Limits exposure window for sensitive data
    - Simplifies configuration management
    - Prevents partition full conditions
    
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
            
            rollbacks_configured = False
            max_rollbacks = None
            
            # Check system configuration
            # Path: configuration.system.max-configuration-rollbacks
            system_config = config.get('system', {})
            
            if 'max-configuration-rollbacks' in system_config:
                rollbacks_configured = True
                max_rollbacks = system_config.get('max-configuration-rollbacks')
            
            # Determine compliance
            # Must have max-configuration-rollbacks explicitly configured
            # Value should be reasonable (not default 49, and within organizational limit)
            overall_compliant = (
                rollbacks_configured and 
                max_rollbacks is not None and 
                max_rollbacks <= MAX_ROLLBACKS_LIMIT
            )
            
            results[device_name] = {
                'rollbacks_configured': rollbacks_configured,
                'max_rollbacks': max_rollbacks,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not rollbacks_configured:
                    error_parts.append("  max-configuration-rollbacks is NOT configured")
                    error_parts.append("  Default: 49 rollbacks (likely excessive)")
                elif max_rollbacks is None:
                    error_parts.append("  max-configuration-rollbacks value is None/missing")
                elif max_rollbacks > MAX_ROLLBACKS_LIMIT:
                    error_parts.append(f"  max-configuration-rollbacks is {max_rollbacks}")
                    error_parts.append(f"  Exceeds recommended limit: {MAX_ROLLBACKS_LIMIT}")
                
                error_parts.append("\nFinding:")
                error_parts.append("  Without explicit configuration rollback limits, the device may")
                error_parts.append("  store excessive configuration files consuming disk space and")
                error_parts.append("  increasing exposure of sensitive configuration data.")
                error_parts.append("\nSecurity and Operational Risks:")
                error_parts.append("  - Excessive disk space consumption")
                error_parts.append("  - Potential partition full conditions affecting operations")
                error_parts.append("  - Extended exposure window for sensitive config data")
                error_parts.append("  - Difficult configuration audit and management")
                error_parts.append("  - May retain outdated security configurations")
                error_parts.append("\nConfiguration Rollback Planning:")
                error_parts.append("  Consider these factors when setting the limit:")
                error_parts.append("  - Change frequency: Daily changes may need 7-14 rollbacks")
                error_parts.append("  - Change windows: Weekly maintenance may need 4-8 rollbacks")
                error_parts.append("  - Compliance: Audit requirements may dictate retention")
                error_parts.append("  - Storage: Available /config partition space")
                error_parts.append("  - Recovery: Time window for identifying bad changes")
                error_parts.append("\nRecommended Limits by Change Frequency:")
                error_parts.append("  - Daily changes:    10-15 rollbacks (2 weeks retention)")
                error_parts.append("  - Weekly changes:   5-8 rollbacks (1-2 months retention)")
                error_parts.append("  - Monthly changes:  3-5 rollbacks (3-5 months retention)")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  [edit]")
                error_parts.append("  set system max-configuration-rollbacks 10")
                error_parts.append("  commit")
                error_parts.append("\nVerification:")
                error_parts.append("  show system max-configuration-rollbacks")
                error_parts.append("  show system rollback")
                error_parts.append("  show system storage")
                error_parts.append("\nNote: Adjust the limit based on your organization's specific")
                error_parts.append("      change management practices and storage capacity.")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError, TypeError) as e:
            results[device_name] = {'error': str(e), 'compliant': False}
            assert False, f"Error checking configuration rollback limit on {device_name}: {e}"
    
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Severity: {SEVERITY}")
    print(f"Title: Configuration rollback storage limit")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  max-configuration-rollbacks: {result.get('max_rollbacks')}")
            print(f"  Recommended limit: <= {MAX_ROLLBACKS_LIMIT}")
            print(f"  STIG {STIG_ID}: COMPLIANT")
            print(f"  Configuration: Rollback storage is appropriately limited")
        else:
            if 'error' not in result:
                print(f"  Rollbacks configured: {'Yes' if result.get('rollbacks_configured') else 'No (using default: 49)'}")
                if result.get('max_rollbacks') is not None:
                    print(f"  Current limit: {result.get('max_rollbacks')}")
                print(f"  Recommended limit: <= {MAX_ROLLBACKS_LIMIT}")


if __name__ == "__main__":
    test_configuration_rollback_limit()
