"""
STIG ID: CISC-ND-001030
Finding ID: V-215693
Rule ID: SV-215693r991832_rule
Severity: CAT II (Medium)
Classification: Unclass
Legacy IDs: V-96121; SV-105259

Extraction Method: Native (CLI/API JSON)
Platform: Cisco IOS-XE Router

Rule Title: The Cisco router must be configured to synchronize its clock with redundant 
authoritative time sources.

Discussion:
Determining the correct time a particular event occurred on a system is critical when 
conducting forensic analysis and investigating system events. Establishing and maintaining 
time synchronization across all network devices is essential for accurate audit records 
and event correlation.

Synchronizing internal information system clocks provides uniformity of time stamps for 
information systems with multiple system clocks and systems connected over a network. Some 
internal system components may have their own internal clocks that are not synchronized 
with the network device time. When time stamps from different devices or components are 
not synchronized, it becomes difficult or impossible to correlate events across the network.

Organizations should configure network devices to use authoritative time sources, such as 
NTP servers that are traceable to national or international time standards. To provide 
redundancy and ensure continuous time synchronization, multiple authoritative time sources 
should be configured. This protects against the failure of a single time source and ensures 
that accurate time stamps are maintained for audit records.

The requirement for redundant time sources also addresses geographic diversity concerns, 
ensuring that time synchronization can continue even if regional network connectivity is lost. 
At minimum, two NTP servers should be configured to provide redundancy.

Check Text:
Review the router configuration to verify that it synchronizes its clock with redundant 
authoritative time sources.

ntp server x.x.x.x
ntp server y.y.y.y

If the Cisco router is not configured to synchronize its clock with redundant authoritative 
time sources, this is a finding.

Fix Text:
Configure the Cisco router to synchronize its clock with redundant authoritative time sources 
as shown in the example below.

R2(config)# ntp server x.x.x.x
R2(config)# ntp server y.y.y.y
R2(config)# end

Note: At minimum, configure two NTP servers. Organizations should identify NTP servers in 
different geographic regions for enhanced redundancy and resilience.

References:
CCI: CCI-001889
NIST SP 800-53 Revision 4 :: AU-8 b
NIST SP 800-53 Revision 5 :: AU-8 b

CCI: CCI-001890
NIST SP 800-53 Revision 4 :: AU-8 b
NIST SP 800-53 Revision 5 :: AU-8 b

CCI: CCI-004928
NIST SP 800-53 Revision 5 :: SC-45 (2) (a)

CCI: CCI-004922
NIST SP 800-53 Revision 5 :: SC-45

CCI: CCI-004923
NIST SP 800-53 Revision 5 :: SC-45 (1) (a)
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-001030"
FINDING_ID = "V-215693"
RULE_ID = "SV-215693r991832_rule"
SEVERITY = "Medium"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router"
EXTRACTION_METHOD = "native"
TITLE = "Router must synchronize clock with redundant authoritative time sources"

# Minimum number of NTP servers required for redundancy
MIN_NTP_SERVERS = 2


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


def test_ntp_redundant_servers():
    """
    Test that NTP is configured with redundant authoritative time sources.
    
    STIG V-215693 (CISC-ND-001030) requires that the router synchronizes its clock with 
    redundant authoritative time sources. This ensures:
    - Accurate and consistent time stamps for audit records
    - Proper event correlation across network devices
    - Continuous time synchronization if one time source fails
    - Geographic diversity for regional network failures
    
    The test validates that:
    1. NTP configuration is present
    2. At least 2 NTP servers are configured (redundancy requirement)
    3. Each NTP server has a valid IP address
    
    Time synchronization is critical for:
    - Forensic analysis and incident investigation
    - Accurate audit record time stamps
    - Correlation of events across multiple systems
    - Meeting compliance requirements for time measurement granularity
    
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
            ntp_configured = False
            ntp_servers = []
            server_count = 0
            redundancy_adequate = False
            
            # Check NTP configuration
            if data_format == 'nso':
                # NSO format: tailf-ned-cisco-ios:ntp -> server -> name-server[]
                ntp_config = config.get('tailf-ned-cisco-ios:ntp', {})
            else:
                # Native format: ntp -> Cisco-IOS-XE-ntp:server -> server-list[]
                ntp_config = config.get('ntp', {})
            
            if ntp_config:
                ntp_configured = True
                
                # Extract NTP servers - format differs between native and NSO
                if data_format == 'nso':
                    # NSO format: ntp -> server -> name-server[] with 'name' field
                    server_config = ntp_config.get('server', {})
                    if server_config:
                        server_list = server_config.get('name-server', [])
                        ntp_servers = [s.get('name') for s in server_list if s.get('name')]
                else:
                    # Native format: ntp -> Cisco-IOS-XE-ntp:server -> server-list[]
                    server_config = ntp_config.get('Cisco-IOS-XE-ntp:server', {})
                    if server_config:
                        server_list = server_config.get('server-list', [])
                        ntp_servers = [s.get('ip-address') for s in server_list if s.get('ip-address')]
                
                server_count = len(ntp_servers)
                
                # Check if redundancy requirement is met (at least 2 servers)
                if server_count >= MIN_NTP_SERVERS:
                    redundancy_adequate = True
            
            # Overall compliance - must have at least 2 NTP servers
            overall_compliant = ntp_configured and redundancy_adequate
            
            results[device_name] = {
                'ntp_configured': ntp_configured,
                'ntp_servers': ntp_servers,
                'server_count': server_count,
                'redundancy_adequate': redundancy_adequate,
                'compliant': overall_compliant
            }
            
            if not overall_compliant:
                error_parts = [f"Device {device_name} is not compliant with STIG {STIG_ID}:"]
                
                if not ntp_configured:
                    error_parts.append("  ✗ NTP is NOT configured")
                elif not redundancy_adequate:
                    error_parts.append(f"  ✗ Only {server_count} NTP server(s) configured (requires ≥ {MIN_NTP_SERVERS})")
                    if server_count == 1:
                        error_parts.append(f"    Configured server: {ntp_servers[0]}")
                    error_parts.append(f"    Missing redundancy - need at least {MIN_NTP_SERVERS} servers")
                
                error_parts.append("\nRedundant authoritative time sources are NOT configured!")
                error_parts.append("\nRequired configuration:")
                error_parts.append("  R2(config)# ntp server x.x.x.x")
                error_parts.append("  R2(config)# ntp server y.y.y.y")
                error_parts.append("  R2(config)# end")
                error_parts.append("\nBest practices:")
                error_parts.append("  - Configure at least 2 NTP servers (minimum for redundancy)")
                error_parts.append("  - Use 3-4 NTP servers for better accuracy and resilience")
                error_parts.append("  - Select servers in different geographic regions")
                error_parts.append("  - Use authoritative time sources (stratum 1 or 2)")
                error_parts.append("  - Enable NTP authentication for security")
                error_parts.append("\nWithout redundant time sources:")
                error_parts.append("  - Single point of failure for time synchronization")
                error_parts.append("  - Audit record time stamps may be inaccurate")
                error_parts.append("  - Event correlation across devices may fail")
                error_parts.append("  - Forensic analysis may be hindered")
                error_parts.append("  - Compliance requirements may not be met")
                
                assert False, "\n".join(error_parts)
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking NTP configuration on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print(f"Severity: {SEVERITY}")
    print(f"Extraction Method: {EXTRACTION_METHOD}")
    print(f"Minimum NTP Servers Required: {MIN_NTP_SERVERS}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if result.get('compliant'):
            print(f"  ✓ NTP configured")
            print(f"  ✓ Server count: {result['server_count']}")
            print(f"  ✓ NTP servers configured:")
            for server in result['ntp_servers']:
                print(f"    - {server}")
            print(f"  ✓ Redundant authoritative time sources configured")
            if result['server_count'] == 2:
                print(f"  ℹ Recommendation: Consider adding more NTP servers (3-4) for better accuracy")
        else:
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  NTP configured: {'✓' if result.get('ntp_configured') else '✗'}")
                print(f"  Server count: {result.get('server_count', 0)} (requires {MIN_NTP_SERVERS})")
                if result.get('ntp_servers'):
                    print(f"  Configured servers:")
                    for server in result['ntp_servers']:
                        print(f"    - {server}")


if __name__ == "__main__":
    test_ntp_redundant_servers()
