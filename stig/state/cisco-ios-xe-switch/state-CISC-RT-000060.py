"""
STIG ID: CISC-RT-000060
Finding ID: V-220991
Rule ID: SV-220991r1117237_rule
Severity: CAT III (Low)
Classification: Unclass
Legacy IDs: V-101699; SV-110803

Test Type: State Check (PyATS/Genie)
Platform: Cisco IOS-XE Switch
Extraction Method: Live Device Access

Rule Title: The Cisco switch must have all inactive interfaces disabled.

Discussion:
An inactive interface is rarely a business requirement. Enabled interfaces increase the attack 
surface of a network device. Leaving unused interfaces enabled provides additional avenues for 
malicious actors to gain unauthorized access to the device or the network.

Disabled interfaces:
- Reduce attack surface by minimizing entry points
- Prevent unauthorized physical connections
- Ensure clear inventory of active network connections
- Support information flow control (AC-4)
- Follow least functionality principle

This test uses pyATS to learn interface operational state and identify interfaces that are:
1. Administratively up (not shutdown) but operationally down
2. Have no traffic (input/output counters near zero)
3. May not be actively used

The test provides a list of potentially inactive interfaces that should be reviewed and 
administratively disabled if not needed.

Check Text:
Review the switch configuration and verify that inactive interfaces have been disabled.

interface GigabitEthernet3
  shutdown
!
interface GigabitEthernet4
  shutdown

If an interface is not being used but is configured or enabled, this is a finding.

Fix Text:
Disable all inactive interfaces:

SW1(config)# interface GigabitEthernet3
SW1(config-if)# shutdown
SW1(config)# interface GigabitEthernet4
SW1(config-if)# shutdown

References:
CCI: CCI-001414
NIST SP 800-53 :: AC-4
NIST SP 800-53 Revision 4 :: AC-4
NIST SP 800-53 Revision 5 :: AC-4
NIST SP 800-53A :: AC-4.1 (iii)
"""

import pytest
import logging
from pyats.topology import loader
from genie.conf import Genie

logger = logging.getLogger(__name__)

# STIG Metadata
STIG_ID = "CISC-RT-000060"
FINDING_ID = "V-220991"
RULE_ID = "SV-220991r1117237_rule"
SEVERITY = "Low"  # CAT III
CATEGORY = "STIG"
PLATFORM = "ios-xe-switch"
TEST_TYPE = "state_check"
TITLE = "Switch must have all inactive interfaces disabled"

# Thresholds for determining if an interface is inactive
# These can be adjusted based on organizational requirements
INACTIVE_THRESHOLDS = {
    'max_input_packets': 100,      # Less than 100 input packets likely inactive
    'max_output_packets': 100,     # Less than 100 output packets likely inactive
    'max_input_rate_bps': 1000,    # Less than 1 Kbps input rate
    'max_output_rate_bps': 1000,   # Less than 1 Kbps output rate
}

# Interfaces to exclude from checks (typically management or special purpose)
EXCLUDED_INTERFACE_PATTERNS = [
    'Loopback',
    'Null',
    'Tunnel',
]


def should_exclude_interface(interface_name):
    """Check if interface should be excluded from inactive checks."""
    for pattern in EXCLUDED_INTERFACE_PATTERNS:
        if pattern.lower() in interface_name.lower():
            return True
    return False


def is_interface_inactive(intf_data):
    """
    Determine if an interface appears inactive based on operational state.
    
    An interface is considered potentially inactive if:
    1. Operational status is 'down' (but admin status is 'up')
    2. Has minimal or no traffic counters
    3. Has no link (no protocol up)
    
    Returns: (is_inactive: bool, reason: str, metrics: dict)
    """
    oper_status = intf_data.get('oper_status', 'unknown').lower()
    enabled = intf_data.get('enabled', False)
    
    # Get counters
    counters = intf_data.get('counters', {})
    in_pkts = counters.get('in_pkts', 0)
    out_pkts = counters.get('out_pkts', 0)
    in_rate = counters.get('in_rate', 0)
    out_rate = counters.get('out_rate', 0)
    
    metrics = {
        'oper_status': oper_status,
        'enabled': enabled,
        'in_pkts': in_pkts,
        'out_pkts': out_pkts,
        'in_rate': in_rate,
        'out_rate': out_rate
    }
    
    # Interface is shutdown - compliant (not a finding)
    if not enabled:
        return False, 'administratively_down', metrics
    
    # Interface is up and running - active (not a finding)
    if oper_status == 'up':
        # Check if it has meaningful traffic
        if (in_pkts > INACTIVE_THRESHOLDS['max_input_packets'] or 
            out_pkts > INACTIVE_THRESHOLDS['max_output_packets']):
            return False, 'active_with_traffic', metrics
        
        # Interface is up but has minimal traffic - potentially inactive
        return True, 'up_but_minimal_traffic', metrics
    
    # Interface is admin up but operationally down - likely inactive
    if enabled and oper_status == 'down':
        return True, 'admin_up_oper_down', metrics
    
    # Other states - review needed
    return True, f'unusual_state_{oper_status}', metrics


def test_inactive_interfaces_disabled(device_params, test_config):
    """
    Test that inactive interfaces are administratively disabled (shutdown).
    
    STIG V-220991 (CISC-RT-000060) requires that unused interfaces be disabled to reduce 
    attack surface and enforce information flow control.
    
    This test:
    1. Connects to the device and learns all interface states
    2. Identifies interfaces that appear inactive based on:
       - Admin up but operationally down
       - Minimal or no traffic counters
       - No link detected
    3. Reports which interfaces should be reviewed and potentially shutdown
    
    Args:
        device_params: Device connection parameters (host, username, password, etc.)
        test_config: Optional test configuration
            - exclude_interfaces: List of interface names to exclude from checks
            - fail_on_inactive: If True, fail test when inactive interfaces found (default: True)
            - strict_mode: If True, use stricter traffic thresholds (default: False)
    
    Native extraction method: Live device state via pyATS.
    """
    exclude_interfaces = test_config.get('exclude_interfaces', [])
    fail_on_inactive = test_config.get('fail_on_inactive', True)
    strict_mode = test_config.get('strict_mode', False)
    
    # Map device_type to PyATS OS
    os_map = {
        "cisco_xe": "iosxe",
        "cisco_ios": "ios",
        "cisco_nxos": "nxos",
        "cisco_iosxr": "iosxr",
    }
    device_os = os_map.get(device_params.get("device_type", "cisco_xe"), "iosxe")
    device_name = device_params.get('device_name', 'switch')
    
    # Build PyATS testbed
    testbed_dict = {
        "devices": {
            device_name: {
                "type": "switch",
                "os": device_os,
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"],
                        "port": device_params.get("port", 22),
                        "arguments": {
                            "learn_hostname": True,
                            "init_exec_commands": [],
                            "init_config_commands": []
                        }
                    }
                },
                "credentials": {
                    "default": {
                        "username": device_params["username"],
                        "password": device_params["password"],
                    },
                    "enable": {
                        "password": device_params.get("enable_password", device_params["password"])
                    }
                }
            }
        }
    }
    
    testbed = loader.load(testbed_dict)
    genie_testbed = Genie.init(testbed)
    device = genie_testbed.devices[device_name]
    
    logger.info(f"Connecting to {device.name}")
    device.connect(learn_hostname=True)
    
    try:
        # Learn interface information
        logger.info(f"Learning interface state from {device.name}")
        
        from genie.libs.ops.interface.iosxe.interface import Interface
        
        interface_ops = Interface(device)
        interface_ops.learn()
        
        assert hasattr(interface_ops, 'info'), f"Failed to learn interface info from {device.name}"
        
        # Analyze interfaces
        all_interfaces = []
        inactive_interfaces = []
        active_interfaces = []
        shutdown_interfaces = []
        
        for intf_name, intf_data in interface_ops.info.items():
            # Skip excluded patterns
            if should_exclude_interface(intf_name):
                continue
            
            # Skip user-specified exclusions
            if intf_name in exclude_interfaces:
                continue
            
            # Check if interface is inactive
            is_inactive, reason, metrics = is_interface_inactive(intf_data)
            
            interface_summary = {
                'name': intf_name,
                'is_inactive': is_inactive,
                'reason': reason,
                'oper_status': metrics['oper_status'],
                'enabled': metrics['enabled'],
                'in_pkts': metrics['in_pkts'],
                'out_pkts': metrics['out_pkts'],
                'in_rate': metrics['in_rate'],
                'out_rate': metrics['out_rate']
            }
            
            all_interfaces.append(interface_summary)
            
            if not metrics['enabled']:
                shutdown_interfaces.append(interface_summary)
            elif is_inactive:
                inactive_interfaces.append(interface_summary)
            else:
                active_interfaces.append(interface_summary)
        
        # Print summary
        print("\n" + "="*80)
        print(f"STIG Compliance Check: {STIG_ID}")
        print(f"Finding ID: {FINDING_ID}")
        print(f"Rule ID: {RULE_ID}")
        print(f"Title: {TITLE}")
        print(f"Severity: {SEVERITY} (CAT III)")
        print("="*80)
        
        print(f"\nInterface Analysis Summary:")
        print(f"  Total interfaces analyzed: {len(all_interfaces)}")
        print(f"  Active interfaces: {len(active_interfaces)}")
        print(f"  Shutdown interfaces (compliant): {len(shutdown_interfaces)}")
        print(f"  Potentially inactive interfaces (FINDINGS): {len(inactive_interfaces)}")
        
        if shutdown_interfaces:
            print(f"\n✓ Properly shutdown interfaces ({len(shutdown_interfaces)}):")
            for intf in shutdown_interfaces[:10]:  # Show first 10
                print(f"    ✓ {intf['name']}: shutdown (compliant)")
            if len(shutdown_interfaces) > 10:
                print(f"    ... and {len(shutdown_interfaces) - 10} more")
        
        if active_interfaces:
            print(f"\n✓ Active interfaces ({len(active_interfaces)}):")
            for intf in active_interfaces[:5]:  # Show first 5
                print(f"    ✓ {intf['name']}: {intf['oper_status']} "
                      f"(in: {intf['in_pkts']} pkts, out: {intf['out_pkts']} pkts)")
            if len(active_interfaces) > 5:
                print(f"    ... and {len(active_interfaces) - 5} more")
        
        # Report inactive interfaces (STIG findings)
        if inactive_interfaces:
            print(f"\n✗ FINDINGS: Potentially inactive interfaces ({len(inactive_interfaces)}):")
            print(f"{'Interface':<25} {'Admin':<8} {'Oper':<8} {'In Pkts':<12} {'Out Pkts':<12} {'Reason'}")
            print("-" * 95)
            
            for intf in inactive_interfaces:
                admin_state = 'up' if intf['enabled'] else 'down'
                print(f"{intf['name']:<25} {admin_state:<8} {intf['oper_status']:<8} "
                      f"{intf['in_pkts']:<12} {intf['out_pkts']:<12} {intf['reason']}")
            
            print("\nRemediation Required:")
            print("Disable each inactive interface using the following commands:\n")
            for intf in inactive_interfaces[:10]:  # Show commands for first 10
                print(f"  SW1(config)# interface {intf['name']}")
                print(f"  SW1(config-if)# shutdown")
            if len(inactive_interfaces) > 10:
                print(f"  ... and {len(inactive_interfaces) - 10} more interfaces")
            
            print("\nSecurity Impact:")
            print("  - Unused enabled interfaces increase attack surface")
            print("  - Unauthorized physical connections may go undetected")
            print("  - Information flow control is not properly enforced")
            print("  - Violates least functionality principle (CCI-001414)")
            
            if fail_on_inactive:
                error_msg = (
                    f"\n{len(inactive_interfaces)} interface(s) appear inactive but are not shutdown.\n"
                    f"Review these interfaces and disable them if not needed.\n\n"
                    f"STIG {STIG_ID} requires all unused interfaces to be administratively disabled."
                )
                assert False, error_msg
            else:
                print("\n⚠️  WARNING: Test configured to not fail on findings (fail_on_inactive=False)")
        else:
            print("\n✓ COMPLIANT: All interfaces are either active or properly shutdown")
            print(f"✓ No inactive interfaces detected that require remediation")
        
    finally:
        # Ensure disconnect
        if device.is_connected():
            device.disconnect()


def test_interface_config_minimal(device_params, test_config):
    """
    Test that shutdown interfaces have minimal configuration (optional stricter check).
    
    This optional test verifies that shutdown interfaces don't have unnecessary 
    configuration like IP addresses, VLANs, or other settings that should only 
    exist on active interfaces.
    
    Args:
        device_params: Device connection parameters
        test_config: Test configuration
            - check_ip_addresses: Warn if shutdown interfaces have IPs (default: True)
            - check_switchport_config: Warn if shutdown interfaces have VLAN config (default: True)
    """
    check_ips = test_config.get('check_ip_addresses', True)
    check_switchport = test_config.get('check_switchport_config', True)
    
    # Map device_type to PyATS OS
    os_map = {
        "cisco_xe": "iosxe",
        "cisco_ios": "ios",
        "cisco_nxos": "nxos",
    }
    device_os = os_map.get(device_params.get("device_type", "cisco_xe"), "iosxe")
    device_name = device_params.get('device_name', 'switch')
    
    # Build PyATS testbed
    testbed_dict = {
        "devices": {
            device_name: {
                "type": "switch",
                "os": device_os,
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"],
                        "port": device_params.get("port", 22),
                        "arguments": {
                            "learn_hostname": True,
                            "init_exec_commands": [],
                            "init_config_commands": []
                        }
                    }
                },
                "credentials": {
                    "default": {
                        "username": device_params["username"],
                        "password": device_params["password"],
                    },
                    "enable": {
                        "password": device_params.get("enable_password", device_params["password"])
                    }
                }
            }
        }
    }
    
    testbed = loader.load(testbed_dict)
    genie_testbed = Genie.init(testbed)
    device = genie_testbed.devices[device_name]
    
    device.connect(learn_hostname=True)
    
    try:
        # Learn interface information
        from genie.libs.ops.interface.iosxe.interface import Interface
        
        interface_ops = Interface(device)
        interface_ops.learn()
        
        misconfigured_shutdown_intfs = []
        
        for intf_name, intf_data in interface_ops.info.items():
            # Skip excluded interfaces
            if should_exclude_interface(intf_name):
                continue
            
            enabled = intf_data.get('enabled', False)
            
            # Only check shutdown interfaces
            if not enabled:
                issues = []
                
                # Check for IP addresses on shutdown interfaces
                if check_ips:
                    ipv4_config = intf_data.get('ipv4', {})
                    if ipv4_config:
                        for ip_addr, ip_data in ipv4_config.items():
                            if ip_addr != 'unnumbered':
                                issues.append(f"has IP address: {ip_addr}")
                
                # Check for switchport configuration
                if check_switchport:
                    switchport_mode = intf_data.get('switchport_mode')
                    access_vlan = intf_data.get('access_vlan')
                    
                    if access_vlan and access_vlan != '1':
                        issues.append(f"configured with access VLAN {access_vlan}")
                
                if issues:
                    misconfigured_shutdown_intfs.append({
                        'name': intf_name,
                        'issues': issues
                    })
        
        # Report findings
        if misconfigured_shutdown_intfs:
            print(f"\n⚠️  Found {len(misconfigured_shutdown_intfs)} shutdown interface(s) with unnecessary configuration:")
            for intf in misconfigured_shutdown_intfs:
                print(f"  ⚠ {intf['name']}:")
                for issue in intf['issues']:
                    print(f"      - {issue}")
            
            print("\nRecommendation: Remove unnecessary configuration from shutdown interfaces")
        else:
            print("\n✓ All shutdown interfaces have minimal configuration")
        
    finally:
        if device.is_connected():
            device.disconnect()


if __name__ == "__main__":
    # Example usage for manual testing
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python state-CISC-RT-000060.py <host> <username> <password>")
        sys.exit(1)
    
    device_params = {
        "device_name": "switch",
        "host": sys.argv[1],
        "username": sys.argv[2],
        "password": sys.argv[3],
        "device_type": "cisco_xe"
    }
    
    test_config = {
        "fail_on_inactive": True
    }
    
    test_inactive_interfaces_disabled(device_params, test_config)
