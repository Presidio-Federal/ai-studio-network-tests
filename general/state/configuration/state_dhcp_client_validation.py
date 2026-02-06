"""
DHCP Client Comprehensive Validation Test

This test performs complete validation of DHCP client functionality by running
multiple sub-tests to ensure DHCP client is properly obtaining and maintaining
IP addresses.

Requirements:
    - Device must have at least one interface configured for DHCP
    - Interface should have obtained IP via DHCP

Validates (runs 2 sub-tests):
    1. IP Assignment - Verifies interface received IP, DNS, gateway from DHCP
    2. Lease Health - Checks leases are valid and not expired/expiring

Author: AI Studio Network Tests
Category: State Check - Configuration
Framework: PyATS
"""

import pytest
from pyats.topology import loader
from genie.testbed import load as genie_loader

# Import sub-test modules
import sys
import os

# Add parent directory to path to import sibling modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir))

# Import individual test functions
from state_dhcp_client_assigned import test_dhcp_client_ip_assigned
from state_dhcp_client_lease_health import test_dhcp_client_lease_healthy


def test_dhcp_client_validation(device_params, test_config):
    """
    Comprehensive DHCP client validation.
    
    This wrapper test executes all DHCP client validation checks:
    - IP assignment verification
    - Lease health monitoring
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        interface (str): Interface to check (optional - checks all if not specified)
        expected_subnet (str): Expected subnet in CIDR notation
        require_dns (bool): Require DNS servers from DHCP
        require_gateway (bool): Require default gateway from DHCP
        warn_expiring_hours (int): Hours threshold for lease expiry warning
        fail_on_expiring (bool): Fail test if lease expiring soon
    """
    
    print("\n" + "="*70)
    print("DHCP CLIENT COMPREHENSIVE VALIDATION")
    print("="*70)
    
    results = {
        "ip_assignment": None,
        "lease_health": None
    }
    
    failures = []
    
    # Test 1: IP Assignment (only if interface specified)
    interface = test_config.get("interface")
    
    if interface:
        print(f"\n[1/2] Checking DHCP IP Assignment on {interface}...")
        print("-" * 70)
        try:
            test_dhcp_client_ip_assigned(device_params, test_config)
            results["ip_assignment"] = "PASS"
            print("✓ IP assignment: PASS")
        except AssertionError as e:
            results["ip_assignment"] = "FAIL"
            failures.append(f"IP Assignment: {str(e)}")
            print(f"✗ IP assignment: FAIL - {str(e)}")
        except Exception as e:
            results["ip_assignment"] = "ERROR"
            failures.append(f"IP Assignment Error: {str(e)}")
            print(f"✗ IP assignment: ERROR - {str(e)}")
    else:
        print("\n[1/2] Skipping IP Assignment check (no interface specified)")
        results["ip_assignment"] = "SKIPPED"
    
    # Test 2: Lease Health
    test_num = "2/2" if interface else "1/1"
    print(f"\n[{test_num}] Checking DHCP Lease Health...")
    print("-" * 70)
    try:
        test_dhcp_client_lease_healthy(device_params, test_config)
        results["lease_health"] = "PASS"
        print("✓ Lease health: PASS")
    except AssertionError as e:
        results["lease_health"] = "FAIL"
        failures.append(f"Lease Health: {str(e)}")
        print(f"✗ Lease health: FAIL - {str(e)}")
    except Exception as e:
        results["lease_health"] = "ERROR"
        failures.append(f"Lease Health Error: {str(e)}")
        print(f"✗ Lease health: ERROR - {str(e)}")
    
    # Summary
    print("\n" + "="*70)
    print("DHCP CLIENT VALIDATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for r in results.values() if r == "PASS")
    failed = sum(1 for r in results.values() if r == "FAIL")
    errors = sum(1 for r in results.values() if r == "ERROR")
    skipped = sum(1 for r in results.values() if r == "SKIPPED")
    
    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
    print(f"\nDetailed Results:")
    for test_name, result in results.items():
        if result == "SKIPPED":
            status_icon = "○"
        else:
            status_icon = "✓" if result == "PASS" else "✗"
        print(f"  {status_icon} {test_name.replace('_', ' ').title()}: {result}")
    
    # Raise assertion if any failures
    if failures:
        print(f"\n✗ DHCP client validation FAILED")
        print(f"\nFailures:")
        for failure in failures:
            print(f"  - {failure}")
        
        assert False, f"DHCP client validation failed: {len(failures)} check(s) failed"
    
    print(f"\n✓ DHCP client validation PASSED - All checks successful")
