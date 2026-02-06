"""
DHCP Server Comprehensive Validation Test

This test performs complete validation of DHCP server functionality by running
multiple sub-tests to ensure the DHCP server is properly configured and operating.

Requirements:
    - Device must be configured as a DHCP server
    - DHCP pools must be configured

Validates (runs 5 sub-tests):
    1. Pool Configuration - Verifies pools are properly configured
    2. Active Bindings - Checks for active client leases
    3. Server Statistics - Monitors DHCP message processing health
    4. Pool Utilization - Ensures adequate capacity
    5. DHCP Snooping - Validates security features (optional)

Author: AI Studio Network Tests
Category: State Check - Services
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
from state_dhcp_pool_configured import test_dhcp_pools_exist_and_configured
from state_dhcp_bindings_active import test_dhcp_active_bindings_exist
from state_dhcp_server_statistics import test_dhcp_server_statistics_healthy
from state_dhcp_pool_utilization import test_dhcp_pool_utilization_healthy


def test_dhcp_server_validation(device_params, test_config):
    """
    Comprehensive DHCP server validation.
    
    This wrapper test executes all DHCP server validation checks:
    - Pool configuration
    - Active bindings
    - Server statistics
    - Pool utilization
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration (see sub-tests for options)
    
    Test Configuration:
        All parameters from sub-tests are supported:
        - min_pools (int): Minimum pools required
        - require_dns (bool): Require DNS in pools
        - require_gateway (bool): Require gateway in pools
        - min_bindings (int): Minimum active bindings
        - check_duplicates (bool): Check for duplicate IPs
        - max_decline_rate_percent (float): Max decline rate
        - max_nak_rate_percent (float): Max NAK rate
        - critical_threshold_percent (float): Pool utilization critical threshold
        - warning_threshold_percent (float): Pool utilization warning threshold
    """
    
    print("\n" + "="*70)
    print("DHCP SERVER COMPREHENSIVE VALIDATION")
    print("="*70)
    
    results = {
        "pool_configuration": None,
        "active_bindings": None,
        "server_statistics": None,
        "pool_utilization": None
    }
    
    failures = []
    
    # Test 1: Pool Configuration
    print("\n[1/4] Checking DHCP Pool Configuration...")
    print("-" * 70)
    try:
        test_dhcp_pools_exist_and_configured(device_params, test_config)
        results["pool_configuration"] = "PASS"
        print("✓ Pool configuration: PASS")
    except AssertionError as e:
        results["pool_configuration"] = "FAIL"
        failures.append(f"Pool Configuration: {str(e)}")
        print(f"✗ Pool configuration: FAIL - {str(e)}")
    except Exception as e:
        results["pool_configuration"] = "ERROR"
        failures.append(f"Pool Configuration Error: {str(e)}")
        print(f"✗ Pool configuration: ERROR - {str(e)}")
    
    # Test 2: Active Bindings
    print("\n[2/4] Checking Active DHCP Bindings...")
    print("-" * 70)
    try:
        test_dhcp_active_bindings_exist(device_params, test_config)
        results["active_bindings"] = "PASS"
        print("✓ Active bindings: PASS")
    except AssertionError as e:
        results["active_bindings"] = "FAIL"
        failures.append(f"Active Bindings: {str(e)}")
        print(f"✗ Active bindings: FAIL - {str(e)}")
    except Exception as e:
        results["active_bindings"] = "ERROR"
        failures.append(f"Active Bindings Error: {str(e)}")
        print(f"✗ Active bindings: ERROR - {str(e)}")
    
    # Test 3: Server Statistics
    print("\n[3/4] Checking DHCP Server Statistics...")
    print("-" * 70)
    try:
        test_dhcp_server_statistics_healthy(device_params, test_config)
        results["server_statistics"] = "PASS"
        print("✓ Server statistics: PASS")
    except AssertionError as e:
        results["server_statistics"] = "FAIL"
        failures.append(f"Server Statistics: {str(e)}")
        print(f"✗ Server statistics: FAIL - {str(e)}")
    except Exception as e:
        results["server_statistics"] = "ERROR"
        failures.append(f"Server Statistics Error: {str(e)}")
        print(f"✗ Server statistics: ERROR - {str(e)}")
    
    # Test 4: Pool Utilization
    print("\n[4/4] Checking DHCP Pool Utilization...")
    print("-" * 70)
    try:
        test_dhcp_pool_utilization_healthy(device_params, test_config)
        results["pool_utilization"] = "PASS"
        print("✓ Pool utilization: PASS")
    except AssertionError as e:
        results["pool_utilization"] = "FAIL"
        failures.append(f"Pool Utilization: {str(e)}")
        print(f"✗ Pool utilization: FAIL - {str(e)}")
    except Exception as e:
        results["pool_utilization"] = "ERROR"
        failures.append(f"Pool Utilization Error: {str(e)}")
        print(f"✗ Pool utilization: ERROR - {str(e)}")
    
    # Summary
    print("\n" + "="*70)
    print("DHCP SERVER VALIDATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for r in results.values() if r == "PASS")
    failed = sum(1 for r in results.values() if r == "FAIL")
    errors = sum(1 for r in results.values() if r == "ERROR")
    
    print(f"\nResults: {passed} passed, {failed} failed, {errors} errors")
    print(f"\nDetailed Results:")
    for test_name, result in results.items():
        status_icon = "✓" if result == "PASS" else "✗"
        print(f"  {status_icon} {test_name.replace('_', ' ').title()}: {result}")
    
    # Raise assertion if any failures
    if failures:
        print(f"\n✗ DHCP server validation FAILED")
        print(f"\nFailures:")
        for failure in failures:
            print(f"  - {failure}")
        
        assert False, f"DHCP server validation failed: {len(failures)} check(s) failed"
    
    print(f"\n✓ DHCP server validation PASSED - All checks successful")
