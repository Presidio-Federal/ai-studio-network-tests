"""
DHCP Relay Validation Test

This test validates DHCP relay (ip helper-address) configuration on interfaces.

Requirements:
    - Device must be configured with DHCP relay
    - Interfaces serving clients should have helper addresses

Validates:
    - Helper addresses are configured on required interfaces
    - Helper addresses point to valid DHCP servers
    - Multiple helper addresses configured where needed (redundancy)

Author: AI Studio Network Tests
Category: State Check - Services
Framework: PyATS

Note: This is a direct wrapper around the relay test for consistency with
      the dhcp-server and dhcp-client validation pattern.
"""

import pytest
from pyats.topology import loader
from genie.testbed import load as genie_loader

# Import sub-test module
import sys
import os

# Add parent directory to path to import sibling modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir))

# Import individual test function
from state_dhcp_relay_configured import test_dhcp_relay_configured as _relay_test


def test_dhcp_relay_validation(device_params, test_config):
    """
    DHCP relay validation wrapper.
    
    This wrapper test provides consistent naming with dhcp-server and dhcp-client
    validation tests while executing the relay configuration check.
    
    Args:
        device_params (dict): Device connection parameters
        test_config (dict): Test configuration
    
    Test Configuration:
        required_interfaces (list): Interfaces that must have helpers
        expected_helper_ips (list): Expected DHCP server IPs
        require_redundant_helpers (bool): Require multiple helpers per interface
        min_helpers_per_interface (int): Minimum helpers per interface
    """
    
    print("\n" + "="*70)
    print("DHCP RELAY VALIDATION")
    print("="*70)
    
    try:
        _relay_test(device_params, test_config)
        print("\n✓ DHCP relay validation PASSED")
    except AssertionError as e:
        print(f"\n✗ DHCP relay validation FAILED: {str(e)}")
        raise
    except Exception as e:
        print(f"\n✗ DHCP relay validation ERROR: {str(e)}")
        raise
