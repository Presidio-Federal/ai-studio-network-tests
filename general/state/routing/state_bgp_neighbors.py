"""
BGP Neighbors Established Test
Validates that all BGP neighbors are in Established state.

This test uses pyATS/Genie to learn BGP state and verify all neighbors.
Based on pyATS example: BGP_Neighbors_Established.py
"""

import pytest
import logging
from pyats.topology import loader
from genie.conf import Genie
from genie.abstract import Lookup
from tabulate import tabulate

logger = logging.getLogger(__name__)


def test_bgp_neighbors_established(device_params, test_config):
    """
    Test that all BGP neighbors are in Established state.
    
    Args:
        device_params: Device connection parameters
        test_config: Test configuration (can be empty for this test)
    """
    # Build testbed from device params
    enable_password = device_params.get('enable_password', device_params.get('password'))
    device_name = device_params.get('device_name', 'device')
    
    testbed_yaml = f"""
testbed:
  name: bgp_test
devices:
  {device_name}:
    os: iosxe
    type: router
    credentials:
      default:
        username: {device_params['username']}
        password: {device_params['password']}
      enable:
        password: {enable_password}
    connections:
      cli:
        protocol: ssh
        ip: {device_params['host']}
        port: {device_params['port']}
"""
    
    # Load testbed
    testbed = loader.load(testbed_yaml)
    genie_testbed = Genie.init(testbed)
    
    # Get device
    device = genie_testbed.devices[device_name]
    
    # Connect with learn_hostname enabled
    logger.info(f"Connecting to {device.name}")
    device.connect(learn_hostname=True)
    
    try:
        # Learn BGP using Genie
        logger.info(f"Learning BGP information from {device.name}")
        
        # Import BGP ops directly instead of using abstract lookup
        from genie.libs.ops.bgp.iosxe.bgp import Bgp
        
        bgp = Bgp(device)
        bgp.learn()
        
        assert hasattr(bgp, 'info'), f"Failed to learn BGP info from {device.name}"
        
        # Check all BGP neighbors
        failed_neighbors = []
        all_neighbors_status = []
        
        # Navigate BGP structure
        vrfs_dict = bgp.info['instance']['default']['vrf']
        
        for vrf_name, vrf_dict in vrfs_dict.items():
            neighbors = vrf_dict.get('neighbor', {})
            
            for nbr, props in neighbors.items():
                state = props.get('session_state', 'unknown')
                
                neighbor_info = {
                    'vrf': vrf_name,
                    'neighbor': nbr,
                    'state': state,
                    'status': 'PASS' if state.lower() == 'established' else 'FAIL'
                }
                
                all_neighbors_status.append(neighbor_info)
                
                if state.lower() != 'established':
                    failed_neighbors.append({
                        'neighbor': nbr,
                        'vrf': vrf_name,
                        'state': state,
                        'expected': 'Established'
                    })
        
        # Build status table for logging
        table_data = [
            [n['vrf'], n['neighbor'], n['state'], n['status']]
            for n in all_neighbors_status
        ]
        
        logger.info(f"\nBGP Status for {device.name}:")
        logger.info("\n" + tabulate(
            table_data,
            headers=['VRF', 'Neighbor', 'State', 'Status'],
            tablefmt='grid'
        ))
        
        # Disconnect
        device.disconnect()
        
        # Assert all neighbors are established
        assert len(failed_neighbors) == 0, (
            f"Found {len(failed_neighbors)} BGP neighbors not in Established state:\n" +
            "\n".join([
                f"  - {n['neighbor']} (VRF: {n['vrf']}): {n['state']}"
                for n in failed_neighbors
            ])
        )
        
        logger.info(f"✓ All {len(all_neighbors_status)} BGP neighbors are Established")
        
    finally:
        # Ensure disconnect
        if device.is_connected():
            device.disconnect()


def test_bgp_neighbors_exist(device_params, test_config):
    """
    Test that BGP is configured and has at least one neighbor.
    
    Args:
        device_params: Device connection parameters
        test_config: Test configuration
            - min_neighbors: Minimum expected neighbors (optional, default: 1)
    """
    min_neighbors = test_config.get('min_neighbors', 1)
    enable_password = device_params.get('enable_password', device_params.get('password'))
    device_name = device_params.get('device_name', 'device')
    
    # Build testbed
    testbed_yaml = f"""
testbed:
  name: bgp_test
devices:
  {device_name}:
    os: iosxe
    type: router
    credentials:
      default:
        username: {device_params['username']}
        password: {device_params['password']}
      enable:
        password: {enable_password}
    connections:
      cli:
        protocol: ssh
        ip: {device_params['host']}
        port: {device_params['port']}
"""
    
    testbed = loader.load(testbed_yaml)
    genie_testbed = Genie.init(testbed)
    device = genie_testbed.devices[device_name]
    
    device.connect(learn_hostname=True)
    
    try:
        # Learn BGP
        from genie.libs.ops.bgp.iosxe.bgp import Bgp
        
        bgp = Bgp(device)
        bgp.learn()
        
        assert hasattr(bgp, 'info'), "BGP is not configured on device"
        
        # Count neighbors
        total_neighbors = 0
        vrfs_dict = bgp.info['instance']['default']['vrf']
        
        for vrf_name, vrf_dict in vrfs_dict.items():
            neighbors = vrf_dict.get('neighbor', {})
            total_neighbors += len(neighbors)
        
        device.disconnect()
        
        assert total_neighbors >= min_neighbors, (
            f"Expected at least {min_neighbors} BGP neighbor(s), found {total_neighbors}"
        )
        
        logger.info(f"✓ Found {total_neighbors} BGP neighbors (minimum: {min_neighbors})")
        
    finally:
        if device.is_connected():
            device.disconnect()
