"""
OSPF Neighbors and State Validation Test

This test validates OSPF neighbor relationships and operational state.
Uses pyATS/Genie to learn OSPF state and verify all neighbors are in FULL state.

Author: AI Studio Network Tests
Category: State Check - Routing
Framework: PyATS
"""

import pytest
import logging
from pyats.topology import loader
from genie.conf import Genie

logger = logging.getLogger(__name__)


def test_ospf_neighbors_full(device_params, test_config):
    """
    Test that all OSPF neighbors are in FULL state.
    
    Args:
        device_params: Device connection parameters
        test_config: Test configuration (can be empty for this test)
    """
    # Build testbed from device params
    enable_password = device_params.get('enable_password', device_params.get('password'))
    device_name = device_params.get('device_name', 'device')
    
    testbed_yaml = f"""
testbed:
  name: ospf_test
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
        # Learn OSPF using Genie
        logger.info(f"Learning OSPF information from {device.name}")
        
        # Import OSPF ops directly
        from genie.libs.ops.ospf.iosxe.ospf import Ospf
        
        ospf = Ospf(device)
        ospf.learn()
        
        assert hasattr(ospf, 'info'), f"Failed to learn OSPF info from {device.name}"
        
        # Check all OSPF neighbors
        failed_neighbors = []
        all_neighbors_status = []
        
        # Navigate OSPF structure
        # Structure: info['vrf'][vrf_name]['address_family'][af]['instance'][instance]['areas'][area]['interfaces'][intf]['neighbors'][neighbor_id]
        vrfs = ospf.info.get('vrf', {})
        
        for vrf_name, vrf_data in vrfs.items():
            address_families = vrf_data.get('address_family', {})
            
            for af_name, af_data in address_families.items():
                instances = af_data.get('instance', {})
                
                for instance_id, instance_data in instances.items():
                    areas = instance_data.get('areas', {})
                    
                    for area_id, area_data in areas.items():
                        interfaces = area_data.get('interfaces', {})
                        
                        for intf_name, intf_data in interfaces.items():
                            neighbors = intf_data.get('neighbors', {})
                            
                            for neighbor_id, neighbor_props in neighbors.items():
                                state = neighbor_props.get('state', 'unknown')
                                address = neighbor_props.get('address', neighbor_id)
                                
                                neighbor_info = {
                                    'vrf': vrf_name,
                                    'instance': instance_id,
                                    'area': area_id,
                                    'interface': intf_name,
                                    'neighbor_id': neighbor_id,
                                    'address': address,
                                    'state': state,
                                    'status': 'PASS' if state.lower() == 'full' else 'FAIL'
                                }
                                
                                all_neighbors_status.append(neighbor_info)
                                
                                if state.lower() != 'full':
                                    failed_neighbors.append({
                                        'neighbor_id': neighbor_id,
                                        'address': address,
                                        'interface': intf_name,
                                        'area': area_id,
                                        'state': state,
                                        'expected': 'FULL'
                                    })
        
        # Print summary for agent visibility
        print(f"\n✓ Found {len(all_neighbors_status)} OSPF neighbor(s):")
        for n in all_neighbors_status:
            status_icon = "✓" if n['status'] == 'PASS' else "✗"
            print(f"  {status_icon} {n['neighbor_id']} ({n['address']}) on {n['interface']}: {n['state']}")
            print(f"      Area: {n['area']}, Instance: {n['instance']}")
        
        # Disconnect
        device.disconnect()
        
        # Assert all neighbors are in FULL state
        assert len(failed_neighbors) == 0, (
            f"Found {len(failed_neighbors)} OSPF neighbors not in FULL state:\n" +
            "\n".join([
                f"  - {n['neighbor_id']} ({n['address']}) on {n['interface']} (Area {n['area']}): {n['state']}"
                for n in failed_neighbors
            ])
        )
        
        print(f"\n✓ All {len(all_neighbors_status)} OSPF neighbor(s) are in FULL state")
        
    finally:
        # Ensure disconnect
        if device.is_connected():
            device.disconnect()


def test_ospf_neighbors_exist(device_params, test_config):
    """
    Test that OSPF is configured and has at least one neighbor.
    
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
  name: ospf_test
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
        # Learn OSPF
        from genie.libs.ops.ospf.iosxe.ospf import Ospf
        
        ospf = Ospf(device)
        ospf.learn()
        
        assert hasattr(ospf, 'info'), "OSPF is not configured on device"
        
        # Count neighbors across all VRFs, instances, areas, and interfaces
        total_neighbors = 0
        vrfs = ospf.info.get('vrf', {})
        
        for vrf_name, vrf_data in vrfs.items():
            address_families = vrf_data.get('address_family', {})
            
            for af_name, af_data in address_families.items():
                instances = af_data.get('instance', {})
                
                for instance_id, instance_data in instances.items():
                    areas = instance_data.get('areas', {})
                    
                    for area_id, area_data in areas.items():
                        interfaces = area_data.get('interfaces', {})
                        
                        for intf_name, intf_data in interfaces.items():
                            neighbors = intf_data.get('neighbors', {})
                            total_neighbors += len(neighbors)
        
        device.disconnect()
        
        print(f"\n✓ Found {total_neighbors} OSPF neighbor(s) configured")
        
        assert total_neighbors >= min_neighbors, (
            f"Expected at least {min_neighbors} OSPF neighbor(s), found {total_neighbors}"
        )
        
        print(f"✓ Meets minimum requirement of {min_neighbors} neighbor(s)")
        
    finally:
        if device.is_connected():
            device.disconnect()
