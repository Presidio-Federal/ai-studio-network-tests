# AI Studio Network Compliance Testing Repository

## Overview

This repository contains multivendor compliance checks that can be presented to an AI agent and executed using MCP (Model Context Protocol). Network testing is made as easy as possible - your agent can query the up-to-date test catalog, select tests, and run them against your data or live network. The agent will then report whether you are compliant with your selected framework.

## Table of Contents

### Test Types
- [Data Validation](#data-validation)
- [Predictive Validation](#predictive-validation) *(Coming Soon)*
- [State Checks](#state-checks)

### Getting Started
- [Data Validation - Getting The Structured Data](#getting-the-structured-data)
- [Data Validation - Running The Checks](#running-data-validation-checks)
- [State Checks - Building A Testbed](#building-a-testbed)
- [State Checks - Running State Checks](#running-state-checks)
- [State Checks - Adding Tests](#adding-state-check-tests)

### Compliance Frameworks
- [HIPAA](#hipaa-compliance)
- [PCI-DSS](#pci-dss-compliance)
- [STIG](#stig-compliance)
- [Purdue Model](#purdue-model)
- [NIST Mapping](#nist-mappings)

### Documentation
- [Test Development Guide](docs/TEST_DEVELOPMENT_GUIDE.md)
- [Data Models Guide](docs/DATA-MODELS.md)
- [NIST Mappings](docs/NIST-MAPPINGS.md)
- [NIST Quick Reference](docs/NIST-QUICK-REFERENCE.md)
- [HIPAA Implementation](docs/HIPAA-TESTS-COMPLETE.md)
- [Compliance Framework Expansion](docs/COMPLIANCE-FRAMEWORK-EXPANSION-REPORT.md)

---

## Test Types

AI Studio provides three types of network testing to validate compliance:

### Data Validation

**Data validation tests** check network device configurations against compliance requirements using structured configuration data. These tests:

- Parse configuration data (JSON/YAML) extracted from network devices
- Validate settings against specific compliance framework requirements
- Provide immediate pass/fail results with detailed remediation guidance
- Run quickly without requiring live device access
- Support multiple extraction methods (NSO, Native API, CLI parsing)

**How it works**: Configuration data is extracted from devices using NSO RESTCONF, native device APIs (RESTCONF, NX-API, Juniper REST), or CLI parsing tools. The structured data is then validated against compliance rules defined in pytest-based tests. Each test checks specific configuration elements (e.g., password encryption, SSH algorithms, logging configuration) and reports compliance status.

**Tools**: pytest, pydantic, jsonschema, YAML/JSON parsers

**Frameworks**: pytest, pydantic, jsonschema  
**Input**: Structured configuration data (JSON/YAML)  
**Output**: pytest JUnit XML reports with detailed findings

### Predictive Validation *(Coming Soon)*

**Predictive validation tests** allow your AI agent to use Batfish to conduct pre-built tests against network snapshots for various compliance checks before deployment. These tests:

- Analyze network topology and routing using Batfish
- Validate security policy enforcement across the network
- Simulate traffic flows to identify potential issues
- Detect configuration errors before deployment
- Verify reachability and access control policies

**How it works**: Network device configurations are loaded into Batfish, which builds a complete model of the network including routing tables, ACLs, and traffic flows. Tests query this model to validate compliance requirements like proper segmentation, traffic filtering, and security policy enforcement.

**Tools**: Batfish, pybatfish  
**Frameworks**: Batfish, pybatfish  
**Input**: Configuration files and network topology  
**Output**: pytest JUnit XML reports with policy violations

### State Checks

**State checks** validate operational state and runtime behavior of live network devices using pyATS/Genie. These tests:

- Connect directly to live network devices via SSH
- Execute operational commands (show commands) on devices
- Parse command output using Genie parsers for structured data
- Validate runtime state (BGP neighbors, interface status, routing tables)
- Verify control plane and data plane functionality
- Check operational aspects that cannot be validated from configuration alone

**How it works**: Tests use pyATS to establish SSH connections to devices, execute show commands, and parse the output using Genie's vendor-specific parsers. The parsed data is validated against operational requirements (e.g., BGP neighbors established, NTP synchronized, interfaces up).

**Tools**: pyATS, Genie, Netmiko  
**Frameworks**: pyATS, Genie, NAPALM  
**Input**: Live device access via SSH (testbed with credentials)  
**Output**: pytest JUnit XML reports with operational state validation

---

## Multi-Framework Compliance Support

The repository supports multiple compliance frameworks, each with framework-specific tests and requirements:

- **STIG (Security Technical Implementation Guides)**: Department of Defense security configuration standards from DISA
- **PCI-DSS v4.0**: Payment Card Industry Data Security Standard for cardholder data protection
- **CSfC (Commercial Solutions for Classified)**: NSA-approved architecture components for classified environments
- **NIST 800-53**: Security and privacy controls for federal information systems
- **HIPAA**: Security and privacy requirements for healthcare data
- **Purdue Model**: Network segmentation standards for Industrial Control Systems (ICS/OT)

**All tests map to NIST SP 800-53 Rev 5 controls**, enabling unified compliance reporting across frameworks. See [NIST Mappings Documentation](docs/NIST-MAPPINGS.md) for complete control mappings.

## Multi-Vendor and Multi-Platform Support

Tests are organized by vendor, platform, and device role:

- **Cisco IOS-XE**: Routers and switches
- **Cisco ASA**: Firewall appliances
- **Cisco NX-OS**: Data center switches
- **Juniper Junos**: Firewalls and routers
- **Multi-vendor**: Generic baseline tests applicable across platforms

---

## Data Validation

Data validation tests check device configurations against compliance requirements without requiring live device access.

### Getting The Structured Data

Before running data validation tests, you must extract configuration data from your network devices in the correct format. The repository supports two extraction methods:

#### NSO (Network Services Orchestrator) Extraction

NSO provides YANG-modeled configuration data with consistent structure across vendors.

**Extract configuration from NSO:**

```bash
curl --location "http://<NSO_IP>:8080/restconf/data/tailf-ncs:devices/device=<DEVICE_NAME>/config" \
  --header 'Accept: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>' \
  --output config.json
```

**Example:**
```bash
NSO_IP="10.0.0.1"
DEVICE_NAME="ROUTER-01"
AUTH=$(echo -n "admin:password" | base64)

curl "http://${NSO_IP}:8080/restconf/data/tailf-ncs:devices/device=${DEVICE_NAME}/config" \
  --header 'Accept: application/yang-data+json' \
  --header "Authorization: Basic ${AUTH}" \
  -o test-data/nso/cisco-ios-xe-router/${DEVICE_NAME}-config.json
```

#### Native Device Extraction

Extract directly from devices using vendor-specific APIs.

**Cisco IOS-XE (RESTCONF):**
```bash
curl "https://<DEVICE_IP>/restconf/data/Cisco-IOS-XE-native:native" \
  --header 'Accept: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>' \
  --insecure -o config.json
```

**Juniper SRX (REST API):**
```bash
curl "http://<DEVICE_IP>:3000/rpc/get-configuration" \
  --header 'Accept: application/json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>' \
  -o config.json
```

**Cisco NX-OS (NX-API):**
```bash
curl "https://<DEVICE_IP>/ins" \
  --header 'Content-Type: application/json' \
  --data '{"ins_api": {"version": "1.0", "type": "cli_show", "chunk": "0", "sid": "1", "input": "show running-config", "output_format": "json"}}' \
  -o config.json
```

For complete extraction instructions, API endpoints, and data model details, see the **[Data Models Guide](docs/DATA-MODELS.md)**.

### Running Data Validation Checks

Tests are executed using pytest with configuration data provided via environment variable.

#### Basic Test Execution

Run a single test:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-000620.py -v
```

Run all tests in a directory:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-asa-firewall/sample-asa.json" \
  pytest stig/nso/cisco-asa-firewall/*.py -v
```

#### Framework-Specific Testing

Run all STIG tests for IOS-XE routers (NSO):
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/*.py -v
```

Run all PCI-DSS tests for IOS-XE routers (Native):
```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/sample_cat8000v_native.json" \
  pytest pci-dss/native/cisco-ios-xe-router/*.py -v
```

Run all HIPAA tests for IOS-XE routers:
```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/sample_cat8000v_native.json" \
  pytest hipaa/native/cisco-ios-xe-router/*.py -v
```

#### Generating Reports

HTML Report:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-asa-firewall/sample-asa.json" \
  pytest stig/nso/cisco-asa-firewall/*.py --html=report.html --self-contained-html
```

JSON Report:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/*.py --json-report --json-report-file=report.json
```

---

## Predictive Validation

*(Coming Soon)*

Batfish-based predictive validation will enable pre-deployment testing of network configurations:

- Network topology analysis
- Security policy validation
- Reachability testing
- Traffic flow simulation
- Configuration error detection

---

## State Checks

State checks validate the operational state of live network devices using pyATS and Genie.

### Building A Testbed

State checks require a testbed definition that describes how to connect to your devices. See the **[Test Development Guide](docs/TEST_DEVELOPMENT_GUIDE.md)** for complete testbed configuration.

**Example testbed structure:**
```python
{
    "device_name": "ROUTER-01",      # Hostname of device
    "host": "192.168.1.1",           # IP address
    "username": "admin",             # SSH username
    "password": "password",          # SSH password
    "device_type": "cisco_xe",       # Device type
    "port": 22                       # SSH port
}
```

### Running State Checks

State checks connect to live devices and validate operational state.

**Run BGP neighbor state check:**
```bash
pytest general/state/routing/state_bgp_neighbors.py -v
```

**Run gateway reachability check:**
```bash
pytest general/state/connectivity/state_gateway_reachability.py -v
```

**Run logging configuration check:**
```bash
pytest general/state/monitoring/state_logging.py -v
```

State checks use pytest fixtures to pass device connection parameters and test-specific configuration.

### Adding State Check Tests

To create new state check tests, follow the patterns in the **[Test Development Guide](docs/TEST_DEVELOPMENT_GUIDE.md)**:

1. **Use standardized fixtures**: Accept `device_params` and `test_config` fixtures
2. **Connect with pyATS**: Use pyATS/Genie for structured data parsing
3. **Print validation details**: Use `print()` statements for agent visibility
4. **Register in catalog**: Add test metadata to `catalog.json`

**Example test structure:**
```python
from genie.testbed import load
from pyats.topology import loader

def test_bgp_neighbors(device_params, test_config):
    """Validate BGP neighbors are established."""
    
    # Build testbed from device_params
    testbed_dict = {
        "devices": {
            device_params["device_name"]: {
                "type": "router",
                "os": "iosxe",
                "credentials": {"default": {
                    "username": device_params["username"],
                    "password": device_params["password"]
                }},
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": device_params["host"]
                    }
                }
            }
        }
    }
    
    # Connect and validate
    testbed = loader.load(testbed_dict)
    device = testbed.devices[device_params["device_name"]]
    device.connect()
    
    try:
        bgp_data = device.learn("bgp")
        # Validation logic here
        print(f"\n✓ All BGP neighbors are established")
    finally:
        device.disconnect()
```

For complete examples and best practices, see:
- **[Test Development Guide](docs/TEST_DEVELOPMENT_GUIDE.md)**: Complete test writing instructions
- **Example tests**: `general/state/connectivity/state_gateway_reachability.py`
- **Example tests**: `general/state/routing/state_bgp_neighbors.py`

---

## Repository Architecture

### Catalog-Driven Design

The `catalog.json` file serves as the central registry for all compliance tests. It provides:

- Hierarchical organization by framework, extraction method, vendor, platform, and device type
- Rich metadata for each test including severity, tags, dependencies, and data paths
- AI-agent accessible structure for automated test discovery and execution
- Query capabilities for filtering tests by multiple criteria

### Directory Structure

```
ai-studio-network-tests/
├── catalog.json                     # Central test registry
├── requirements.txt                 # Python dependencies
│
├── stig/                            # STIG compliance tests
│   ├── nso/                         # NSO extraction method
│   │   ├── cisco-ios-xe/
│   │   │   ├── router/              # Router tests
│   │   │   └── switch/              # Switch tests
│   │   └── cisco-asa-firewall/      # Firewall tests
│   └── native/                      # Native extraction method
│       ├── cisco-ios-xe-router/     # Router tests
│       └── juniper-srx-gateway/     # SRX gateway tests
│
├── pci-dss/                         # PCI-DSS compliance tests
│   ├── nso/
│   │   └── cisco-ios-xe-router/
│   └── native/
│       └── cisco-ios-xe-router/
│
├── hipaa/                           # HIPAA compliance tests
│   ├── nso/
│   │   └── cisco-ios-xe-router/
│   └── native/
│       └── cisco-ios-xe-router/
│
├── csfc/                            # CSfC architecture tests
│   ├── eg-dr/                       # Enclave Gateway Data in Transit
│   └── eg-fw/                       # Enclave Gateway Firewall
│
├── purdue/                          # Purdue Model ICS/OT tests
│   └── level-3.5/                   # Level 3.5 tests
│
├── general/                         # General state checks
│   └── state/                       # State validation tests
│       ├── connectivity/            # Connectivity tests
│       ├── routing/                 # Routing tests
│       └── monitoring/              # Monitoring tests
│
├── docs/                            # Documentation
│   ├── DATA-MODELS.md
│   ├── TEST_DEVELOPMENT_GUIDE.md
│   ├── NIST-MAPPINGS.md
│   └── ...
│
└── test-data/                       # Sample configurations (gitignored)
    ├── nso/                         # NSO format samples
    └── native/                      # Native format samples
```

### Test Organization

Tests are organized in a hierarchical structure:

```
compliance_framework/
  └── extraction_method/
      └── vendor/
          └── platform/
              └── device_type/
                  └── test_type/
                      └── individual_tests/
```

This organization enables precise test discovery based on:
- What compliance framework applies
- How configuration data was extracted
- What vendor and platform is being tested
- What role the device serves (router, switch, firewall)
- What type of test is needed (data validation, state checks, traffic analysis)

## Available Compliance Frameworks

### HIPAA Compliance

**Health Insurance Portability and Accountability Act** - Security and privacy requirements for healthcare data.

The HIPAA test suite validates technical safeguards required by 45 CFR § 164.312:

- **Access Control**: Unique user identification, automatic logoff, emergency access procedures
- **Audit Controls**: Comprehensive logging, log retention, centralized logging
- **Integrity**: Configuration change control, data integrity validation
- **Authentication**: Multi-factor authentication, password complexity, account lockout
- **Transmission Security**: Encryption in transit, strong cryptography, secure protocols

**Current Coverage**: 3 tests for Cisco IOS-XE (expandable to 17 tests)  
**Severity Levels**: High, Medium  
**NIST Mapping**: AC-2, AC-7, AC-11, AU-2, IA-2, IA-5, SC-8, SC-13

**Documentation**: [HIPAA Implementation Guide](docs/HIPAA-TESTS-COMPLETE.md)

**Example Test**:
```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/config.json" \
  pytest hipaa/native/cisco-ios-xe-router/native-HIPAA-PA-004.py -v
```

### PCI-DSS Compliance

**Payment Card Industry Data Security Standard v4.0** - Requirements for protecting cardholder data.

The PCI-DSS test suite validates network security controls for payment card processing environments:

- **Requirement 1**: Network security controls (firewall rules, change control)
- **Requirement 2**: Secure configurations (vendor defaults, strong crypto, disabled services)
- **Requirement 8**: User identification and authentication (unique IDs, MFA, password policies)
- **Requirement 10**: Logging and monitoring (comprehensive logs, log protection, log review)

**Current Coverage**: 6 tests for Cisco IOS-XE (expandable to 44 tests)  
**Severity Levels**: Critical, High, Medium  
**NIST Mapping**: AC-2, AC-3, AU-2, AU-3, IA-2, IA-5, SC-8, SC-13

**Example Test**:
```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/config.json" \
  pytest pci-dss/native/cisco-ios-xe-router/native_pci_8_3_6_account_lockout.py -v
```

### STIG Compliance

**Security Technical Implementation Guides** - Department of Defense security configuration standards from DISA.

The STIG test suite validates DoD security requirements for network devices:

#### Cisco IOS-XE (29 tests)
- Session management and access control
- Account management and auditing  
- Password and authentication security
- Remote access security (SSH, HTTPS)
- Logging and audit requirements
- Service hardening
- **State Checks**: Inactive interface validation (pyATS/Genie)
- **Switch-Specific**: Gratuitous ARP protection (DoS prevention), Auxiliary port security

#### Cisco ASA Firewall (10 tests)
- Logging and audit configuration
- Syslog transport and redundancy
- Email alerting for failures
- Threat detection (basic and scanning)
- Application layer inspection

#### Juniper SRX (11 tests)
- Password policy enforcement
- SSH configuration and hardening
- Session timeout controls
- Authentication mechanisms

**Current Coverage**: 50 tests across multiple platforms  
**Severity Levels**: CAT I (High), CAT II (Medium), CAT III (Low)  
**NIST Mapping**: All tests map to NIST SP 800-53 Rev 5 controls

**Example Tests**:
```bash
# Data validation test (configuration check)
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/config.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-001210.py -v

# Native switch test (gratuitous ARP check)
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/config.json" \
  pytest stig/native/cisco-ios-xe-switch/native-CISC-RT-000150.py -v

# Native switch test (auxiliary port security)
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/config.json" \
  pytest stig/native/cisco-ios-xe-switch/native-CISC-RT-000230.py -v

# State check test (live device operational state)
pytest stig/state/cisco-ios-xe-switch/state-CISC-RT-000060.py \
  --testbed=testbed.yaml -v
```

### Purdue Model

**Industrial Control System (ICS/OT) Network Segmentation** - Network segmentation standards for operational technology.

The Purdue Model test suite validates network segmentation for ICS/OT environments:

- **Level 3.5 (DMZ)**: Boundary protection between IT and OT networks
- **Level 4 (Enterprise)**: Business network security controls

**Current Coverage**: 1 test for Level 3.5 DMZ boundary protection  
**Use Case**: Manufacturing, utilities, critical infrastructure  
**NIST Mapping**: SC-7 (Boundary Protection)

**Example Test**:
```bash
pytest purdue/level-3.5/tests/L3.5-SC7-001_test.py -v
```

### NIST Mappings

**All tests map to NIST SP 800-53 Rev 5 controls**, enabling unified compliance reporting across frameworks.

The NIST mapping provides:
- Cross-framework control alignment
- Unified compliance reporting
- Control family grouping (AC, AU, IA, SC, etc.)
- Control descriptions and requirements

**Available Documentation**:
- **[NIST Mappings](docs/NIST-MAPPINGS.md)**: Complete control mappings with descriptions
- **[NIST Quick Reference](docs/NIST-QUICK-REFERENCE.md)**: Quick lookup tables
- **[nist-800-53-mappings.json](docs/nist-800-53-mappings.json)**: Machine-readable mapping data

**Example**: A single password encryption test validates:
- STIG: CISC-ND-000620
- PCI-DSS: 2.2.2
- HIPAA: HIPAA-PA-002
- NIST: IA-5(1)(c)

---

---

## Prerequisites

Python 3.8 or higher with the following dependencies:

```bash
pip install -r requirements.txt
```

Required packages:
- pytest
- pyyaml
- jsonschema
- pytest-html
- pytest-json-report

### Configuration Data Extraction

Before running tests, you need to extract configuration data from your network devices in the correct format. See the **[Data Models Guide](docs/DATA-MODELS.md)** for detailed instructions on:

- API calls for each platform (IOS-XE, ASA, SRX, NX-OS)
- NSO vs Native extraction methods
- Data structure requirements
- Sample configurations
- Troubleshooting extraction issues

**Quick Start**:
```bash
# Extract from NSO
curl http://<NSO_IP>:8080/restconf/data/tailf-ncs:devices/device=<NAME>/config \
  --header 'Accept: application/yang-data+json' \
  --header 'Authorization: Basic <AUTH>' -o config.json

# Extract from Native IOS-XE
curl https://<DEVICE_IP>/restconf/data/Cisco-IOS-XE-native:native \
  --header 'Accept: application/yang-data+json' \
  --header 'Authorization: Basic <AUTH>' --insecure -o config.json

# Extract from Native Juniper SRX
curl http://<DEVICE_IP>:3000/rpc/get-configuration \
  --header 'Accept: application/json' \
  --header 'Authorization: Basic <AUTH>' -o config.json
```

### Running Tests

Tests are executed using pytest with configuration data provided via environment variable.

#### Basic Test Execution

Run a single test:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-000620.py -v
```

Run all tests in a directory:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-asa-firewall/sample-asa.json" \
  pytest stig/nso/cisco-asa-firewall/*.py -v
```

#### Framework-Specific Testing

Run all STIG tests for IOS-XE routers (NSO):
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/*.py -v
```

Run all PCI-DSS tests for IOS-XE routers (Native):
```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/sample_cat8000v_native.json" \
  pytest pci-dss/native/cisco-ios-xe-router/*.py -v
```

#### Generating Reports

HTML Report:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-asa-firewall/sample-asa.json" \
  pytest stig/nso/cisco-asa-firewall/*.py --html=report.html --self-contained-html
```

JSON Report:
```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/*.py --json-report --json-report-file=report.json
```

### Virtual Environment Setup

For isolated testing:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## AI Agent Integration

### Catalog Query System

The catalog is designed for programmatic access by AI agents. Agents can query tests based on:

- **Framework**: `framework='STIG'` or `framework='PCI-DSS'` or `framework='HIPAA'`
- **Extraction Method**: `extraction_method='nso'` or `extraction_method='native'`
- **Vendor**: `vendor='cisco'` or `vendor='juniper'`
- **Platform**: `platform='ios-xe'` or `platform='asa'` or `platform='junos'`
- **Device Type**: `device_type='router'` or `device_type='firewall'`
- **Test Type**: `test_type='data_validation'` or `test_type='state_checks'`
- **Severity**: `severity='high'` or `severity='critical'`
- **Control ID**: `control_id='CISC-ND-001210'`
- **Tags**: `tags CONTAINS 'ssh'` or `tags CONTAINS 'encryption'`

### Example AI Agent Workflow

1. **Extract Configuration**: Agent retrieves configuration from NSO API or native device API
2. **Identify Attributes**: Determines vendor=cisco, platform=ios-xe, device_type=router
3. **Query Catalog**: 
   ```
   framework='STIG' AND extraction_method='nso' AND vendor='cisco' 
   AND platform='ios-xe' AND device_type='router'
   ```
4. **Download Tests**: Agent retrieves relevant test files from repository
5. **Execute Tests**: Runs pytest with extracted configuration data
6. **Report Results**: Generates compliance report with pass/fail status and remediation guidance

---

## Test Development

### Creating New Tests

All tests follow a consistent structure. See the **[Test Development Guide](docs/TEST_DEVELOPMENT_GUIDE.md)** for complete instructions on:

- Data validation test structure
- State check test structure
- PyATS testbed configuration
- Output formatting for AI agents
- Catalog registration

### Test Naming Convention

Tests follow a consistent naming pattern:

- **STIG NSO**: `nso-CISC-ND-000620.py`
- **STIG Native**: `native-CISC-ND-000620.py`
- **PCI-DSS NSO**: `nso_pci_8_3_6_account_lockout.py`
- **PCI-DSS Native**: `native_pci_8_3_6_account_lockout.py`
- **HIPAA NSO**: `nso-HIPAA-PA-004.py`
- **HIPAA Native**: `native-HIPAA-PA-004.py`
- **State Checks**: `state_bgp_neighbors.py`, `state_gateway_reachability.py`

---

## Benefits

### For Security Teams

- **Automated Compliance Validation**: Run compliance checks without manual configuration review
- **Consistent Testing**: Same validation logic applied across all devices
- **Multi-Framework Support**: Single repository for STIG, PCI-DSS, HIPAA, NIST, and other frameworks
- **Detailed Remediation**: Exact configuration commands provided for non-compliant findings
- **Historical Tracking**: Track compliance posture over time

### For Network Operations

- **Pre-Deployment Validation**: Test configurations before deploying to production
- **Change Impact Analysis**: Validate that changes maintain compliance
- **Operational State Validation**: Verify runtime behavior with state checks
- **Documentation**: Built-in documentation of security requirements
- **Multi-Vendor Support**: Consistent testing across Cisco, Juniper, and other vendors

### For Auditors

- **Evidence Generation**: Automated compliance reports for audit packages
- **Traceable Results**: Each test maps to specific framework requirements
- **Repeatable Process**: Consistent testing methodology
- **Framework Alignment**: Tests reference official control IDs and requirements

### For AI Agents

- **Structured Metadata**: Machine-readable catalog with rich test metadata
- **Flexible Queries**: Filter tests by multiple criteria
- **Automated Discovery**: Find relevant tests based on device attributes
- **Self-Service**: Download and execute tests without human intervention
- **MCP Integration**: Execute via Model Context Protocol for seamless AI integration

---

## Summary Statistics

- **Total Tests**: 60+ tests across data validation and state checks
- **Compliance Frameworks**: 6 (STIG, PCI-DSS, HIPAA, CSfC, NIST, Purdue)
- **Vendors Supported**: 2 (Cisco, Juniper)
- **Platforms**: 5 (IOS-XE, ASA, NX-OS, Junos, Multi-vendor)
- **Extraction Methods**: 2 (NSO, Native)
- **Test Types**: 3 (Data Validation, State Checks, Predictive Validation*)
- **Active Development**: Ongoing expansion of test coverage

*Coming Soon

---

## License

This repository is maintained by AI Studio for network compliance validation purposes.

---

This repository represents a comprehensive, scalable approach to network infrastructure compliance testing, designed for automation, AI agent integration, and multi-framework security validation.
