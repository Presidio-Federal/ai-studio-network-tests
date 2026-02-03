# HAI Network Compliance Testing Repository

## Overview

The HAI Network Compliance Testing Repository is a centralized, catalog-driven compliance validation system designed for network infrastructure security testing across multiple frameworks, vendors, and platforms. This repository enables automated compliance checking through an AI-agent accessible catalog architecture that supports multi-vendor environments and various data extraction methods.

## Key Features

### Multi-Framework Compliance Support

The repository supports multiple compliance frameworks, each with framework-specific tests and requirements:

- **STIG (Security Technical Implementation Guides)**: Department of Defense security configuration standards from DISA
- **PCI-DSS v4.0**: Payment Card Industry Data Security Standard for cardholder data protection
- **CSfC (Commercial Solutions for Classified)**: NSA-approved architecture components for classified environments
- **NIST 800-53**: Security and privacy controls for federal information systems
- **HIPAA**: Security and privacy requirements for healthcare data
- **Purdue Model**: Network segmentation standards for Industrial Control Systems (ICS/OT)

**All tests map to NIST SP 800-53 Rev 5 controls**, enabling unified compliance reporting across frameworks. See [NIST Mappings Documentation](docs/NIST-MAPPINGS.md) for complete control mappings.

### Multi-Vendor and Multi-Platform Support

Tests are organized by vendor, platform, and device role:

- **Cisco IOS-XE**: Routers and switches
- **Cisco ASA**: Firewall appliances
- **Cisco NX-OS**: Data center switches
- **Juniper Junos**: Firewalls and routers
- **Multi-vendor**: Generic baseline tests applicable across platforms

### Multiple Data Extraction Methods

The repository supports different methods of extracting configuration data from network devices:

- **NSO (Network Services Orchestrator)**: Tests consume YANG-modeled JSON/YAML data from Cisco NSO
- **Native CLI/API**: Tests parse native device configurations or API responses
- **API-Specific**: Tests for vendor-specific APIs (DNAC, SD-WAN vManage, etc.)

This architecture allows the same compliance requirement to be tested against different data sources, providing flexibility for organizations with varied tooling.

## Repository Architecture

### Catalog-Driven Design

The `catalog.json` file serves as the central registry for all compliance tests. It provides:

- Hierarchical organization by framework, extraction method, vendor, platform, and device type
- Rich metadata for each test including severity, tags, dependencies, and data paths
- AI-agent accessible structure for automated test discovery and execution
- Query capabilities for filtering tests by multiple criteria

### Directory Structure

```
hai-network-tests/
├── catalog.json                     # Central test registry
├── requirements.txt                 # Python dependencies
│
├── stig/                            # STIG compliance tests
│   ├── nso/                         # NSO extraction method
│   │   ├── cisco-ios-xe/
│   │   │   ├── router/              # 7 router tests
│   │   │   └── switch/              # 2 switch tests
│   │   └── cisco-asa-firewall/      # 10 firewall tests
│   └── native/                      # Native extraction method
│       └── cisco-ios-xe-router/     # 7 router tests
│
├── pci-dss/                         # PCI-DSS compliance tests
│   ├── nso/
│   │   └── cisco-ios-xe-router/     # 3 PCI-DSS tests
│   └── native/
│       └── cisco-ios-xe-router/     # 3 PCI-DSS tests
│
├── csfc/                            # CSfC architecture tests
│   ├── eg-dr/                       # Enclave Gateway Data in Transit
│   └── eg-fw/                       # Enclave Gateway Firewall
│
├── purdue/                          # Purdue Model ICS/OT tests
│   └── catalog/                     # Level-specific control catalogs
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

## Test Types

### Data Validation Tests

Configuration compliance validation using pytest and JSON schema validation. These tests:
- Parse structured configuration data (JSON/YAML)
- Validate against compliance requirements
- Provide detailed pass/fail results with remediation guidance
- Run quickly without requiring live device access

**Frameworks**: pytest, pydantic, jsonschema  
**Input**: Structured configuration data  
**Output**: pytest JUnit XML reports

### State Checks

Operational state validation using pyATS/Genie parsers. These tests:
- Execute operational commands on live devices
- Parse and validate operational state
- Check runtime behavior and status
- Verify control plane and data plane functionality

**Frameworks**: pyATS, Genie, NAPALM  
**Input**: Live device access or operational state dumps  
**Output**: pytest JUnit XML reports

### Traffic Tests

Traffic flow analysis and security policy validation. These tests:
- Analyze network topology and routing
- Validate security policy enforcement
- Simulate traffic flows
- Identify potential security gaps

**Frameworks**: Batfish, pybatfish  
**Input**: Configuration files and network topology  
**Output**: pytest JUnit XML reports

## Current Test Inventory

### STIG Compliance Tests

#### Cisco ASA Firewall (NSO) - 10 Tests
- CASA-FW-000040: Traffic log event types
- CASA-FW-000050: Logging timestamps
- CASA-FW-000090: Buffered logging and queue
- CASA-FW-000100: TCP syslog transport
- CASA-FW-000130: Unnecessary services disabled
- CASA-FW-000150: Basic threat detection
- CASA-FW-000200: Central syslog server
- CASA-FW-000210: Email alerts for syslog failure
- CASA-FW-000220: Scanning threat detection (CAT I High)
- CASA-FW-000270: Application layer inspection

#### Cisco IOS-XE Router (NSO) - 7 Tests
- CISC-ND-000010: Concurrent session limits
- CISC-ND-000100: Account modification auditing
- CISC-ND-000150: Login attempt limits
- CISC-ND-000280: Log timestamps
- CISC-ND-000620: Password encryption (High)
- CISC-ND-000720: Connection timeout
- CISC-ND-001210: SSH v2 with FIPS encryption (High)

#### Cisco IOS-XE Router (Native) - 7 Tests
- Identical STIG requirements as NSO, but tests native CLI/API data formats

#### Cisco IOS-XE Switch (NSO) - 2 Tests
- CISC-ND-001200: FIPS-validated HMAC for remote maintenance
- CISC-ND-001210: SSH v2 with FIPS encryption

### PCI-DSS Compliance Tests

#### Cisco IOS-XE Router (NSO + Native) - 6 Tests
- PCI-DSS 2.2.2: Password encryption and vendor defaults (High)
- PCI-DSS 8.3.6: Account lockout duration (30 minutes minimum) (High)
- PCI-DSS 10.3.4: Audit log timestamps (High)

Each requirement includes both NSO and Native extraction method versions.

### CSfC Architecture Tests

#### Juniper Junos Firewall - 14 Tests
- Enclave Gateway Data in Transit (EG-DR): 1 test
- Enclave Gateway Firewall (EG-FW): 13 tests

### General Baseline Tests - 2 Tests
- NTP server configuration and synchronization
- Clear text password detection

### Purdue Model Tests - 1 Test
- Level 3.5 DMZ boundary protection

**Total Test Count: 49 tests** across multiple frameworks and extraction methods

## Usage

### Prerequisites

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

- **Framework**: `framework='STIG'` or `framework='PCI-DSS'`
- **Extraction Method**: `extraction_method='nso'` or `extraction_method='native'`
- **Vendor**: `vendor='cisco'`
- **Platform**: `platform='ios-xe'` or `platform='asa'`
- **Device Type**: `device_type='router'` or `device_type='firewall'`
- **Test Type**: `test_type='data_validation'`
- **Severity**: `severity='high'`
- **Control ID**: `control_id='CISC-ND-001210'`
- **Tags**: `tags CONTAINS 'ssh'` or `tags CONTAINS 'encryption'`

### Example AI Agent Workflow

1. **Extract Configuration**: Agent retrieves configuration from NSO API
2. **Identify Attributes**: Determines vendor=cisco, platform=ios-xe, device_type=router
3. **Query Catalog**: 
   ```
   framework='STIG' AND extraction_method='nso' AND vendor='cisco' 
   AND platform='ios-xe' AND device_type='router'
   ```
4. **Download Tests**: Agent retrieves relevant test files
5. **Execute Tests**: Runs pytest with extracted configuration data
6. **Report Results**: Generates compliance report with pass/fail status and remediation guidance

### Catalog Structure Example

```json
{
  "compliance_frameworks": {
    "STIG": {
      "extraction_methods": {
        "nso": {
          "vendors": {
            "cisco": {
              "platforms": {
                "ios-xe": {
                  "device_types": {
                    "router": {
                      "test_types": {
                        "data_validation": {
                          "tests": [...]
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## Test Metadata

Each test in the catalog includes comprehensive metadata:

- **Unique ID**: Globally unique identifier for the test
- **Control ID**: Framework-specific control identifier (e.g., CISC-ND-000620, PCI-DSS-8.3.6)
- **NIST Controls**: Mapped NIST SP 800-53 controls (e.g., AU-9a, IA-5(1)(c))
- **CCI**: Control Correlation Identifier for cross-framework mapping
- **Finding/Rule IDs**: Official framework identifiers for audit compliance
- **Severity**: high, medium, low (or CAT I, CAT II, CAT III for STIG)
- **Description**: Human-readable test purpose
- **Tags**: Searchable keywords (encryption, ssh, logging, etc.)
- **Dependencies**: Required Python packages
- **Data Path**: JSONPath to relevant configuration section
- **Input Schema**: Expected data structure
- **Runtime**: Estimated execution time (fast, medium, slow)

**NIST Mappings**: All tests map to NIST SP 800-53 Rev 5 controls. See [NIST Mappings Documentation](docs/NIST-MAPPINGS.md) for complete mappings and [Quick Reference](docs/NIST-QUICK-REFERENCE.md) for quick lookup tables.

## Compliance Test Examples

### STIG Example: SSH Version 2 with FIPS Encryption

**STIG ID**: CISC-ND-001210  
**Severity**: CAT I (High)  
**Validates**: SSH server uses version 2 with FIPS-approved encryption algorithms

```bash
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-001210.py -v
```

**Check**: 
- SSH encryption: aes256-ctr, aes192-ctr, aes128-ctr
- SSH MAC: hmac-sha2-256, hmac-sha2-512

### PCI-DSS Example: Account Lockout Duration

**PCI-DSS Requirement**: 8.3.6  
**Severity**: High  
**Validates**: Account lockout for at least 30 minutes after failed authentication

```bash
TEST_INPUT_JSON="test-data/native/cisco-ios-xe-router/sample_cat8000v_native.json" \
  pytest pci-dss/native/cisco-ios-xe-router/native_pci_8_3_6_account_lockout.py -v
```

**Check**: Login block-for configured with lockout duration >= 1800 seconds

### CSfC Example: Enclave Gateway Firewall

**Control ID**: CSfC-EG-FW-001  
**Validates**: Only authorized gray network IPs and management traffic accepted

```bash
pytest csfc/eg-fw/test_eg_fw_1.py -v
```

## Data Formats

### NSO Data Format (YANG-modeled JSON/YAML)

```yaml
tailf-ned-cisco-ios:hostname: ROUTER-01
tailf-ned-cisco-ios:service:
  password-encryption: {}
tailf-ned-cisco-ios:ip:
  ssh:
    server:
      algorithm:
        encryption:
          - aes256-ctr
          - aes192-ctr
        mac:
          - hmac-sha2-256
```

### Native Data Format (CLI/API JSON)

```json
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-ios:hostname": "ROUTER-01",
    "tailf-ned-cisco-ios:service": {
      "password-encryption": {}
    }
  }
}
```

## Test Development

### Creating New Tests

All tests follow a consistent structure:

1. **Header Documentation**: STIG/PCI-DSS requirement details, discussion, check text, fix text
2. **Test Metadata**: Constants for IDs, severity, platform, extraction method
3. **Data Loading**: Flexible loader supporting multiple data formats
4. **Validation Logic**: Framework-specific compliance checks
5. **Detailed Output**: Pass/fail status with remediation guidance

### Example Test Structure

```python
"""
STIG ID: CISC-ND-000620
Finding ID: V-215687
Severity: High
Rule Title: Router must only store cryptographic representations of passwords
"""

import os
import json
import yaml
import pytest

STIG_ID = "CISC-ND-000620"
FINDING_ID = "V-215687"
SEVERITY = "High"
EXTRACTION_METHOD = "nso"

def load_test_data(file_path):
    # Load and normalize configuration data
    pass

def test_password_encryption_enabled():
    # Validate compliance requirement
    # Assert with detailed error messages
    # Print summary results
    pass
```

### Test Naming Convention

Tests follow a consistent naming pattern:

- **STIG NSO**: `nso-CISC-ND-000620.py`
- **STIG Native**: `native-CISC-ND-000620.py`
- **PCI-DSS NSO**: `nso_pci_8_3_6_account_lockout.py`
- **PCI-DSS Native**: `native_pci_8_3_6_account_lockout.py`
- **CSfC**: `test_eg_fw_1.py`

## Compliance Reporting

### Test Output Format

Tests provide detailed compliance information:

```
STIG Compliance Summary:
STIG ID: CISC-ND-001210
Finding ID: V-220556
Severity: High
Title: Router must use SSH version 2 with FIPS-approved encryption

Device Results:
ROUTER-01: PASS
  SSH configured with FIPS-approved algorithms
  Encryption: aes256-ctr, aes192-ctr, aes128-ctr
  MAC: hmac-sha2-256
```

### Failure Reporting

Non-compliant configurations receive detailed remediation guidance:

```
Device ROUTER-01 is not compliant with STIG CISC-ND-000620:
  Password encryption is NOT enabled

Required configuration:
  Router(config)# service password-encryption

Finding: Passwords are stored in clear text and can be easily compromised.
Risk: Unauthorized access if configuration is exposed.
```

## Supported Compliance Requirements

### STIG Coverage

**Cisco IOS-XE Routers**: 14 tests covering:
- Access control and session management
- Account management and auditing
- Password and authentication security
- Remote access security (SSH, HTTPS)
- Logging and audit requirements

**Cisco ASA Firewalls**: 10 tests covering:
- Logging and audit configuration
- Syslog transport and redundancy
- Email alerting for failures
- Threat detection (basic and scanning)
- Application layer inspection
- Service hardening

### PCI-DSS Coverage

**Network Security Controls**: 6 tests covering:
- Requirement 2.2.2: Vendor default management
- Requirement 8.3.6: Account lockout duration
- Requirement 10.3.4: Audit log timestamps

### CSfC Coverage

**Enclave Gateway Architectures**: 14 tests covering:
- Firewall security policies
- Access control enforcement
- Encrypted tunnel configurations

## Benefits

### For Security Teams

- **Automated Compliance Validation**: Run compliance checks without manual configuration review
- **Consistent Testing**: Same validation logic applied across all devices
- **Multi-Framework Support**: Single repository for STIG, PCI-DSS, NIST, and other frameworks
- **Detailed Remediation**: Exact configuration commands provided for non-compliant findings
- **Historical Tracking**: Track compliance posture over time

### For Network Operations

- **Pre-Deployment Validation**: Test configurations before deploying to production
- **Change Impact Analysis**: Validate that changes maintain compliance
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

## Extending the Repository

### Adding New Frameworks

1. Add framework entry to `compliance_frameworks` in catalog.json
2. Create directory structure: `framework/extraction_method/vendor-platform-role/`
3. Develop tests following established patterns
4. Add test metadata to catalog

### Adding New Platforms

1. Register platform in `platform_registry`
2. Create test directories under relevant frameworks
3. Develop platform-specific tests
4. Update catalog with test entries

### Adding New Tests

1. Identify compliance requirement and framework
2. Create test file in appropriate directory
3. Follow naming convention: `{extraction_method}-{control_id}.py`
4. Include full requirement documentation in test header
5. Add test entry to catalog.json with complete metadata

## Roadmap

### Planned Enhancements

- **Additional STIG Tests**: Expand coverage for routers, switches, and firewalls
- **NIST 800-53 Tests**: Implement NIST security control validation
- **HIPAA Tests**: Healthcare-specific network security tests
- **Juniper Platform Tests**: Expand multi-vendor support
- **State Check Tests**: Add pyATS-based operational validation
- **Traffic Analysis Tests**: Implement Batfish policy validation
- **API Integration**: REST API for programmatic catalog queries
- **CI/CD Integration**: GitHub Actions workflows for automated testing

## Test Data Management

The `test-data/` directory contains sample configurations for testing and validation. This directory is excluded from version control via `.gitignore` to prevent accidental exposure of production configurations.

### Directory Structure

```
test-data/
├── nso/
│   ├── cisco-ios-xe-router/
│   │   └── sample-cat8000v.yaml
│   └── cisco-asa-firewall/
│       └── sample-asa.json
└── native/
    └── cisco-ios-xe-router/
        ├── sample_cat8000v_native.json
        └── sample_cat8000v_cli.txt
```

## Contributing

When adding new tests:

1. Follow established directory structure and naming conventions
2. Include complete requirement documentation in test header
3. Support both JSON and YAML input formats
4. Provide detailed pass/fail messages with remediation guidance
5. Add comprehensive metadata to catalog.json
6. Test against sample configurations before committing

## License

This repository is maintained by Presidio Federal HAI Team for internal compliance validation purposes.

## Documentation

- **[README.md](README.md)**: Repository overview and usage guide (this file)
- **[Data Models Guide](docs/DATA-MODELS.md)**: Configuration extraction methods and API calls for each platform
- **[NIST Mappings](docs/NIST-MAPPINGS.md)**: Comprehensive NIST SP 800-53 control mappings with control descriptions
- **[NIST Quick Reference](docs/NIST-QUICK-REFERENCE.md)**: Quick lookup tables for NIST controls and test files
- **[NIST Mappings Data](docs/nist-800-53-mappings.json)**: Machine-readable NIST mapping data for AI agent queries
- **[catalog.json](catalog.json)**: Complete test inventory with metadata

## Maintainer

Presidio Federal HAI Team

## Version

Current Version: 2.0.0  
Last Updated: 2026-01-30

## Summary Statistics

- **Total Tests**: 49
- **Compliance Frameworks**: 6 (STIG, PCI-DSS, CSfC, NIST, HIPAA, Purdue)
- **Vendors Supported**: 2 (Cisco, Juniper)
- **Platforms**: 5 (IOS-XE, ASA, NX-OS, Junos, Multi-vendor)
- **Extraction Methods**: 3 (NSO, Native, API-specific)
- **Test Types**: 3 (Data Validation, State Checks, Traffic Tests)
- **Active Development**: Ongoing expansion of test coverage

---

This repository represents a comprehensive, scalable approach to network infrastructure compliance testing, designed for automation, AI agent integration, and multi-framework security validation.
