# NIST SP 800-53 Control Mappings

## Overview

This document provides comprehensive mappings between:
- **STIG Controls** to NIST SP 800-53 Rev 5
- **PCI-DSS Requirements** to NIST SP 800-53 Rev 5
- **CCI (Control Correlation Identifiers)** to NIST controls

All tests in this repository map to NIST SP 800-53 controls, enabling organizations to:
- Demonstrate NIST compliance through STIG/PCI-DSS testing
- Map multiple frameworks to a common control baseline
- Prioritize testing based on NIST baseline requirements (LOW, MODERATE, HIGH)

---

## NIST Control Family Coverage

| Control Family | Family Name | Controls Covered | Tests Available |
|----------------|-------------|------------------|-----------------|
| **AC** | Access Control | 5 | 11 |
| **AU** | Audit and Accountability | 7 | 15 |
| **CM** | Configuration Management | 4 | 6 |
| **IA** | Identification and Authentication | 1 | 4 |
| **SC** | System and Communications Protection | 3 | 4 |

**Total**: 16 unique NIST controls across 5 control families

---

## STIG to NIST Mappings

### Access Control (AC)

| STIG ID | Finding | NIST Control | CCI | Description | Tests |
|---------|---------|--------------|-----|-------------|-------|
| CISC-ND-000010 | V-215662 | AC-10 | CCI-000054 | Concurrent session limits | NSO, Native |
| CISC-ND-000100 | V-215664 | AC-2(4) | CCI-001403 | Automated account audit | NSO, Native |
| CISC-ND-000150 | V-215668 | AC-7a | CCI-000044 | Login attempt limits | NSO, Native |
| CISC-ND-001200 | V-220555 | AC-17(2) | CCI-000068 | FIPS encryption for remote access | NSO |
| CISC-ND-001210 | V-220556 | AC-17(2) | CCI-000068 | SSH v2 with FIPS encryption | NSO, Native |

**Control Details**:

#### AC-10: Concurrent Session Control
- **Baseline**: MODERATE, HIGH
- **Description**: Limit number of concurrent sessions for each system account
- **Implementation**: `ip http max-connections`, VTY line limits
- **Organization Parameter**: Max sessions per account type

#### AC-2(4): Account Management - Automated Audit Actions
- **Baseline**: MODERATE, HIGH
- **Description**: Automatically audit account creation, modification, enabling, disabling, and removal
- **Implementation**: `archive log config logging enable`
- **Benefits**: Real-time account change tracking

#### AC-7a: Unsuccessful Logon Attempts
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Enforce limit of consecutive invalid logon attempts
- **Implementation**: `login block-for <seconds> attempts <count> within <window>`
- **Organization Parameters**: 
  - Number of attempts
  - Time window
  - Lockout duration

#### AC-17(2): Remote Access - Protection of Confidentiality/Integrity
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Implement cryptographic mechanisms for remote access
- **Implementation**: SSH v2, FIPS-approved encryption algorithms
- **Approved Algorithms**: AES-CTR, HMAC-SHA2

---

### Audit and Accountability (AU)

| STIG ID | Finding | NIST Control | CCI | Description | Tests |
|---------|---------|--------------|-----|-------------|-------|
| CISC-ND-000280 | V-215672 | AU-3b | CCI-000131 | Audit timestamp requirements | NSO, Native |
| CISC-ND-000380 | V-215675 | AU-9a | CCI-000163 | Audit information protection | NSO, Native |
| CASA-FW-000040 | V-239855 | AU-3a | CCI-000130 | Traffic log event types | NSO |
| CASA-FW-000050 | V-239856 | AU-3b | CCI-000131 | Traffic log timestamps | NSO |
| CASA-FW-000090 | V-239857 | AU-5b | CCI-000140 | Log queue for server failure | NSO |
| CASA-FW-000200 | V-239862 | CM-1a1(a) | CCI-001821 | Central syslog server | NSO |
| CASA-FW-000210 | V-239863 | AU-5(2) | CCI-001858 | Real-time alerts for failures | NSO |

**Control Details**:

#### AU-3: Content of Audit Records
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Ensure audit records contain sufficient information
- **Enhancements**:
  - **AU-3a**: Event type (what happened)
  - **AU-3b**: Date and time (when it happened)
- **Implementation**: `service timestamps log datetime`, ACL logging

#### AU-5: Response to Audit Processing Failures
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Alert and take action upon audit failure
- **Enhancements**:
  - **AU-5b**: Take defined actions (queue, alert, etc.)
  - **AU-5(2)**: Real-time alerts to personnel
- **Implementation**: `logging buffered`, `logging mail`, SMTP alerts

#### AU-9: Protection of Audit Information
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Protect audit info from unauthorized access
- **Enhancement AU-9a**: Protect from modification and deletion
- **Implementation**: `file privilege 15`, read-only log storage

---

### Configuration Management (CM)

| STIG ID | Finding | NIST Control | CCI | Description | Tests |
|---------|---------|--------------|-----|-------------|-------|
| CASA-FW-000100 | V-239858 | CM-6b | CCI-000366 | TCP syslog transport | NSO |
| CASA-FW-000130 | V-239859 | CM-7a | CCI-000381 | Unnecessary services disabled | NSO |
| CASA-FW-000200 | V-239862 | CM-1a1(a) | CCI-001821 | Configuration management policy | NSO |
| CASA-FW-000270 | V-239866 | CM-6b | CCI-000366 | Application layer inspection | NSO |

**Control Details**:

#### CM-6: Configuration Settings
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Establish and document configuration settings
- **Enhancement CM-6b**: Implement the configuration settings
- **Implementation**: Security baseline, hardening guides

#### CM-7: Least Functionality
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Configure system to provide only essential capabilities
- **Enhancement CM-7a**: Restrict to mission-essential capabilities
- **Implementation**: Disable telnet, HTTP, unnecessary services

#### CM-1: Configuration Management Policy and Procedures
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Develop, document, and disseminate CM policy
- **Implementation**: Centralized configuration management

---

### Identification and Authentication (IA)

| STIG ID | Finding | NIST Control | CCI | Description | Tests |
|---------|---------|--------------|-----|-------------|-------|
| CISC-ND-000620 | V-215687 | IA-5(1)(c) | CCI-000196 | Password encryption | NSO, Native |

**Control Details**:

#### IA-5(1): Authenticator Management - Password-Based Authentication
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Manage password-based authentication
- **Enhancement IA-5(1)(c)**: Store and transmit cryptographically-protected passwords
- **Implementation**: `service password-encryption`
- **Risk**: Clear-text passwords can be compromised if config accessed

---

### System and Communications Protection (SC)

| STIG ID | Finding | NIST Control | CCI | Description | Tests |
|---------|---------|--------------|-----|-------------|-------|
| CISC-ND-000720 | V-215691 | SC-10 | CCI-001133 | Session timeout/network disconnect | NSO, Native |
| CASA-FW-000150 | V-239860 | SC-5(2) | CCI-001095 | Basic threat detection for DoS | NSO |
| CASA-FW-000220 | V-239864 | SC-5a | CCI-002385 | Scanning threat detection | NSO |

**Control Details**:

#### SC-10: Network Disconnect
- **Baseline**: MODERATE, HIGH
- **Description**: Terminate network connection after defined inactivity period
- **Implementation**: `exec-timeout`, `absolute-timeout`
- **Organization Parameter**: Timeout duration (typically 10-15 minutes)

#### SC-5: Denial-of-Service Protection
- **Baseline**: LOW, MODERATE, HIGH
- **Description**: Protect against or limit effects of DoS attacks
- **Enhancements**:
  - **SC-5a**: Protection capability
  - **SC-5(2)**: Capacity/bandwidth/redundancy management
- **Implementation**: `threat-detection basic-threat`, `threat-detection scanning-threat`

---

## PCI-DSS to NIST Mappings

### PCI-DSS Requirements Mapped to NIST Controls

| PCI-DSS Req | Description | NIST Control | Control Family | Relationship |
|-------------|-------------|--------------|----------------|--------------|
| 2.2.2 | Vendor defaults managed | IA-5(1)(c), CM-6b | IA, CM | Password protection and secure config |
| 8.3.6 | Account lockout ≥30 min | AC-7a | AC | More stringent than NIST baseline |
| 10.3.4 | Date/time in audit logs | AU-3b | AU | Direct mapping |

**Key Differences Between PCI-DSS and NIST**:

1. **Account Lockout Duration**:
   - NIST AC-7a: Organization-defined duration
   - PCI-DSS 8.3.6: Minimum 30 minutes (1800 seconds)
   - **Impact**: PCI-DSS is more prescriptive

2. **Scope**:
   - NIST: Applies to all federal information systems
   - PCI-DSS: Applies specifically to Cardholder Data Environment (CDE)

3. **Baseline Applicability**:
   - NIST: Different controls for LOW/MODERATE/HIGH baselines
   - PCI-DSS: All requirements apply to CDE systems

---

## CCI (Control Correlation Identifier) Reference

### What is CCI?

CCI provides a standard identifier for security controls that:
- Links multiple security standards (DISA STIG, NIST 800-53, etc.)
- Enables cross-framework compliance mapping
- Supports automated security assessment tools

### CCI to NIST Control Mappings

| CCI | Definition | NIST Control(s) | Family |
|-----|------------|-----------------|--------|
| CCI-000044 | Enforce limit of invalid logon attempts | AC-7a | AC |
| CCI-000054 | Limit concurrent sessions | AC-10 | AC |
| CCI-000068 | Cryptographic protection for remote access | AC-17(2) | AC |
| CCI-000130 | Audit records establish event type | AU-3, AU-3a | AU |
| CCI-000131 | Audit records establish date/time | AU-3, AU-3b | AU |
| CCI-000140 | Take action upon audit failure | AU-5b | AU |
| CCI-000163 | Protect audit info from modification | AU-9, AU-9a | AU |
| CCI-000196 | Store/transmit encrypted passwords | IA-5(1)(c) | IA |
| CCI-000366 | Implement security configuration settings | CM-6b | CM |
| CCI-000381 | Provide only mission-essential capabilities | CM-7, CM-7a | CM |
| CCI-001095 | Manage capacity/bandwidth for DoS protection | SC-5(2) | SC |
| CCI-001133 | Terminate connection after inactivity | SC-10 | SC |
| CCI-001403 | Automatically audit account modification | AC-2(4) | AC |
| CCI-001821 | Define CM policy dissemination | CM-1a1(a) | CM |
| CCI-001858 | Real-time alerts for audit failures | AU-5(2) | AU |
| CCI-002385 | Protect against DoS events | SC-5, SC-5a | SC |

---

## NIST Baseline Impact Levels

### Control Coverage by Baseline

| Baseline | Description | Controls Covered | Percentage |
|----------|-------------|------------------|------------|
| **LOW** | Limited adverse impact | 12/16 | 75% |
| **MODERATE** | Serious adverse impact | 15/16 | 94% |
| **HIGH** | Severe/catastrophic impact | 15/16 | 94% |

### Baseline Definitions

**LOW Impact**: Loss of CIA has limited adverse effect on:
- Organizational operations
- Organizational assets
- Individuals

**MODERATE Impact**: Loss of CIA has serious adverse effect on:
- Organizational operations
- Organizational assets
- Individuals

**HIGH Impact**: Loss of CIA has severe or catastrophic adverse effect on:
- Organizational operations
- Organizational assets
- Individuals

---

## Using NIST Mappings

### Query by NIST Control

Find all tests for a specific NIST control:

```bash
# Find all AC-7a (unsuccessful logon) tests
grep -r "AC-7a" nist-800-53-mappings.json

# Find all AU-3 (audit content) tests
grep -r "AU-3" nist-800-53-mappings.json
```

### Query by Control Family

Find all tests for Access Control family:

```bash
# Find all AC (Access Control) tests
jq '.test_to_nist_mappings | to_entries[] | select(.value.control_family == "AC")' nist-800-53-mappings.json
```

### Query by Baseline Impact

Find all tests applicable to HIGH baseline:

```bash
# All controls marked as HIGH baseline
jq '.control_families | .[] | .controls | .[] | select(.baseline | contains(["HIGH"]))' nist-800-53-mappings.json
```

### Query by CCI

Find tests mapped to specific CCI:

```bash
# Find tests for CCI-000196 (password encryption)
jq '.test_to_nist_mappings | to_entries[] | select(.value.cci[] == "CCI-000196")' nist-800-53-mappings.json
```

---

## Framework Alignment Matrix

### STIG ↔ NIST ↔ PCI-DSS Alignment

| Technical Control | STIG ID | NIST Control | PCI-DSS Req | Notes |
|-------------------|---------|--------------|-------------|-------|
| Password encryption | CISC-ND-000620 | IA-5(1)(c) | 2.2.2 | All frameworks require |
| Account lockout | CISC-ND-000150 | AC-7a | 8.3.6 | PCI-DSS more stringent (30 min) |
| Audit timestamps | CISC-ND-000280 | AU-3b | 10.3.4 | Direct alignment |
| Session limits | CISC-ND-000010 | AC-10 | - | NIST/STIG only |
| Audit protection | CISC-ND-000380 | AU-9a | - | NIST/STIG only |
| SSH encryption | CISC-ND-001210 | AC-17(2) | - | NIST/STIG only |

**Key Insight**: Most STIG controls map to NIST, while PCI-DSS covers a subset with additional specificity for payment card environments.

---

## Compliance Reporting

### NIST Control Coverage Report

When running tests, you can generate NIST-focused reports:

```bash
# Run all tests and map to NIST controls
pytest --collect-only --quiet | python3 scripts/nist-coverage-report.py
```

**Sample Output**:
```
NIST SP 800-53 Control Coverage Report
========================================

AC-7a (Unsuccessful Logon Attempts):
  ✓ CISC-ND-000150 (NSO)    - PASS
  ✓ CISC-ND-000150 (Native) - PASS
  
AU-3b (Audit Timestamp):
  ✓ CISC-ND-000280 (NSO)    - PASS
  ✓ CISC-ND-000280 (Native) - PASS
  ✓ CASA-FW-000050 (NSO)    - PASS

IA-5(1)(c) (Password Encryption):
  ✗ CISC-ND-000620 (NSO)    - FAIL
  ✓ CISC-ND-000620 (Native) - PASS

Total Controls Tested: 16
Controls Passed: 15 (93.75%)
Controls Failed: 1 (6.25%)
```

---

## Integration with Catalog

The `catalog.json` has been enhanced to include NIST metadata. Each test entry now includes:

```json
{
  "id": "stig-nso-iosxe-router-v215675-dv-001",
  "control_id": "CISC-ND-000380",
  "nist_controls": ["AU-9", "AU-9a"],
  "cci": ["CCI-000163"],
  "control_family": "AU",
  "baseline_applicability": ["LOW", "MODERATE", "HIGH"]
}
```

This enables AI agents to query tests by NIST control:

```python
# Query all AU (Audit) family tests
tests = [t for t in catalog['tests'] if t.get('control_family') == 'AU']

# Query all HIGH baseline tests
tests = [t for t in catalog['tests'] if 'HIGH' in t.get('baseline_applicability', [])]

# Query specific NIST control
tests = [t for t in catalog['tests'] if 'AC-7a' in t.get('nist_controls', [])]
```

---

## References

- **NIST SP 800-53 Rev 5**: [https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **DISA STIG**: [https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)
- **CCI List**: [https://public.cyber.mil/stigs/cci/](https://public.cyber.mil/stigs/cci/)
- **PCI-DSS v4.0**: [https://www.pcisecuritystandards.org/](https://www.pcisecuritystandards.org/)

---

## Maintainer Notes

### Updating NIST Mappings

When adding new tests:

1. Identify the STIG/PCI-DSS requirement
2. Look up the CCI identifier in test documentation
3. Map CCI to NIST control using `nist-800-53-mappings.json`
4. Add mapping to `test_to_nist_mappings` section
5. Update control family counts in summary section

### Validation

Validate NIST mappings:

```bash
# Validate JSON structure
python3 -m json.tool nist-800-53-mappings.json > /dev/null

# Verify all test CCIs have NIST mappings
python3 scripts/validate-nist-mappings.py
```

---

**Last Updated**: 2026-01-30  
**NIST SP 800-53 Version**: Revision 5  
**Total NIST Controls Mapped**: 16  
**Total Tests with NIST Mappings**: 52
