# NIST SP 800-53 Quick Reference

## Quick Control Lookup

| NIST Control | Control Name | STIG Tests | Native Tests | PCI Tests | Total |
|--------------|--------------|------------|--------------|-----------|-------|
| AC-2(4) | Account Mgmt - Automated Audit | 1 | 1 | - | 2 |
| AC-7a | Unsuccessful Logon Attempts | 1 | 1 | 2 | 4 |
| AC-10 | Concurrent Session Control | 1 | 1 | - | 2 |
| AC-17(2) | Remote Access Encryption | 3 | 1 | - | 4 |
| AU-3a | Audit Content - Event Type | 1 | - | - | 1 |
| AU-3b | Audit Content - Date/Time | 2 | 1 | 2 | 5 |
| AU-5b | Audit Failure Response | 1 | - | - | 1 |
| AU-5(2) | Audit Failure - Real-Time Alerts | 1 | - | - | 1 |
| AU-9a | Protection of Audit Information | 1 | 1 | - | 2 |
| CM-1a1(a) | Configuration Management Policy | 1 | - | - | 1 |
| CM-6b | Configuration Settings | 2 | - | 1 | 3 |
| CM-7a | Least Functionality | 1 | - | - | 1 |
| IA-5(1)(c) | Password Encryption | 1 | 1 | 2 | 4 |
| SC-5a | DoS Protection | 1 | - | - | 1 |
| SC-5(2) | DoS - Capacity/Bandwidth | 1 | - | - | 1 |
| SC-10 | Network Disconnect | 1 | 1 | - | 2 |

**Totals**: 16 NIST controls, 35 tests with NIST mappings

---

## Control Family Summary

### AC - Access Control (5 controls, 12 tests)
- Account management and authentication controls
- Session management
- Remote access security

### AU - Audit and Accountability (7 controls, 11 tests)
- Audit record content and timestamps
- Audit failure responses
- Protection of audit information

### CM - Configuration Management (4 controls, 5 tests)
- Security configuration baselines
- Least functionality principle
- Configuration change tracking

### IA - Identification and Authentication (1 control, 4 tests)
- Password-based authentication
- Cryptographic password storage

### SC - System and Communications Protection (3 controls, 4 tests)
- Session timeout and disconnect
- Denial of service protection
- Threat detection

---

## Test Lookup by NIST Control

### Access Control (AC)

#### AC-2(4): Account Management - Automated Audit Actions
- **Tests**: CISC-ND-000100 (NSO, Native)
- **Command**: `archive log config logging enable`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000100.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000100.py`

#### AC-7a: Unsuccessful Logon Attempts
- **Tests**: CISC-ND-000150 (NSO, Native), PCI-8.3.6 (NSO, Native)
- **Command**: `login block-for <seconds> attempts <count> within <window>`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000150.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000150.py`
  - `pci-dss/nso/cisco-ios-xe-router/nso_pci_8_3_6_account_lockout.py`
  - `pci-dss/native/cisco-ios-xe-router/native_pci_8_3_6_account_lockout.py`

#### AC-10: Concurrent Session Control
- **Tests**: CISC-ND-000010 (NSO, Native)
- **Commands**: `ip http max-connections`, VTY limits
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000010.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000010.py`

#### AC-17(2): Remote Access - Protection of Confidentiality
- **Tests**: CISC-ND-001200 (NSO), CISC-ND-001210 (NSO, Native)
- **Commands**: `ip ssh server algorithm encryption`, `ip ssh server algorithm mac`
- **Files**:
  - `stig/nso/cisco-ios-xe/switch/nso-CISC-ND-001200.py`
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-001210.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-001210.py`

---

### Audit and Accountability (AU)

#### AU-3a: Content of Audit Records - Event Type
- **Tests**: CASA-FW-000040 (NSO)
- **Command**: `access-list ... deny ... log`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000040.py`

#### AU-3b: Content of Audit Records - Date and Time
- **Tests**: CISC-ND-000280 (NSO, Native), CASA-FW-000050 (NSO), PCI-10.3.4 (NSO, Native)
- **Command**: `service timestamps log datetime`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000280.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000280.py`
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000050.py`
  - `pci-dss/nso/cisco-ios-xe-router/nso_pci_10_3_4_log_timestamps.py`
  - `pci-dss/native/cisco-ios-xe-router/native_pci_10_3_4_log_timestamps.py`

#### AU-5b: Response to Audit Processing Failures
- **Tests**: CASA-FW-000090 (NSO)
- **Commands**: `logging buffered`, `logging queue`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000090.py`

#### AU-5(2): Audit Processing Failure - Real-Time Alerts
- **Tests**: CASA-FW-000210 (NSO)
- **Commands**: `logging mail`, `smtp-server`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000210.py`

#### AU-9a: Protection of Audit Information
- **Tests**: CISC-ND-000380 (NSO, Native)
- **Command**: `file privilege 15`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000380.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000380.py`

---

### Configuration Management (CM)

#### CM-1a1(a): Configuration Management Policy and Procedures
- **Tests**: CASA-FW-000200 (NSO)
- **Command**: `logging host`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000200.py`

#### CM-6b: Configuration Settings
- **Tests**: CASA-FW-000100 (NSO), CASA-FW-000270 (NSO), PCI-2.2.2 (NSO, Native)
- **Commands**: `logging host ... tcp`, `service-policy global`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000100.py`
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000270.py`
  - `pci-dss/nso/cisco-ios-xe-router/nso_pci_2_2_2_password_encryption.py`
  - `pci-dss/native/cisco-ios-xe-router/native_pci_2_2_2_password_encryption.py`

#### CM-7a: Least Functionality
- **Tests**: CASA-FW-000130 (NSO)
- **Commands**: `no http server enable`, `no telnet`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000130.py`

---

### Identification and Authentication (IA)

#### IA-5(1)(c): Password-Based Authentication - Encrypted Storage
- **Tests**: CISC-ND-000620 (NSO, Native), PCI-2.2.2 (NSO, Native)
- **Command**: `service password-encryption`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000620.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000620.py`
  - `pci-dss/nso/cisco-ios-xe-router/nso_pci_2_2_2_password_encryption.py`
  - `pci-dss/native/cisco-ios-xe-router/native_pci_2_2_2_password_encryption.py`

---

### System and Communications Protection (SC)

#### SC-5a: Denial-of-Service Protection
- **Tests**: CASA-FW-000220 (NSO)
- **Command**: `threat-detection scanning-threat shun`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000220.py`

#### SC-5(2): DoS Protection - Capacity, Bandwidth, Redundancy
- **Tests**: CASA-FW-000150 (NSO)
- **Command**: `threat-detection basic-threat`
- **Files**:
  - `stig/nso/cisco-asa-firewall/nso-CASA-FW-000150.py`

#### SC-10: Network Disconnect
- **Tests**: CISC-ND-000720 (NSO, Native)
- **Command**: `exec-timeout`, `absolute-timeout`
- **Files**:
  - `stig/nso/cisco-ios-xe/router/nso-CISC-ND-000720.py`
  - `stig/native/cisco-ios-xe-router/native-CISC-ND-000720.py`

---

## Running Tests by NIST Control

```bash
# Run all AC (Access Control) tests
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-000010.py \
         stig/nso/cisco-ios-xe/router/nso-CISC-ND-000100.py \
         stig/nso/cisco-ios-xe/router/nso-CISC-ND-000150.py \
         stig/nso/cisco-ios-xe/router/nso-CISC-ND-001210.py -v

# Run all AU (Audit and Accountability) tests for routers
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-000280.py \
         stig/nso/cisco-ios-xe/router/nso-CISC-ND-000380.py -v

# Run all IA (Identification and Authentication) tests
TEST_INPUT_JSON="test-data/nso/cisco-ios-xe-router/sample-cat8000v.yaml" \
  pytest stig/nso/cisco-ios-xe/router/nso-CISC-ND-000620.py \
         pci-dss/nso/cisco-ios-xe-router/nso_pci_2_2_2_password_encryption.py -v
```

---

## NIST Baseline Coverage

### LOW Baseline (12 controls covered)
- AC-7a, AC-17(2)
- AU-3, AU-5, AU-9
- CM-1, CM-6, CM-7
- IA-5(1)(c)
- SC-5, SC-10

### MODERATE Baseline (15 controls covered)
All LOW controls plus:
- AC-2(4), AC-10

### HIGH Baseline (15 controls covered)
All MODERATE controls (same as MODERATE)

**Coverage**: 75% LOW, 94% MODERATE, 94% HIGH

---

## See Also

- **Full NIST Mappings**: `NIST-MAPPINGS.md` - Comprehensive control descriptions and mappings
- **JSON Data**: `nist-800-53-mappings.json` - Machine-readable mapping data
- **Catalog**: `catalog.json` - Complete test inventory with NIST metadata
- **README**: `README.md` - Repository overview and usage guide

---

**Last Updated**: 2026-01-30  
**NIST SP 800-53 Version**: Revision 5
