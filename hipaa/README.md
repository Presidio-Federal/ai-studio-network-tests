# HIPAA Compliance Tests for Cisco IOS-XE

## Overview

This directory contains pytest-based validation tests for HIPAA (Health Insurance Portability and Accountability Act) Security Rule compliance on Cisco IOS-XE network devices. These tests validate technical safeguards required under 45 CFR Part 164, Subpart C.

## Test Structure

Tests are organized by extraction method:
- **`native/`**: Tests using native CLI/API JSON output
- **`nso/`**: Tests using NSO (Network Services Orchestrator) YANG models

## Implemented Tests

### Access Control (§ 164.312(a))

| Test ID | Rule Title | Severity | Status | Files |
|---------|-----------|----------|--------|-------|
| **HIPAA-AC-001** | Unique User Identification | High | ✅ Complete | native-HIPAA-AC-001.py<br>nso-HIPAA-AC-001.py |
| **HIPAA-AC-003** | Automatic Logoff | Medium | ✅ Complete | native-HIPAA-AC-003.py<br>nso-HIPAA-AC-003.py |
| **HIPAA-AC-004** | Encryption and Decryption | High | ⏳ Planned | - |

### Audit Controls (§ 164.312(b))

| Test ID | Rule Title | Severity | Status | Files |
|---------|-----------|----------|--------|-------|
| **HIPAA-AU-001** | Audit Logging Enabled | High | ⏳ Planned | - |
| **HIPAA-AU-003** | Centralized Logging | High | ⏳ Planned | - |
| **HIPAA-AU-004** | Failed Login Attempts | Medium | ⏳ Planned | - |

### Integrity (§ 164.312(c))

| Test ID | Rule Title | Severity | Status | Files |
|---------|-----------|----------|--------|-------|
| **HIPAA-IN-001** | Configuration Change Control | High | ⏳ Planned | - |

### Person or Entity Authentication (§ 164.312(d))

| Test ID | Rule Title | Severity | Status | Files |
|---------|-----------|----------|--------|-------|
| **HIPAA-PA-002** | Password Complexity | High | ⏳ Planned | - |
| **HIPAA-PA-004** | Account Lockout | High | ✅ Complete | native-HIPAA-PA-004.py<br>nso-HIPAA-PA-004.py |

### Transmission Security (§ 164.312(e))

| Test ID | Rule Title | Severity | Status | Files |
|---------|-----------|----------|--------|-------|
| **HIPAA-TS-001** | Encryption in Transit | High | ⏳ Planned | - |
| **HIPAA-TS-002** | Strong Cryptography | High | ⏳ Planned | - |
| **HIPAA-TS-003** | Secure Protocol Versions | High | ⏳ Planned | - |

## Test Details

### HIPAA-AC-001: Unique User Identification
**Reference:** 45 CFR § 164.312(a)(2)(i)  
**NIST Mapping:** AC-2, IA-2

Verifies that:
- Individual user accounts are configured (no shared accounts)
- Multiple user accounts exist (minimum 2)
- No suspicious shared account names (admin, operator, team, etc.)

**Sample Configuration:**
```
username john.doe privilege 15 secret 9 <hash>
username jane.smith privilege 10 secret 9 <hash>
```

---

### HIPAA-AC-003: Automatic Logoff
**Reference:** 45 CFR § 164.312(a)(2)(iii)  
**NIST Mapping:** AC-11, AC-12

Verifies that:
- Exec-timeout is configured on all lines (console, VTY, AUX)
- Timeout is ≤ 15 minutes
- Timeout is not disabled (not set to 0 0)

**Sample Configuration:**
```
line console 0
  exec-timeout 15 0
line vty 0 15
  exec-timeout 15 0
```

---

### HIPAA-PA-004: Account Lockout
**Reference:** 45 CFR § 164.312(a)(2)(i), § 164.312(d)  
**NIST Mapping:** AC-7

Verifies that:
- Login block-for is configured
- Failed attempts threshold ≤ 5
- Block duration ≥ 300 seconds (5 minutes)
- Failed login logging is enabled

**Sample Configuration:**
```
login block-for 900 attempts 3 within 120
login on-failure log
login on-success log
```

## Running Tests

### Prerequisites

```bash
pip install -r requirements.txt
```

### Running Individual Tests

```bash
# Set the test data file
export TEST_INPUT_JSON=/path/to/device/config.json

# Run a specific test
pytest hipaa/native/cisco-ios-xe-router/native-HIPAA-AC-001.py -v

# Run all HIPAA native tests
pytest hipaa/native/cisco-ios-xe-router/ -v

# Run all HIPAA NSO tests
pytest hipaa/nso/cisco-ios-xe-router/ -v
```

### Running with Custom Test Data

```bash
TEST_INPUT_JSON=./test-data/nso/cisco-ios-xe-switch/sample_compliant_switch.json \
  pytest hipaa/nso/cisco-ios-xe-router/nso-HIPAA-AC-001.py -v
```

### Test Output Format

Tests provide detailed compliance reports:

```
HIPAA Compliance Summary:
HIPAA ID: HIPAA-AC-001
Rule: Unique User Identification
Reference: 45 CFR § 164.312(a)(2)(i)
Severity: High
Extraction Method: native

Device Results:
HAI-HQ: PASS
  ✓ 2 individual user accounts configured
  ✓ Users: admin, cisco
  ✓ No suspicious shared accounts detected
  ✓ HIPAA unique user identification requirement satisfied
```

## Test Data Format

### Native Format
Tests expect JSON data in NSO format with `tailf-ncs:config` root element:

```json
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-ios:hostname": "router-01",
    "tailf-ned-cisco-ios:username": [
      {
        "name": "admin",
        "privilege": 15,
        "secret": {
          "type": "9",
          "secret": "$9$hash..."
        }
      }
    ]
  }
}
```

### NSO Format
Identical to native format - tests use the same data model structure.

## Test Development Status

**Completed:** 3 tests (6 files total - native + NSO)
- HIPAA-AC-001 ✅
- HIPAA-AC-003 ✅  
- HIPAA-PA-004 ✅

**Planned:** 9 additional tests (18 files)
- See "Implemented Tests" table above

## References

- **HIPAA Security Rule:** 45 CFR Part 164, Subpart C
- **NIST SP 800-53 Rev 5:** Security and Privacy Controls
- **NIST SP 800-66:** HIPAA Security Rule Implementation Guide
- **HHS HIPAA Security Series:** Technical Safeguards (Vol 2, Paper 4)

## Contributing

When adding new HIPAA tests:

1. Follow the existing test structure (see HIPAA-AC-001 as template)
2. Include comprehensive docstrings with:
   - HIPAA regulatory reference
   - NIST SP 800-53 mapping
   - Discussion of requirement
   - Check text and fix text
3. Create both `native-HIPAA-XX-YYY.py` and `nso-HIPAA-XX-YYY.py` versions
4. Update this README with test details
5. Include sample configurations in docstrings

## License

Internal use - HAI Compliance Testing Team

---

**Last Updated:** February 3, 2026  
**Version:** 1.0  
**Maintainer:** HAI Compliance Testing Team
