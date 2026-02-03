# Data Models and Configuration Extraction Guide

## Overview

The compliance tests in this repository require structured configuration data in specific formats. This guide explains how to extract configuration data from network devices in the correct format for each extraction method and platform.

**Critical**: Tests will only work if the configuration data matches the expected data model structure. Use the API calls and examples below to ensure compatibility.

---

## Extraction Methods

### NSO (Network Services Orchestrator)

NSO provides YANG-modeled configuration data with consistent structure across vendors.

**Pros**:
- Standardized YANG data models
- Consistent structure across devices
- Rich metadata and relationships
- Supports YAML and JSON output

**Cons**:
- Requires NSO deployment
- Device must be managed by NSO

### Native (CLI/API)

Native extraction uses vendor-specific APIs or CLI parsing to get configuration data.

**Pros**:
- Direct device access (no NSO required)
- Real-time configuration data
- Works with any device

**Cons**:
- Vendor-specific data structures
- May require API enablement
- Different formats per vendor

---

## Cisco IOS-XE Router/Switch

### Method 1: NSO Extraction

**API Endpoint**: NSO RESTCONF  
**Data Format**: YANG-modeled JSON/YAML  
**Use Cases**: NSO-managed environments

#### API Call

```bash
curl --location 'http://<NSO_IP>:<NSO_PORT>/restconf/data/tailf-ncs:devices/device=<DEVICE_NAME>/config' \
  --header 'Accept: application/yang-data+json' \
  --header 'Content-Type: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>'
```

**Parameters**:
- `<NSO_IP>`: Your NSO server IP address
- `<NSO_PORT>`: NSO RESTCONF port (typically 8080 or custom port)
- `<DEVICE_NAME>`: Device hostname in NSO (e.g., HAI-HQ, ROUTER-01)
- `<BASE64_CREDENTIALS>`: Base64-encoded `username:password`

**Example**:
```bash
# Replace with your values
NSO_IP="10.0.0.1"
NSO_PORT="8080"
DEVICE_NAME="HAI-HQ"
NSO_USER="admin"
NSO_PASS="YourPassword"

# Encode credentials
AUTH=$(echo -n "${NSO_USER}:${NSO_PASS}" | base64)

# Extract configuration
curl --location "http://${NSO_IP}:${NSO_PORT}/restconf/data/tailf-ncs:devices/device=${DEVICE_NAME}/config" \
  --header 'Accept: application/yang-data+json' \
  --header 'Content-Type: application/yang-data+json' \
  --header "Authorization: Basic ${AUTH}" \
  --insecure \
  -o "${DEVICE_NAME}-nso-config.json"

# Or get as YAML
curl --location "http://${NSO_IP}:${NSO_PORT}/restconf/data/tailf-ncs:devices/device=${DEVICE_NAME}/config" \
  --header 'Accept: application/yang-data+yaml' \
  --header 'Content-Type: application/yang-data+json' \
  --header "Authorization: Basic ${AUTH}" \
  --insecure \
  -o "${DEVICE_NAME}-nso-config.yaml"
```

#### Data Structure (NSO)

```json
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-ios:hostname": "HAI-HQ",
    "tailf-ned-cisco-ios:service": {
      "password-encryption": {},
      "timestamps": {
        "log": {
          "datetime": {
            "localtime": {}
          }
        }
      }
    },
    "tailf-ned-cisco-ios:login": {
      "block-for": {
        "seconds": 900,
        "attempts": 3,
        "within": 120
      }
    },
    "tailf-ned-cisco-ios:ip": {
      "http": {
        "secure-server": {},
        "max-connections": 2
      },
      "ssh": {
        "server": {
          "algorithm": {
            "encryption": [
              "aes256-ctr",
              "aes192-ctr",
              "aes128-ctr"
            ],
            "mac": [
              "hmac-sha2-256",
              "hmac-sha2-512"
            ]
          }
        }
      }
    },
    "tailf-ned-cisco-ios:archive": {
      "log": {
        "config": {
          "logging": {
            "enable": {}
          }
        }
      }
    },
    "tailf-ned-cisco-ios:line": [
      {
        "name": "vty",
        "first": "0",
        "last": "1",
        "transport": {
          "input": {
            "protocol": {
              "ssh": {}
            }
          }
        },
        "exec-timeout": {
          "minutes": 10,
          "seconds": 0
        }
      }
    ]
  }
}
```

**Key Characteristics**:
- Root element: `tailf-ncs:config`
- Namespace prefixes: `tailf-ned-cisco-ios:`
- Configuration hierarchy follows YANG model
- Flags/enables represented as empty objects: `{}`
- Lists contain objects with keys

---

### Method 2: Native IOS-XE Extraction

**API Endpoint**: Device RESTCONF  
**Data Format**: Native YANG-modeled JSON  
**Use Cases**: Direct device access, no NSO

#### API Call

```bash
curl --location 'https://<DEVICE_IP>:<RESTCONF_PORT>/restconf/data/Cisco-IOS-XE-native:native' \
  --header 'Content-Type: application/yang-data+json' \
  --header 'Accept: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>' \
  --insecure
```

**Parameters**:
- `<DEVICE_IP>`: Device management IP address
- `<RESTCONF_PORT>`: RESTCONF port (typically 443)
- `<BASE64_CREDENTIALS>`: Base64-encoded `username:password`

**Example**:
```bash
# Replace with your values
DEVICE_IP="192.168.1.1"
DEVICE_USER="admin"
DEVICE_PASS="YourPassword"

# Encode credentials
AUTH=$(echo -n "${DEVICE_USER}:${DEVICE_PASS}" | base64)

# Extract configuration
curl --location "https://${DEVICE_IP}/restconf/data/Cisco-IOS-XE-native:native" \
  --header 'Content-Type: application/yang-data+json' \
  --header 'Accept: application/yang-data+json' \
  --header "Authorization: Basic ${AUTH}" \
  --insecure \
  -o "$(hostname)-native-config.json"
```

**Prerequisites**:
```
# Enable RESTCONF on IOS-XE device
Router(config)# restconf
Router(config)# ip http secure-server
Router(config)# ip http authentication local
```

#### Data Structure (Native IOS-XE)

```json
{
  "Cisco-IOS-XE-native:native": {
    "hostname": "HAI-HQ",
    "service": {
      "password-encryption": [null],
      "timestamps": {
        "log": {
          "datetime-localtime": [null]
        }
      }
    },
    "login": {
      "block-for": {
        "seconds": 900,
        "attempts-in": {
          "attempts": 3,
          "within": 120
        }
      }
    },
    "ip": {
      "http": {
        "secure-server": true,
        "max-connections": 2
      },
      "ssh": {
        "version": 2,
        "server": {
          "algorithm": {
            "encryption": [
              "aes256-ctr",
              "aes192-ctr",
              "aes128-ctr"
            ],
            "mac": [
              "hmac-sha2-256",
              "hmac-sha2-512"
            ]
          }
        }
      }
    },
    "archive": {
      "log": {
        "config": {
          "logging": {
            "enable": [null]
          }
        }
      }
    },
    "line": [
      {
        "vty": [
          {
            "first": 0,
            "last": 1,
            "transport": {
              "input": {
                "ssh": [null]
              }
            },
            "exec-timeout": {
              "timeout": 10
            }
          }
        ]
      }
    ]
  }
}
```

**Key Characteristics**:
- Root element: `Cisco-IOS-XE-native:native`
- Namespace: `Cisco-IOS-XE-native:`
- Similar structure to NSO but with vendor-specific variations
- Boolean flags as `[null]` or `true`
- Different key names in some places (e.g., `datetime-localtime` vs `datetime.localtime`)

**Note**: Our tests support both formats by detecting the structure and adapting accordingly.

---

## Cisco ASA Firewall

### Method 1: NSO Extraction

**API Endpoint**: NSO RESTCONF  
**Data Format**: YANG-modeled JSON/YAML  
**Use Cases**: NSO-managed ASA firewalls

#### API Call

```bash
curl --location 'http://<NSO_IP>:<NSO_PORT>/restconf/data/tailf-ncs:devices/device=<ASA_NAME>/config' \
  --header 'Accept: application/yang-data+json' \
  --header 'Content-Type: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>'
```

**Example**:
```bash
NSO_IP="10.0.0.1"
NSO_PORT="8080"
ASA_NAME="ASA-FW-01"
AUTH=$(echo -n "admin:password" | base64)

curl --location "http://${NSO_IP}:${NSO_PORT}/restconf/data/tailf-ncs:devices/device=${ASA_NAME}/config" \
  --header 'Accept: application/yang-data+json' \
  --header 'Content-Type: application/yang-data+json' \
  --header "Authorization: Basic ${AUTH}" \
  -o "${ASA_NAME}-nso-config.json"
```

#### Data Structure (NSO ASA)

```json
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-asa:logging": {
      "enable": {},
      "timestamp": {},
      "buffered": {
        "level": "informational"
      },
      "queue": 8192,
      "host": {
        "ipv4": {
          "host-id": "10.1.22.2",
          "protocol": "tcp",
          "port": 1514
        }
      },
      "permit-hostdown": {},
      "mail": "errors",
      "from-address": "firewall@example.mil",
      "recipient-address": [
        {
          "address": "admin@example.mil",
          "level": "errors"
        }
      ]
    },
    "tailf-ned-cisco-asa:access-list": {
      "extended": [
        {
          "id": "OUTSIDE_ACL",
          "rules": [
            {
              "rule-id": "1",
              "action": "deny",
              "protocol": "ip",
              "source": {
                "any": {}
              },
              "destination": {
                "any": {}
              },
              "log": {
                "level": "default"
              }
            }
          ]
        }
      ]
    },
    "tailf-ned-cisco-asa:threat-detection": {
      "basic-threat": {},
      "scanning-threat": {
        "shun": {}
      }
    },
    "tailf-ned-cisco-asa:service-policy": {
      "policy-map": "global_policy",
      "global": {}
    },
    "tailf-ned-cisco-asa:http": {
      "server": {
        "enable": {}
      }
    },
    "tailf-ned-cisco-asa:telnet": {
      "timeout": 10
    },
    "tailf-ned-cisco-asa:smtp-server": {
      "ipv4": "10.1.12.33"
    }
  }
}
```

**Key Characteristics**:
- Namespace: `tailf-ned-cisco-asa:`
- Configuration flags as empty objects: `{}`
- Lists with rule-id or name keys
- IPv4/IPv6 nested under protocol type
- Complex objects like ACLs have nested structures

---

## Juniper SRX Services Gateway

### Method 1: Native Extraction (REST API)

**API Endpoint**: Juniper REST API  
**Data Format**: Native Junos JSON  
**Use Cases**: Direct SRX access

#### API Call

```bash
curl --location 'http://<DEVICE_IP>:<API_PORT>/rpc/get-configuration' \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>'
```

**Parameters**:
- `<DEVICE_IP>`: SRX management IP address
- `<API_PORT>`: REST API port (default 3000, or custom)
- `<BASE64_CREDENTIALS>`: Base64-encoded `username:password`

**Example**:
```bash
# Replace with your values
DEVICE_IP="192.168.1.100"
API_PORT="3000"
DEVICE_USER="admin"
DEVICE_PASS="YourPassword"

# Encode credentials
AUTH=$(echo -n "${DEVICE_USER}:${DEVICE_PASS}" | base64)

# Extract configuration
curl --location "http://${DEVICE_IP}:${API_PORT}/rpc/get-configuration" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --header "Authorization: Basic ${AUTH}" \
  -o "srx-config.json"
```

**Prerequisites**:
```
# Enable REST API on Juniper SRX
[edit]
set system services rest http port 3000
set system services rest enable-explorer
commit
```

#### Data Structure (Native Juniper)

```json
{
  "configuration": {
    "@": {
      "junos:changed-seconds": "1770077458",
      "junos:changed-localtime": "2026-02-03 00:10:58 UTC"
    },
    "version": "23.2R2.21",
    "system": {
      "host-name": "SRX-Gateway-01",
      "root-authentication": {
        "encrypted-password": "$6$abc123..."
      },
      "login": {
        "retry-options": {
          "tries-before-disconnect": 3
        },
        "password": {
          "minimum-numerics": 1,
          "minimum-upper-cases": 1,
          "minimum-lower-cases": 1,
          "minimum-punctuations": 1,
          "format": "sha256"
        },
        "class": [
          {
            "name": "admin-class",
            "idle-timeout": 10,
            "permissions": ["all"]
          }
        ],
        "user": [
          {
            "name": "admin",
            "uid": 2004,
            "class": "admin-class",
            "authentication": {
              "encrypted-password": "$6$xyz789..."
            }
          }
        ]
      },
      "services": {
        "ssh": {
          "root-login": "deny",
          "no-tcp-forwarding": [null],
          "max-sessions-per-connection": 1,
          "macs": [
            "hmac-sha2-512",
            "hmac-sha2-256",
            "hmac-sha1",
            "hmac-sha1-96"
          ],
          "connection-limit": 10
        },
        "netconf": {
          "ssh": [null]
        }
      },
      "syslog": {
        "host": [
          {
            "name": "10.0.0.1",
            "contents": [
              {
                "name": "any",
                "info": [null]
              }
            ]
          }
        ]
      }
    },
    "security": {
      "screen": {
        "ids-option": [
          {
            "name": "untrust-screen",
            "tcp": {
              "syn-flood": {
                "alarm-threshold": 1024,
                "attack-threshold": 200
              }
            }
          }
        ]
      },
      "policies": {
        "policy": [
          {
            "from-zone-name": "trust",
            "to-zone-name": "untrust",
            "policy": [
              {
                "name": "allow-outbound",
                "match": {
                  "source-address": ["any"],
                  "destination-address": ["any"],
                  "application": ["any"]
                },
                "then": {
                  "permit": [null]
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

**Key Characteristics**:
- Root element: `configuration`
- Metadata in `@` attributes
- Configuration flags as `[null]` arrays
- Lists are arrays of objects
- No namespace prefixes (native Junos structure)
- Hierarchical structure: system → services → ssh

---

## Cisco NX-OS Switch

### Method 1: NSO Extraction

**API Endpoint**: NSO RESTCONF  
**Data Format**: YANG-modeled JSON

#### API Call

```bash
curl --location 'http://<NSO_IP>:<NSO_PORT>/restconf/data/tailf-ncs:devices/device=<NXOS_NAME>/config' \
  --header 'Accept: application/yang-data+json' \
  --header 'Content-Type: application/yang-data+json' \
  --header 'Authorization: Basic <BASE64_CREDENTIALS>'
```

#### Data Structure (NSO NX-OS)

```json
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-nx:hostname": "NEXUS-CORE-01",
    "tailf-ned-cisco-nx:feature": {
      "ssh": {},
      "nxapi": {}
    },
    "tailf-ned-cisco-nx:ssh": {
      "key": {
        "rsa": {
          "bits": 2048
        }
      }
    },
    "tailf-ned-cisco-nx:logging": {
      "server": [
        {
          "host": "10.0.0.1",
          "use-vrf": "management"
        }
      ],
      "timestamp": "microseconds"
    },
    "tailf-ned-cisco-nx:line": {
      "vty": {
        "exec-timeout": {
          "minutes": 10
        },
        "session-limit": 5
      }
    }
  }
}
```

**Key Characteristics**:
- Namespace: `tailf-ned-cisco-nx:`
- Similar structure to IOS-XE but NX-OS specific commands
- Features enabled via `feature` object

---

## Complete API Extraction Workflow

### Step 1: Identify Your Environment

**Determine**:
- Device vendor and platform
- Available extraction method (NSO vs Native)
- Authentication credentials
- Network connectivity to device/NSO

### Step 2: Enable Required Services

**For Native IOS-XE**:
```
Router(config)# restconf
Router(config)# ip http secure-server
Router(config)# ip http authentication local
```

**For Native Juniper SRX**:
```
[edit]
set system services rest http port 3000
set system services rest enable-explorer
commit
```

**For NSO**:
- Ensure device is onboarded and in sync
- Verify RESTCONF API is enabled on NSO

### Step 3: Extract Configuration

```bash
# Choose the appropriate API call from above
# Save output to JSON file
# Place in test-data/ directory
```

### Step 4: Run Tests

```bash
# Set TEST_INPUT_JSON to your extracted file
export TEST_INPUT_JSON="test-data/native/juniper-junos-router/srx-config.json"

# Run compliance tests
pytest stig/native/juniper-srx-gateway/*.py -v
```

### Step 5: Review Results

Tests will output:
- Pass/Fail status for each requirement
- Current configuration values
- Non-compliance details
- Remediation commands
- NIST control mappings

---

## Data Model Validation

### Verify Data Structure

Before running tests, validate your extracted configuration matches the expected structure:

```python
import json

# Load your extracted config
with open('your-config.json') as f:
    config = json.load(f)

# For NSO IOS-XE
if 'tailf-ncs:config' in config:
    print("✓ Valid NSO format")
    if 'tailf-ned-cisco-ios:hostname' in config['tailf-ncs:config']:
        print(f"✓ Hostname: {config['tailf-ncs:config']['tailf-ned-cisco-ios:hostname']}")

# For Native Juniper
if 'configuration' in config:
    print("✓ Valid Juniper native format")
    if 'system' in config['configuration']:
        hostname = config['configuration']['system'].get('host-name', 'N/A')
        print(f"✓ Hostname: {hostname}")

# For Native IOS-XE
if 'Cisco-IOS-XE-native:native' in config:
    print("✓ Valid IOS-XE native format")
    hostname = config['Cisco-IOS-XE-native:native'].get('hostname', 'N/A')
    print(f"✓ Hostname: {hostname}")
```

### Common Data Structure Issues

**Issue 1: Missing root element**
```json
// WRONG
{
  "hostname": "ROUTER-01",
  "service": {...}
}

// CORRECT (NSO)
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-ios:hostname": "ROUTER-01",
    "tailf-ned-cisco-ios:service": {...}
  }
}
```

**Issue 2: Incorrect namespace**
```json
// WRONG
{
  "config": {
    "hostname": "ROUTER-01"
  }
}

// CORRECT (NSO)
{
  "tailf-ncs:config": {
    "tailf-ned-cisco-ios:hostname": "ROUTER-01"
  }
}
```

**Issue 3: String instead of structured data**
```json
// WRONG
{
  "configuration": "show configuration | display json"
}

// CORRECT
{
  "configuration": {
    "system": {...}
  }
}
```

---

## Troubleshooting

### Authentication Issues

**Problem**: 401 Unauthorized

**Solutions**:
```bash
# Verify credentials are correct
echo "<YOUR_BASE64_AUTH>" | base64 -d
# Should output: username:password

# Re-encode with correct credentials
echo -n "username:password" | base64
```

### Connection Issues

**Problem**: Connection refused or timeout

**Solutions**:
- Verify device IP address is reachable: `ping <DEVICE_IP>`
- Check port is correct and open: `nc -zv <DEVICE_IP> <PORT>`
- Verify firewall rules allow access
- For HTTPS, try with `--insecure` flag to bypass certificate validation

### API Not Enabled

**Problem**: 404 Not Found or API endpoint doesn't exist

**Solutions**:
- Enable RESTCONF/REST API on device (see prerequisites above)
- Verify API is listening: `show ip http server status` (IOS-XE)
- Check Juniper REST: `show system services | match rest`
- Restart services after enabling

### Data Format Issues

**Problem**: Tests fail with KeyError or AttributeError

**Solutions**:
- Validate JSON structure: `python3 -m json.tool config.json`
- Check root element matches expected format
- Verify namespaces are present (NSO) or absent (Native)
- Compare against sample files in `test-data/`

### Empty or Partial Configuration

**Problem**: Configuration is missing expected sections

**Solutions**:
- For NSO: Ensure device is in sync: `devices device <name> sync-from`
- For Native: Check device configuration is complete
- Verify API user has read permissions
- Some features may not appear if not configured (this is normal)

---

## Best Practices

### Security

1. **Never commit credentials**: Keep authentication tokens and passwords out of git
2. **Use environment variables**: Store credentials in env vars, not scripts
3. **Restrict API access**: Limit API to management network only
4. **Use HTTPS**: Always use HTTPS for production (use `--insecure` only for testing)
5. **Rotate credentials**: Change API passwords regularly

### Data Management

1. **Organize by extraction method**: Keep NSO and Native configs separate
2. **Use descriptive filenames**: `<hostname>-<method>-config.json`
3. **Include metadata**: Document when config was extracted
4. **Version control structure only**: Keep actual configs in gitignored `test-data/`
5. **YAML for NSO**: Use YAML format for NSO configs (more readable)

### Testing Workflow

```bash
# 1. Extract configuration
curl ... -o test-data/native/juniper-srx-gateway/prod-srx-01.json

# 2. Run tests
TEST_INPUT_JSON="test-data/native/juniper-srx-gateway/prod-srx-01.json" \
  pytest stig/native/juniper-srx-gateway/*.py -v

# 3. Generate report
TEST_INPUT_JSON="test-data/native/juniper-srx-gateway/prod-srx-01.json" \
  pytest stig/native/juniper-srx-gateway/*.py \
  --html=reports/prod-srx-01-stig-report.html --self-contained-html

# 4. Review and remediate
# Use remediation commands from test output
```

---

## Quick Reference Table

| Platform | Extraction Method | API Endpoint | Data Root Element | Namespace Prefix |
|----------|------------------|--------------|-------------------|------------------|
| IOS-XE Router | NSO | `/devices/device=<name>/config` | `tailf-ncs:config` | `tailf-ned-cisco-ios:` |
| IOS-XE Router | Native | `/restconf/data/Cisco-IOS-XE-native:native` | `Cisco-IOS-XE-native:native` | None |
| ASA Firewall | NSO | `/devices/device=<name>/config` | `tailf-ncs:config` | `tailf-ned-cisco-asa:` |
| NX-OS Switch | NSO | `/devices/device=<name>/config` | `tailf-ncs:config` | `tailf-ned-cisco-nx:` |
| Juniper SRX | Native | `/rpc/get-configuration` | `configuration` | None |

---

## Example: Complete Extraction and Testing

### Scenario: Test Juniper SRX for STIG Compliance

```bash
#!/bin/bash
# juniper-srx-compliance-check.sh

# Configuration
DEVICE_IP="192.168.100.50"
DEVICE_USER="compliance-user"
DEVICE_PASS="SecurePassword123"
OUTPUT_DIR="test-data/native/juniper-srx-gateway"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Encode credentials
AUTH=$(echo -n "${DEVICE_USER}:${DEVICE_PASS}" | base64)

# Extract configuration
echo "Extracting configuration from ${DEVICE_IP}..."
curl --location "http://${DEVICE_IP}:3000/rpc/get-configuration" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json' \
  --header "Authorization: Basic ${AUTH}" \
  --silent \
  -o "${OUTPUT_DIR}/srx-gateway-config.json"

# Verify extraction
if [ $? -eq 0 ]; then
    echo "✓ Configuration extracted successfully"
    
    # Validate JSON
    python3 -m json.tool "${OUTPUT_DIR}/srx-gateway-config.json" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ JSON is valid"
    else
        echo "✗ JSON is invalid"
        exit 1
    fi
else
    echo "✗ Configuration extraction failed"
    exit 1
fi

# Run STIG tests
echo "Running STIG compliance tests..."
export TEST_INPUT_JSON="${OUTPUT_DIR}/srx-gateway-config.json"

pytest stig/native/juniper-srx-gateway/*.py \
  -v \
  --html=reports/srx-gateway-stig-report.html \
  --self-contained-html

# Summary
echo ""
echo "Compliance testing complete!"
echo "Report: reports/srx-gateway-stig-report.html"
```

---

## Sample Configurations

All sample configurations are available in the `test-data/` directory:

```
test-data/
├── nso/
│   ├── cisco-ios-xe-router/
│   │   └── sample-cat8000v.yaml          # NSO IOS-XE sample
│   ├── cisco-asa-firewall/
│   │   └── sample-asa.json               # NSO ASA sample
│   └── cisco-nxos-switch/
│       └── nso-nexus-sample.json         # NSO NX-OS sample
└── native/
    ├── cisco-ios-xe-router/
    │   ├── sample_cat8000v_native.json   # Native IOS-XE sample
    │   └── sample_cat8000v_cli.txt       # Raw CLI output
    └── juniper-junos-router/
        └── vsrx-sample.json              # Native Juniper sample
```

Use these samples as templates for understanding the expected data structure.

---

## Support and Issues

### Data Model Questions

If you're unsure about the data model structure:

1. **Check sample files**: Review `test-data/` for examples
2. **Examine test code**: Look at the `load_test_data()` and test logic
3. **Validate extraction**: Use `python3 -m json.tool` to validate JSON
4. **Compare structures**: Match your config against samples

### API Access Issues

**Common Problems**:
- API not enabled on device
- Incorrect credentials
- Network connectivity issues
- Firewall blocking access
- Certificate validation errors (use `--insecure` for testing)

**Debugging Steps**:
```bash
# Test connectivity
ping <DEVICE_IP>
nc -zv <DEVICE_IP> <API_PORT>

# Test authentication
curl -v http://<DEVICE_IP>:<PORT>/... --header "Authorization: Basic <AUTH>"

# Check JSON validity
python3 -m json.tool your-config.json
```

---

## Advanced: Converting CLI to Structured Data

If you only have CLI output and need to convert to structured format:

### Option 1: Use NSO

```bash
# Onboard device to NSO
ncs_cli -C -u admin
devices device <name> address <ip>
devices device <name> device-type cli ned-id cisco-iosxe-cli
devices device <name> sync-from

# Extract via RESTCONF (structured output)
curl http://nso-server/restconf/data/tailf-ncs:devices/device=<name>/config
```

### Option 2: Use Vendor APIs

Most modern network devices support RESTCONF/NETCONF for structured output:
- Cisco IOS-XE 16.9+: RESTCONF
- Juniper Junos: REST API, NETCONF
- Cisco NX-OS: NX-API

### Option 3: Parsing Tools (Not Recommended)

Tools like TextFSM or pyATS Genie can parse CLI, but:
- Structure may not match test expectations
- Requires custom parsers
- Less reliable than native APIs
- Additional maintenance burden

**Recommendation**: Use native APIs or NSO for structured data extraction.

---

## Summary

**To use these tests successfully**:

1. **Extract configuration** using appropriate API call for your platform/method
2. **Verify structure** matches expected data model (compare to samples)
3. **Save to test-data** directory (gitignored)
4. **Set TEST_INPUT_JSON** environment variable
5. **Run tests** with pytest
6. **Review results** and remediate findings

**Key Success Factors**:
- Use correct API endpoint for platform
- Ensure proper authentication
- Validate JSON structure before testing
- Match extraction method to test type (NSO tests need NSO data, Native tests need Native data)

---

**For questions or issues with data models, consult the sample configurations in `test-data/` or examine the test code directly.**
