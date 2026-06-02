# CyberArk Secure Infrastructure Access (SIA) Network Connectivity Checker

This repository contains network connectivity validation tools for the CyberArk SaaS platform, ensuring proper network configuration according to CyberArk Secure Infrastructure Access documentation. The tools test connectivity to required endpoints and detect potential issues with packet inspection, SSL termination, or other network security tools that may interfere with CyberArk SIA functionality.

## Available Versions

- **Windows PowerShell**: `NetworkCheck.ps1` - For Windows environments
- **Linux Python**: `network_check.py` - For Linux environments (RHEL, Ubuntu, Amazon Linux)

## What It Does

Both scripts perform comprehensive network validation for CyberArk SaaS connectivity by:

- **Testing TCP Connectivity**: Validates that required ports (443) are accessible to CyberArk endpoints
- **Detecting Packet Inspection**: Identifies corporate firewalls, proxy servers, or network security tools that may interfere with encrypted communication
- **SSL Certificate Analysis**: Checks for certificate replacement or manipulation by network security devices
- **Network Path Validation**: Analyzes connection patterns to detect potential traffic interception
- **Compliance Verification**: Ensures network configuration aligns with CyberArk SIA requirements

### Tested Endpoints

The script validates connectivity to the following CyberArk and AWS services:

1. **AWS S3 Global**: `https://s3.amazonaws.com`
2. **AWS S3 Regional**: `https://s3.[region].amazonaws.com`
3. **CyberArk Tenant**: `https://[tenant-name].cyberark.cloud`
4. **SIA IoT Broker**: `https://a2m4b3cupk8nzj-ats.iot.[region].amazonaws.com`
5. **SIA Deployment Assets**: `https://cms-assets-bucket-445444212982.s3.[region].amazonaws.com` or `https://cms-assets-bucket-445444212982-[region].s3.[region].amazonaws.com`
6. **SIA Backend**: `https://[tenant-name].dpa.cyberark.cloud`
7. **Connector Management Backend**: `https://[tennant-name].connectormanagement.cyberark.cloud`
8. **Connector Management Deployment Assets**: `https://connector-management-scripts-490081306957-[region].s3.amazonaws.com` and `https://connector-management-assets-490081306957-[region].s3.amazonaws.com`
8.1. **Connector Management Deployment Assets** (UAE Region): `https://connector-management-scripts-490081306957-[region].s3.[region].amazonaws.com` and `https://connector-management-assets-490081306957-[region].s3.[region].amazonaws.com`
9. **Connector Management Component Registry**: `https://component-registry-store-490081306957.s3.amazonaws.com`
10. **IP Resolution Services**: `https://api.ipify.org`, `https://ipinfo.io`, `https://api.my-ip.io`


### Packet Inspection Detection

Both scripts employ multiple detection methods to identify network interference:

- **Certificate Authority Analysis**: Detects corporate/proxy certificates from known security vendors
- **HTTP Header Inspection**: Identifies headers injected by network security tools
- **TLS Handshake Timing**: Analyzes connection patterns for inspection indicators
- **Connection Consistency**: Tests for network path manipulation

Supported detection for these network security tools:
- Zscaler
- BlueCoat/Symantec
- Forcepoint
- McAfee Web Gateway
- Palo Alto Networks
- Fortinet
- SonicWall
- Check Point
- Cisco
- Sophos
- And many others

## Prerequisites

### Windows (PowerShell)
- **PowerShell 5.1 or higher**
- **Network connectivity** to internet endpoints
- **Regular user privileges** (no admin rights required)

### Linux (Python)
- **Python 3.6 or higher**
- **Required Python packages**:
  - `requests` 
  - `urllib3`
- **Network connectivity** to internet endpoints
- **Regular user privileges** (no sudo required)

#### Installing Python Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3-requests python3-urllib3
```

**RHEL/CentOS/Amazon Linux:**
```bash
sudo yum install python3-requests python3-urllib3
# Or on newer versions:
sudo dnf install python3-requests python3-urllib3
```

**Using pip:**
```bash
pip3 install requests
# urllib3 is included with requests
```

The Python script will automatically check for missing dependencies and provide installation instructions if any are missing.

## Configuration

### config.json Setup

Before running the script, configure the `config.json` file with your CyberArk environment details:

```json
{
    "tenant_name": "your-tenant-name",
    "aws_region": "us-east-1",
    "include_sia": true,
    "include_connector_management": true
}
```

#### Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `tenant_name` | Your CyberArk SaaS tenant name (the subdomain in your CyberArk URL) | `"mycompany"` for `mycompany.cyberark.cloud` |
| `aws_region` | AWS region where your CyberArk SaaS tenant is hosted | `"us-east-1"`, `"eu-west-1"`, `"ap-southeast-2"` |
| `include_sia` | Whether to test SIA endpoints | `true`, `false` |
| `include_connector_management` | Whether to test Connector Management endpoints | `true`, `false` |


#### Finding Your Configuration Values

**Tenant Name:**
- Look at your CyberArk login URL: `https://[TENANT-NAME].cyberark.cloud`
- The tenant name is the subdomain before `.cyberark.cloud`

**AWS Region:**
- This is typically provided by CyberArk during tenant provisioning
- Common regions: `us-east-1` (N. Virginia), `us-west-2` (Oregon), `eu-west-1` (Ireland)
- Contact your CyberArk administrator if unsure

## Usage

### Windows PowerShell

#### Basic Usage

```powershell
.\NetworkCheck.ps1
```

#### Advanced Usage

```powershell
# Use custom configuration file
.\NetworkCheck.ps1 -ConfigPath "production-config.json"

# Specify custom log file location
.\NetworkCheck.ps1 -LogPath "C:\Logs\cyberark-connectivity.log"

# Use both custom config and log paths
.\NetworkCheck.ps1 -ConfigPath "prod-config.json" -LogPath "prod-test.log"
```

### Linux Python

#### Basic Usage

```bash
python3 network_check.py
```

#### Advanced Usage

```bash
# Use custom configuration file
python3 network_check.py --config production-config.json

# Specify custom log file location  
python3 network_check.py --log /var/log/cyberark-connectivity.log

# Use both custom config and log paths
python3 network_check.py -c prod-config.json -l prod-test.log

# Make executable and run directly
chmod +x network_check.py
./network_check.py
```

### Parameters

#### PowerShell Parameters
| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `-ConfigPath` | Path to JSON configuration file | `config.json` | No |
| `-LogPath` | Path to output log file | `endpoint_test.log` | No |

#### Python Parameters  
| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `--config`, `-c` | Path to JSON configuration file | `config.json` | No |
| `--log`, `-l` | Path to output log file | `endpoint_test.log` | No |


## Output and Results

### Console Output

Both scripts provide real-time feedback with color-coded messages:
- 🟢 **Green**: Successful connections and passed tests
- 🟡 **Yellow**: Warnings and detected issues
- 🔴 **Red**: Failures and critical problems
- ⚪ **White**: Informational messages

### Dependency Check (Python Only)

The Python script will automatically check for required dependencies on startup:

```
ERROR: Missing required Python packages
Missing packages: requests

Ubuntu/Debian:
  sudo apt-get install python3-requests

RHEL/CentOS/Amazon Linux:
  sudo yum install python3-requests

Using pip:
  pip3 install requests
```

### Results Table

After testing, both scripts display a comprehensive results table:

```
Endpoint                                                                     Type     Status TCP  SSL  Service PacketInspection InspectionTool
--------                                                                     ----     ------ ---  ---  ------- ---------------- --------------
https://s3.amazonaws.com                                                     S3       PASS   Pass Pass Pass    None             None
https://s3.us-east-1.amazonaws.com                                           S3       PASS   Pass Pass Pass    None             None
https://mycompany.cyberark.cloud                                             CyberArk PASS   Pass Pass Pass    None             None
https://mycompany.dpa.cyberark.cloud                                         CyberArk PASS   Pass Pass Pass    None             None
https://cms-assets-bucket-445444212982.s3.us-east-1.amazonaws.com            S3       PASS   Pass Pass Pass    None             None
https://a2m4b3cupk8nzj-ats.iot.us-east-1.amazonaws.com                       IoT      PASS   Pass Pass Pass    None             None
https://mycompany.connectormanagement.cyberark.cloud                         CyberArk PASS   Pass Pass Pass    None             None
https://connector-management-scripts-490081306957-us-east-1.s3.amazonaws.com S3       PASS   Pass Pass Pass    None             None
https://connector-management-assets-490081306957-us-east-1.s3.amazonaws.com  S3       PASS   Pass Pass Pass    None             None
https://component-registry-store-490081306957.s3.amazonaws.com               S3       PASS   Pass Pass Pass    None             None
https://a3vvqcp8z371p3-ats.iot.us-east-1.amazonaws.com                       IoT      PASS   Pass Pass Pass    None             None
https://api.ipify.org                                                        IPCheck  PASS   Pass Pass Pass    None             None
https://ipinfo.io                                                            IPCheck  PASS   Pass Pass Pass    None             None
https://api.my-ip.io                                                         IPCheck  PASS   Pass Pass Pass    None             None
```

### Log File

All test results are logged to the specified log file with timestamps for audit and troubleshooting purposes.

## Interpreting Results

### Success Indicators
- ✅ **Status: PASS** - Endpoint is reachable with no interference detected
- ✅ **TCP: Pass** - Port 443 is accessible
- ✅ **PacketInspection: None** - No network interference detected

### Failure Indicators
- ❌ **Status: FAIL** - Connectivity or security issue detected
- ❌ **TCP: Fail** - Port 443 is blocked or unreachable
- ❌ **PacketInspection: DETECTED** - Network security tool interference found

### Common Issues and Solutions

#### Port Blocking
**Symptom**: `TCP: Fail`
**Solution**: Work with network administrators to open port 443 for the listed endpoints

#### Packet Inspection Detection
**Symptom**: `PacketInspection: DETECTED`
**Solution**: Configure network security tools to bypass inspection for CyberArk endpoints

#### Certificate Replacement
**Symptom**: Certificate-related warnings in logs
**Solution**: Add CyberArk domains to security tool bypass lists

## Troubleshooting

### Common Error Messages

1. **"Configuration file not found"**
   - Ensure `config.json` exists in the script directory
   - Verify the path if using custom config parameter

2. **"TCP port 443 not reachable"**
   - Check firewall rules
   - Verify internet connectivity
   - Confirm DNS resolution for endpoints

3. **"Network packet inspection detected"**
   - Review corporate security policies
   - Configure security tools to bypass CyberArk traffic
   - Consult with network security team

4. **"Missing required Python packages" (Linux only)**
   - Install missing packages using provided commands
   - Ensure Python 3.6+ is installed
   - Check package manager repositories are accessible

### Debug Mode

For additional troubleshooting information, examine the log file for detailed connection attempts and error messages.

### Platform-Specific Notes

**Windows PowerShell:**
- Uses native .NET networking classes for SSL/TLS analysis
- Requires Windows PowerShell 5.1+ or PowerShell Core
- May require execution policy adjustment: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

**Linux Python:**
- Uses Python's `ssl`, `socket`, and `requests` libraries
- Automatically disables SSL warnings for inspection analysis
- Compatible with Python 3.6+ on most Linux distributions
- Can be run as a regular user (no sudo required)

## Security Considerations

- Both scripts do not transmit sensitive data
- All tests use standard HTTPS connectivity checks
- Certificate information is analyzed locally
- No authentication credentials are required or stored
- Scripts can be run with regular user privileges (no admin rights required for either version)

## Support

For CyberArk SIA-specific network requirements, consult:
- CyberArk Secure Infrastructure Access documentation
- CyberArk Support Portal
- Your organization's CyberArk administrator

## Exit Codes

Both scripts use the same exit codes:
- **0**: All tests passed successfully
- **1**: One or more tests failed or packet inspection detected

## Version Requirements

**Windows PowerShell:**
- PowerShell 5.1+ (specified in script header)
- Windows PowerShell or PowerShell Core
- .NET Framework (for SSL/TLS operations)

**Linux Python:**
- Python 3.6 or higher
- Standard library modules: `ssl`, `socket`, `json`, `logging`, `urllib.parse`
- Third-party packages: `requests`, `urllib3`

## File Structure

```
cyberark-sia-checker/
├── README.md
├── config.json
├── NetworkCheck.ps1          # Windows PowerShell version
└── network_check.py           # Linux Python version
```

---

*These scripts are designed to validate CyberArk SaaS connectivity requirements across Windows and Linux environments. Ensure you have appropriate permissions to run network tests in your environment.*