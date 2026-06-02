#Requires -Version 5.1

<#
.SYNOPSIS
    Tests network connectivity and HTTPS validation for specified endpoints
.DESCRIPTION
    This script tests connectivity to AWS S3, CyberArk Cloud, and AWS IoT endpoints
    while detecting potential packet inspection, encryption, or termination by third parties.
    Enhanced with proper service-level validation for all endpoint types.
.PARAMETER ConfigPath
    Path to the JSON configuration file (default: config.json)
.PARAMETER LogPath
    Path to the log file (default: endpoint_test.log)
.EXAMPLE
    .\NetworkCheck.ps1
.EXAMPLE
    .\NetworkCheck.ps1 -ConfigPath "custom-config.json" -LogPath "custom.log"
#>

param(
    [string]$ConfigPath = "config.json",
    [string]$LogPath = "endpoint_test.log"
)

# Function to write to log and console
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with color coding
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "PASS"  { Write-Host $logEntry -ForegroundColor Green }
        "FAIL"  { Write-Host $logEntry -ForegroundColor Red }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry
}

# Function to test TCP connectivity
function Test-TCPConnection {
    param(
        [string]$Hostname,
        [int]$Port,
        [int]$TimeoutMs = 5000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)
        $timeoutTask = [System.Threading.Tasks.Task]::Delay($TimeoutMs)
        
        $completedTask = [System.Threading.Tasks.Task]::WaitAny(@($connectTask, $timeoutTask))
        
        if ($completedTask -eq 0 -and $connectTask.IsCompletedSuccessfully) {
            $tcpClient.Close()
            return $true
        } else {
            $tcpClient.Close()
            return $false
        }
    }
    catch {
        return $false
    }
}

# Function to test actual HTTPS connectivity with service validation
function Test-HTTPSConnectivity {
    param(
        [string]$Hostname,
        [string]$EndpointType = "Generic",
        [int]$TimeoutSeconds = 15
    )
    
    $result = @{
        HTTPSConnectivity = $false
        SSLHandshake = $false
        ServiceReachable = $false
        StatusCode = $null
        FailureReason = ""
        ResponseDetails = ""
    }
    
    # Step 1: Test SSL/TLS handshake
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $TimeoutSeconds * 1000
        $tcpClient.SendTimeout = $TimeoutSeconds * 1000
        $tcpClient.Connect($Hostname, 443)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
        $sslStream.ReadTimeout = $TimeoutSeconds * 1000
        $sslStream.WriteTimeout = $TimeoutSeconds * 1000
        
        $sslStream.AuthenticateAsClient($Hostname)
        $result.SSLHandshake = $true
        Write-LogMessage "SSL handshake successful for $Hostname" "INFO"
        
        $sslStream.Close()
        $tcpClient.Close()
    }
    catch {
        $result.FailureReason = "SSL handshake failed: $($_.Exception.Message)"
        Write-LogMessage "SSL handshake failed for $Hostname`: $($_.Exception.Message)" "WARN"
        return $result
    }
    
    # Step 2: Test actual HTTPS request
    try {
        $webRequest = [System.Net.WebRequest]::Create("https://$Hostname")
        $webRequest.Timeout = $TimeoutSeconds * 1000
        $webRequest.UserAgent = "SIA-Network-Check/1.0"
        
        # Configure SSL/TLS settings
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        
        # Set appropriate HTTP method based on endpoint type
        switch ($EndpointType) {
            "S3" { 
                $webRequest.Method = "HEAD"  # S3 supports HEAD requests
            }
            "CyberArk" { 
                $webRequest.Method = "GET"   # CyberArk endpoints expect GET
            }
            "IoT" { 
                $webRequest.Method = "GET"   # IoT endpoints expect GET
            }
            "IPCheck" {
                $webRequest.Method = "GET"   # Public-IP reporting services answer to GET
            }
            default { 
                $webRequest.Method = "HEAD"  # Default to HEAD for minimal impact
            }
        }
        
        try {
            $response = $webRequest.GetResponse()
            $result.HTTPSConnectivity = $true
            $result.StatusCode = $response.StatusCode
            $result.ResponseDetails = "HTTP Status: $($response.StatusCode)"

            # Connectivity check: receiving ANY well-formed HTTP response means the
            # endpoint was reached end-to-end through an intact TLS tunnel. The exact
            # status code (200/403/404/405) reflects auth/method/path, not reachability.
            # TLS/MITM interception is detected separately in Test-PacketInspection.
            $result.ServiceReachable = $true
            Write-LogMessage "$EndpointType endpoint reachable: $Hostname (Status: $($response.StatusCode))" "PASS"

            $response.Close()
        }
        catch [System.Net.WebException] {
            $webResponse = $_.Exception.Response
            if ($webResponse) {
                # We received an HTTP response (even a 4xx/5xx), so the service was
                # reached end-to-end. 403/404/405 are normal for unauthenticated,
                # method-restricted, or root-path probes (e.g. HEAD https://s3.amazonaws.com
                # returns 405; a GET against an IoT ATS root returns 404).
                $statusCode = $webResponse.StatusCode
                $statusNumber = [int]$webResponse.StatusCode
                $result.HTTPSConnectivity = $true
                $result.StatusCode = $statusCode
                $result.ResponseDetails = "HTTP Status: $statusCode ($statusNumber)"
                $result.ServiceReachable = $true

                if ($statusNumber -ge 500) {
                    # Reachable, but a 5xx can indicate a broken upstream proxy/gateway.
                    Write-LogMessage "$EndpointType endpoint reachable but returned server error: $Hostname (Status: $statusCode)" "WARN"
                } else {
                    Write-LogMessage "$EndpointType endpoint reachable: $Hostname (Status: $statusCode - expected for probe)" "PASS"
                }

                $webResponse.Close()
            }
            else {
                # No response object => genuine connectivity failure
                # (DNS failure, connection reset, blocked by firewall/proxy, or timeout).
                $result.FailureReason = "HTTPS request failed (no response received): $($_.Exception.Message)"
                Write-LogMessage "HTTPS request failed for $Hostname`: $($_.Exception.Message)" "FAIL"
            }
        }
    }
    catch {
        $result.FailureReason = "HTTPS connectivity test failed: $($_.Exception.Message)"
        Write-LogMessage "HTTPS connectivity test failed for $Hostname`: $($_.Exception.Message)" "FAIL"
    }
    
    return $result
}

# Function to detect packet inspection through multiple methods
function Test-PacketInspection {
    param(
        [string]$Hostname,
        [int]$Port = 443
    )
    
    $inspectionResult = @{
        CertificateReplacement = $false
        SuspiciousHeaders = $false
        TLSFingerprint = $false
        NetworkInterception = $false
        InspectionTool = "None"
        Details = @()
    }
    
    try {
        # Method 1: Certificate Analysis - Check for corporate/proxy certificates
        Write-LogMessage "Analyzing SSL certificate for $Hostname" "INFO"
        $certInfo = Get-SSLCertificate -Hostname $Hostname
        
        if ($certInfo) {
            # Known corporate/NGFW certificate authorities and patterns
            $corporateCAs = @(
                "BlueCoat", "Zscaler", "Forcepoint", "McAfee", "Symantec Web Security",
                "Corporate", "Proxy", "Firewall", "Gateway", "Palo Alto", "Fortinet",
                "SonicWall", "Check Point", "Cisco", "Barracuda", "WatchGuard",
                "Sophos", "Trend Micro", "Websense", "ContentKeeper", "Lightspeed"
            )
            
            foreach ($ca in $corporateCAs) {
                if ($certInfo.Issuer -match $ca -or $certInfo.Subject -match $ca) {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.InspectionTool = $ca
                    $inspectionResult.Details += "Certificate issued by: $($certInfo.Issuer)"
                    Write-LogMessage "DETECTION: Certificate replacement by $ca detected" "WARN"
                    break
                }
            }
            
            # Check for non-standard certificate chains that might indicate interception
            if ($Hostname -match "amazonaws\.com") {
                $expectedIssuers = @("Amazon", "DigiCert", "Symantec", "VeriSign", "GlobalSign")
                $validIssuer = $false
                foreach ($issuer in $expectedIssuers) {
                    if ($certInfo.Issuer -match $issuer) {
                        $validIssuer = $true
                        break
                    }
                }
                if (-not $validIssuer) {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.Details += "Non-AWS certificate for AWS endpoint: $($certInfo.Issuer)"
                }
            }
            elseif ($Hostname -match "cyberark\.cloud") {
                if ($certInfo.Subject -notmatch "cyberark\.cloud" -and $certInfo.Subject -notmatch "\*\.cyberark\.cloud") {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.Details += "Non-CyberArk certificate for CyberArk endpoint"
                }
            }
        }
        
        # Method 2: HTTP Header Analysis - Check for inspection tool headers
        Write-LogMessage "Analyzing HTTP headers for $Hostname" "INFO"
        try {
            $headers = @{}
            $webRequest = [System.Net.WebRequest]::Create("https://$Hostname")
            $webRequest.Method = "HEAD"
            $webRequest.Timeout = 10000
            
            # Allow certificate errors for header analysis
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            
            try {
                $response = $webRequest.GetResponse()
                $headers = $response.Headers
                $response.Close()
            }
            catch {
                # Even if request fails, we might get headers in the exception
                if ($_.Exception.Response) {
                    $headers = $_.Exception.Response.Headers
                }
            }
            
            # Vendor-branded headers: these are injected by inspection/proxy products
            # specifically when they are in the path, so they are reliable signals.
            $inspectionHeaders = @{
                "X-Zscaler-" = "Zscaler"
                "X-BlueCoat-" = "BlueCoat"
                "X-Forcepoint-" = "Forcepoint"
                "X-McAfee-" = "McAfee"
                "X-Sophos-" = "Sophos"
                "X-Fortinet-" = "Fortinet"
                "X-SonicWall-" = "SonicWall"
                "X-Palo-Alto-" = "Palo Alto"
                "X-Check-Point-" = "Check Point"
                "X-Websense-" = "Websense"
                "X-Cisco-" = "Cisco"
            }

            # Generic intermediary headers: standard HTTP headers added by ANY forward/
            # reverse proxy, load balancer, or CDN (e.g. CloudFront, ipinfo.io's frontend).
            # Their presence indicates an intermediary at the HTTP layer but does NOT mean
            # the TLS tunnel was decrypted. TLS interception is caught by the certificate
            # check above (issuer = a corporate/NGFW CA). We log these for visibility only.
            $informationalHeaders = @{
                "X-Proxy-" = "Generic Proxy"
                "X-Forwarded-" = "Proxy/Load Balancer"
                "Via" = "Proxy/CDN"
            }
            
            foreach ($header in $headers.AllKeys) {
                foreach ($pattern in $inspectionHeaders.Keys) {
                    if ($header -match $pattern) {
                        $inspectionResult.SuspiciousHeaders = $true
                        $inspectionResult.NetworkInterception = $true
                        $inspectionResult.InspectionTool = $inspectionHeaders[$pattern]
                        $inspectionResult.Details += "Inspection-tool header detected: $header"
                        Write-LogMessage "DETECTION: Inspection tool header found: $header" "WARN"
                    }
                }
                foreach ($pattern in $informationalHeaders.Keys) {
                    if ($header -match $pattern) {
                        # Intermediary present (CDN/proxy/LB) but NOT treated as interception.
                        Write-LogMessage "Intermediary header present (informational, not flagged): $header [$($informationalHeaders[$pattern])]" "INFO"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Header analysis failed for $Hostname`: $($_.Exception.Message)" "INFO"
        }
        
        # Method 3: TLS Handshake Analysis - Check for modified TLS patterns
        Write-LogMessage "Analyzing TLS handshake for $Hostname" "INFO"
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($Hostname, $Port)
            
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
            
            # Capture TLS negotiation details
            $startTime = Get-Date
            $sslStream.AuthenticateAsClient($Hostname)
            $handshakeTime = (Get-Date) - $startTime
            
            # Check for unusually long handshake times (possible inspection)
            if ($handshakeTime.TotalMilliseconds -gt 2000) {
                $inspectionResult.TLSFingerprint = $true
                $inspectionResult.NetworkInterception = $true
                $inspectionResult.Details += "Unusually long TLS handshake: $($handshakeTime.TotalMilliseconds)ms"
                Write-LogMessage "DETECTION: Slow TLS handshake suggests inspection" "WARN"
            }
            
            # Check TLS version and cipher suite
            $tlsVersion = $sslStream.SslProtocol
            Write-LogMessage "TLS Protocol: $tlsVersion" "INFO"
            
            $sslStream.Close()
            $tcpClient.Close()
        }
        catch {
            Write-LogMessage "TLS analysis failed for $Hostname`: $($_.Exception.Message)" "INFO"
        }
        
        # Method 4: Network Path Analysis - Multiple connection attempts
        Write-LogMessage "Performing network path analysis for $Hostname" "INFO"
        $connectionTimes = @()
        
        for ($i = 1; $i -le 3; $i++) {
            try {
                $startTime = Get-Date
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($Hostname, $Port)
                $connectionTime = (Get-Date) - $startTime
                $connectionTimes += $connectionTime.TotalMilliseconds
                $tcpClient.Close()
                Start-Sleep -Milliseconds 100
            }
            catch {
                Write-LogMessage "Connection attempt $i failed for $Hostname" "INFO"
            }
        }
        
        if ($connectionTimes.Count -gt 0) {
            $avgConnectionTime = ($connectionTimes | Measure-Object -Average).Average
            $maxConnectionTime = ($connectionTimes | Measure-Object -Maximum).Maximum
            
            # Check for inconsistent connection times (possible inspection)
            if ($maxConnectionTime - ($connectionTimes | Measure-Object -Minimum).Minimum -gt 500) {
                $inspectionResult.NetworkInterception = $true
                $inspectionResult.Details += "Inconsistent connection times suggest network inspection"
                Write-LogMessage "DETECTION: Inconsistent connection times" "WARN"
            }
            
            Write-LogMessage "Average connection time: $([math]::Round($avgConnectionTime, 2))ms" "INFO"
        }
        
    }
    catch {
        Write-LogMessage "Packet inspection analysis failed for $Hostname`: $($_.Exception.Message)" "WARN"
    }
    finally {
        # Reset certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
    
    return $inspectionResult
}

# Function to get SSL certificate information
function Get-SSLCertificate {
    param(
        [string]$Hostname,
        [int]$Port = 443
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Hostname, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
        $sslStream.AuthenticateAsClient($Hostname)
        
        $cert = $sslStream.RemoteCertificate
        $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
        
        $sslStream.Close()
        $tcpClient.Close()
        
        return @{
            Subject = $x509Cert.Subject
            Issuer = $x509Cert.Issuer
            Thumbprint = $x509Cert.Thumbprint
            NotBefore = $x509Cert.NotBefore
            NotAfter = $x509Cert.NotAfter
            HasPrivateKey = $x509Cert.HasPrivateKey
        }
    }
    catch {
        return $null
    }
}

# Function to determine endpoint type based on hostname
function Get-EndpointType {
    param([string]$Hostname)
    
    if ($Hostname -match '^(api\.ipify\.org|ipinfo\.io|api\.my-ip\.io)$') {
        return "IPCheck"
    }
    elseif ($Hostname -match '\.iot\..+\.amazonaws\.com$') {
        return "IoT"
    }
    elseif ($Hostname -match 's3.*\.amazonaws\.com$') {
        return "S3"
    }
    elseif ($Hostname -match '\.cyberark\.cloud$') {
        return "CyberArk"
    }
    else {
        return "Generic"
    }
}

# Enhanced function to test endpoint with proper service-level validation
function Test-NetworkEndpoint {
    param(
        [string]$Url
    )
    
    $hostname = ([System.Uri]$Url).Host
    $endpointType = Get-EndpointType -Hostname $hostname
    
    $result = @{
        Endpoint = $Url
        EndpointType = $endpointType
        TCPConnectivity = $false
        HTTPSConnectivity = $false
        SSLHandshake = $false
        ServiceReachable = $false
        PacketInspectionDetected = $false
        InspectionTool = "None"
        Status = "FAIL"
        FailureReason = ""
        StatusCode = $null
        InspectionDetails = @()
    }
    
    Write-LogMessage "Testing $endpointType endpoint: $Url" "INFO"
    
    # Step 1: Test TCP connectivity
    try {
        $tcpTest = Test-NetConnection -ComputerName $hostname -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        $result.TCPConnectivity = $tcpTest
    }
    catch {
        # Fallback to custom TCP test
        $result.TCPConnectivity = Test-TCPConnection -Hostname $hostname -Port 443
    }
    
    if (-not $result.TCPConnectivity) {
        $result.FailureReason = "TCP port 443 not reachable"
        Write-LogMessage "TCP connectivity failed for $hostname" "FAIL"
        return $result
    }
    
    Write-LogMessage "TCP connectivity successful for $hostname" "PASS"
    
    # Step 2: Test HTTPS connectivity with service validation
    $httpsResult = Test-HTTPSConnectivity -Hostname $hostname -EndpointType $endpointType
    $result.HTTPSConnectivity = $httpsResult.HTTPSConnectivity
    $result.SSLHandshake = $httpsResult.SSLHandshake
    $result.ServiceReachable = $httpsResult.ServiceReachable
    $result.StatusCode = $httpsResult.StatusCode
    
    if (-not $result.SSLHandshake) {
        $result.FailureReason = $httpsResult.FailureReason
        Write-LogMessage "SSL handshake failed for $hostname" "FAIL"
        return $result
    }
    
    if (-not $result.ServiceReachable) {
        if ($httpsResult.FailureReason) {
            $result.FailureReason = $httpsResult.FailureReason
        } else {
            $result.FailureReason = "Service not responding correctly (Status: $($httpsResult.StatusCode))"
        }
        Write-LogMessage "Service validation failed for $hostname" "FAIL"
        return $result
    }
    
    # Step 3: Perform packet inspection detection
    $inspectionResult = Test-PacketInspection -Hostname $hostname
    
    if ($inspectionResult.NetworkInterception) {
        $result.PacketInspectionDetected = $true
        $result.InspectionTool = $inspectionResult.InspectionTool
        $result.InspectionDetails = $inspectionResult.Details
        $result.Status = "FAIL"
        $result.FailureReason = "Network packet inspection detected by $($inspectionResult.InspectionTool)"
        Write-LogMessage "PACKET INSPECTION DETECTED for $hostname by $($inspectionResult.InspectionTool)" "FAIL"
    } else {
        $result.Status = "PASS"
        Write-LogMessage "No packet inspection detected for $hostname" "PASS"
    }
    
    return $result
}

# Main script execution
try {
    Write-LogMessage "Starting enhanced endpoint connectivity tests" "INFO"
    Write-LogMessage "Log file: $LogPath" "INFO"
    
    # Load configuration
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }
    
    $config = Get-Content $ConfigPath | ConvertFrom-Json
    Write-LogMessage "Configuration loaded from $ConfigPath" "INFO"
    Write-LogMessage "Tenant Name: $($config.tenant_name)" "INFO"
    Write-LogMessage "AWS Region: $($config.aws_region)" "INFO"
    
    $region = $config.aws_region
    $tenant = $config.tenant_name

    $endpoints = New-Object System.Collections.Generic.List[string]

    # General S3 reachability sanity checks
    $endpoints.Add("https://s3.amazonaws.com")
    $endpoints.Add("https://s3.$region.amazonaws.com")

    if ($config.include_sia -eq $true) {
        # ----- SIA (Secure Infrastructure Access) connector outbound -----
        $endpoints.Add("https://$tenant.cyberark.cloud")                            # SIA backend / shared services
        $endpoints.Add("https://$tenant.dpa.cyberark.cloud")                        # SIA (DPA) backend
        if ($region -eq 'us-east-1') {
            $endpoints.Add("https://cms-assets-bucket-445444212982.s3.$region.amazonaws.com")          # SIA connector binaries (us-east-1)
        } else {
            $endpoints.Add("https://cms-assets-bucket-445444212982-$region.s3.$region.amazonaws.com")  # SIA connector binaries (other regions)
        }
        $endpoints.Add("https://a2m4b3cupk8nzj-ats.iot.$region.amazonaws.com")      # SIA IoT broker (session events)
    }

    if ($config.include_connector_management -eq $true) {
        # ----- Connector Management agent outbound -----
        $endpoints.Add("https://$tenant.connectormanagement.cyberark.cloud")                                        # CM REST APIs
        if ($region -eq 'me-central-1') {                                                                           # CM install files/logs for UAE region
            $endpoints.Add("https://connector-management-scripts-490081306957-$region.s3.$region.amazonaws.com")
            $endpoints.Add("https://connector-management-assets-490081306957-$region.s3.$region.amazonaws.com")
        } else {                                                                                                    # CM install files/logs for all other regions
            $endpoints.Add("https://connector-management-scripts-490081306957-$region.s3.amazonaws.com")  
            $endpoints.Add("https://connector-management-assets-490081306957-$region.s3.amazonaws.com")   
        }

        $endpoints.Add("https://component-registry-store-490081306957.s3.amazonaws.com")              # CM component registry (always us-east-1)
        $endpoints.Add("https://a3vvqcp8z371p3-ats.iot.$region.amazonaws.com")                        # CM IoT broker target
        # Public-IP reporting - MUST be excluded from SSL inspection, or Secure Zone
        # allowlist validation can fail.
        $endpoints.Add("https://api.ipify.org")
        $endpoints.Add("https://ipinfo.io")
        $endpoints.Add("https://api.my-ip.io")
    }

    $endpoints = $endpoints.ToArray()
    
    # Test all endpoints
    $results = @()
    foreach ($endpoint in $endpoints) {
        $testResult = Test-NetworkEndpoint -Url $endpoint
        $results += $testResult
        Start-Sleep -Milliseconds 500  # Brief pause between tests
    }
    
    # Display results table
    Write-Host "`n" -NoNewline
    Write-LogMessage "=== NETWORK ENDPOINT TEST RESULTS ===" "INFO"
    
    $tableData = $results | Select-Object @{
        Name = "Endpoint"
        Expression = { $_.Endpoint }
    }, @{
        Name = "Type"
        Expression = { $_.EndpointType }
    }, @{
        Name = "Status" 
        Expression = { $_.Status }
    }, @{
        Name = "TCP"
        Expression = { if ($_.TCPConnectivity) { "Pass" } else { "Fail" } }
    }, @{
        Name = "SSL"
        Expression = { if ($_.SSLHandshake) { "Pass" } else { "Fail" } }
    }, @{
        Name = "Service"
        Expression = { if ($_.ServiceReachable) { "Pass" } else { "Fail" } }
    }, @{
        Name = "PacketInspection"
        Expression = { if ($_.PacketInspectionDetected) { "DETECTED" } else { "None" } }
    }, @{
        Name = "InspectionTool"
        Expression = { $_.InspectionTool }
    }
    
    $tableData | Format-Table -AutoSize
    
    # Detailed failure information
    $failedEndpoints = @($results | Where-Object { $_.Status -eq "FAIL" })
    if ($failedEndpoints.Count -gt 0) {
        Write-LogMessage "=== FAILURE DETAILS ===" "INFO"
        foreach ($failed in $failedEndpoints) {
            Write-LogMessage "Endpoint: $($failed.Endpoint)" "ERROR"
            Write-LogMessage "  Reason: $($failed.FailureReason)" "ERROR"
            if ($failed.StatusCode) {
                Write-LogMessage "  HTTP Status: $($failed.StatusCode)" "ERROR"
            }
            if (@($failed.InspectionDetails).Count -gt 0) {
                Write-LogMessage "  Inspection Details:" "ERROR"
                foreach ($detail in $failed.InspectionDetails) {
                    Write-LogMessage "    - $detail" "ERROR"
                }
            }
        }
    }
    
    # Summary
    $passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $inspectionCount = @($results | Where-Object { $_.PacketInspectionDetected -eq $true }).Count
    
    Write-LogMessage "=== SUMMARY ===" "INFO"
    Write-LogMessage "Total Endpoints: $($results.Count)" "INFO"
    Write-LogMessage "Passed: $passCount" "INFO"
    Write-LogMessage "Failed: $failCount" "INFO"
    Write-LogMessage "Packet Inspection Detected: $inspectionCount" "INFO"
    
    if ($inspectionCount -gt 0) {
        Write-LogMessage "WARNING: Network packet inspection detected on $inspectionCount endpoint(s)" "WARN"
        Write-LogMessage "Your network traffic may be monitored by corporate security tools" "WARN"
    }
    
    if ($failCount -gt 0) {
        Write-LogMessage "Some endpoints failed validation. Check logs for details." "WARN"
        exit 1
    } else {
        Write-LogMessage "All endpoints passed connectivity tests with no packet inspection detected." "PASS"
        exit 0
    }
}
catch {
    Write-LogMessage "Script execution failed: $($_.Exception.Message)" "ERROR"
    Write-LogMessage $_.ScriptStackTrace "ERROR"
    exit 1
}