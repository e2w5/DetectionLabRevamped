function download {
    param(
      [Parameter(Mandatory)][string]$URL,
      [string]$PatternToMatch,
      [switch]$SuccessOn401,
      [int]$Retries = 3,
      [int]$TimeoutSec = 10
    )

    # Prefer TLS 1.2 and ignore self-signed certs
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}

    # Extract host/port and preflight the TCP port
    try {
        $uri = [Uri]$URL
        $TargetPort = if ($uri.Port -gt 0) { $uri.Port } elseif ($uri.Scheme -eq 'https') { 443 } else { 80 }
        $TargetHost = $uri.Host
    } catch {
        Write-Host "Invalid URL: $URL" -ForegroundColor Red
        return $false
    }

    $attempt = 0
    while ($attempt -lt $Retries) {
        $attempt++

        # Quick connectivity check to reduce misleading SSL errors
        try {
            $tcp = Test-NetConnection -ComputerName $TargetHost -Port $TargetPort -WarningAction SilentlyContinue -InformationLevel Quiet
            if (-not $tcp) {
                Write-Host "Connection check failed to $TargetHost`:$TargetPort (attempt $attempt/$Retries)" -ForegroundColor Yellow
                Start-Sleep -Seconds 3
                continue
            }
        } catch {
            Write-Host "Connection test error to $TargetHost`:$TargetPort (attempt $attempt/$Retries): $($_.Exception.Message)" -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            continue
        }

        # Use Invoke-WebRequest with timeout; ServicePointManager overrides cert validation in Windows PowerShell
        try {
            $iwrParams = @{ Uri = $URL; Method = 'GET'; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
            $cmd = Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
            if ($cmd) {
                if ($cmd.Parameters.ContainsKey('SkipCertificateCheck')) { $iwrParams['SkipCertificateCheck'] = $true }
                if ($cmd.Parameters.ContainsKey('UseBasicParsing')) { $iwrParams['UseBasicParsing'] = $true }
            }

            $resp = Invoke-WebRequest @iwrParams

            if ($SuccessOn401.IsPresent -and $resp.StatusCode -eq 401) { return $true }

            if ($PatternToMatch) {
                if ($resp.Content -like "*$PatternToMatch*") { return $true } else { return $false }
            } else {
                return $true
            }
        }
        catch {
            # Some servers return 401 with an exception path in PS 5.1
            $statusCode = $null
            try { $statusCode = $_.Exception.Response.StatusCode.Value__ } catch {}
            if ($SuccessOn401.IsPresent -and $statusCode -eq 401) { return $true }

            Write-Host "Error occured on webrequest (attempt $attempt/$Retries): $($_.Exception.Message)" -ForegroundColor red
            Start-Sleep -Seconds 3
        }
    }
    return $false
}

function post_build_checks {
    $checkmark = ([char]8730)

    if ((Get-NetAdapter | where {$_.name -eq "VMware Network Adapter VMnet2"}).ifIndex) {
      Write-Host '[*] Verifying vmnet2 interface has its IP address set correctly'
      $vmnet2idx=(Get-NetAdapter | where {$_.name -eq "VMware Network Adapter VMnet2"}).ifIndex
      if ((get-netipaddress -AddressFamily IPv4 | where { $_.InterfaceIndex -eq $vmnet2idx }).IPAddress -ne "192.168.57.1") {
        Write-Host '[!] Your vmnet2 network adapter is not set with a static IP address of 192.168.57.1' -ForegroundColor red
        Write-Host '[!] Please match your adapter settings to the screenshot shown here: https://github.com/clong/DetectionLab/issues/681#issuecomment-890442441' -ForegroundColor red
      }
      Else {
        Write-Host '  ['$($checkmark)'] VMNet2 is correctly set to 192.168.57.1!' -ForegroundColor Green
      }
    }

    Write-Host '[*] Verifying that Splunk is reachable...'
    $SPLUNK_CHECK = download -URL 'https://192.168.57.105:8000/en-US/account/login?return_to=%2Fen-US%2F' -PatternToMatch 'This browser is not supported by Splunk'
    if ($SPLUNK_CHECK -eq $false) {
        Write-Host '[!] Splunk was unreachable and may not have installed correctly.' -ForegroundColor red
    }
    else {
        Write-Host '  ['$($checkmark)'] Splunk is running and reachable!' -ForegroundColor Green
    }
    Write-Host ''

    Write-Host '[*] Verifying that Fleet is reachable...'
    # Accept success on HTTP 200/redirects or 401 (unauthenticated login page)
    $FLEET_CHECK = download -URL 'https://192.168.57.105:8412' -SuccessOn401
    if ($FLEET_CHECK -eq $false) {
        Write-Host '[!] Fleet was unreachable and may not have installed correctly.' -ForegroundColor red
    }
    else {
        Write-Host '  ['$($checkmark)'] Fleet is running and reachable!' -ForegroundColor Green
    }
    Write-Host ''

    Write-Host '[*] Verifying that Velociraptor is reachable...'
    $VELOCIRAPTOR_CHECK = download -URL 'https://192.168.57.105:9999' -SuccessOn401 -Retries 10 -TimeoutSec 10
    if ($VELOCIRAPTOR_CHECK -eq $false) {
        Write-Host '[!] Velociraptor was unreachable and may not have installed correctly.' -ForegroundColor red
    }
    else {
        Write-Host '  ['$($checkmark)'] Velociraptor is running and reachable!' -ForegroundColor Green
    }
    Write-Host ''

    Write-Host '[*] Verifying that Guacamole is reachable...'
    # Use canonical URL without trailing slash; accept any 200 OK
    $GUACAMOLE_CHECK = download -URL 'http://192.168.57.105:8080/guacamole/' -Retries 10 -TimeoutSec 10
    if ($GUACAMOLE_CHECK -eq $false) {
        Write-Host '[!] Guacamole was unreachable and may not have installed correctly.' -ForegroundColor red
    }
    else {
        Write-Host '  ['$($checkmark)'] Guacamole is running and reachable!' -ForegroundColor Green
    }
    Write-Host ''
}

post_build_checks
