# Purpose: Installs a Splunk Universal Forwader on the host

If (-not (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe")) {
  $defaultVersion = '10.0.0'
  $defaultBuild = 'e8eb0c4654f8'
  $defaultUrl = "https://download.splunk.com/products/universalforwarder/releases/$defaultVersion/windows/splunkforwarder-$defaultVersion-$defaultBuild-windows-x64.msi"

  $downloadUrl = if ([string]::IsNullOrWhiteSpace($env:SPLUNK_UF_DOWNLOAD_URL)) { $defaultUrl } else { $env:SPLUNK_UF_DOWNLOAD_URL }
  $installerName = Split-Path -Path $downloadUrl -Leaf
  $msiFile = Join-Path -Path $env:TEMP -ChildPath $installerName

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Splunk Universal Forwarder from $downloadUrl..."
  [Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  if (Test-Path $msiFile) { Remove-Item -Path $msiFile -Force }
  (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $msiFile)

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing & Starting Splunk Universal Forwarder ($installerName)..."
  Start-Process -FilePath "c:\windows\system32\msiexec.exe" -ArgumentList '/i', "$msiFile", 'RECEIVING_INDEXER="192.168.57.105:9997" WINEVENTLOG_SEC_ENABLE=0 WINEVENTLOG_SYS_ENABLE=0 WINEVENTLOG_APP_ENABLE=0 AGREETOLICENSE=Yes SERVICESTARTTYPE=AUTO LAUNCHSPLUNK=1 SPLUNKPASSWORD=changeme /quiet' -Wait
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Splunk Universal Forwarder is already installed. Moving on."
}


$ufRoot = 'C:\Program Files\SplunkUniversalForwarder'
$needsRestart = $false

$inputsDir = Join-Path $ufRoot 'etc\system\local'
if (-not (Test-Path $inputsDir)) {
  Write-Host ("[{0:HH:mm}] Creating Splunk UF local inputs directory {1}" -f (Get-Date), $inputsDir)
  New-Item -Path $inputsDir -ItemType Directory -Force | Out-Null
}

$inputsFile = Join-Path $inputsDir 'inputs.conf'
$sysmonStanza = @"
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
renderXml = true
disabled = 0
"@

if (Test-Path $inputsFile) {
  $currentContent = Get-Content -Path $inputsFile -Raw
  if ($currentContent -notmatch '\[WinEventLog://Microsoft-Windows-Sysmon/Operational\]') {
    Write-Host ("[{0:HH:mm}] Adding Sysmon WinEventLog stanza to inputs.conf" -f (Get-Date))
    Add-Content -Path $inputsFile -Value "`r`n$sysmonStanza"
    $needsRestart = $true
  }
} else {
  Write-Host ("[{0:HH:mm}] Creating inputs.conf with Sysmon WinEventLog stanza" -f (Get-Date))
  $sysmonStanza | Out-File -FilePath $inputsFile -Encoding ASCII
  $needsRestart = $true
}

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
$eventLogGroup = 'Event Log Readers'
$serviceAccount = 'NT SERVICE\SplunkForwarder'
try {
  if (-not (Get-LocalGroupMember -Group $eventLogGroup -Member $serviceAccount -ErrorAction SilentlyContinue)) {
    Write-Host ("[{0:HH:mm}] Granting $serviceAccount rights to read event logs" -f (Get-Date))
    Add-LocalGroupMember -Group $eventLogGroup -Member $serviceAccount -ErrorAction Stop
    $needsRestart = $true
  }
} catch {
  Write-Warning "Unable to add $serviceAccount to $eventLogGroup: $($_.Exception.Message)"
}

if ($needsRestart -and (Get-Service -Name splunkforwarder -ErrorAction SilentlyContinue)) {
  Write-Host ("[{0:HH:mm}] Restarting Splunk Universal Forwarder to apply configuration" -f (Get-Date))
  Restart-Service splunkforwarder -Force
  Start-Sleep -Seconds 5
}

$service = Get-Service -Name splunkforwarder -ErrorAction SilentlyContinue
if (-not $service) {
  throw 'Splunk forwarder service not found'
}
if ($service.Status -ne 'Running') {
  Write-Host ("[{0:HH:mm}] Starting Splunk Universal Forwarder service" -f (Get-Date))
  Start-Service splunkforwarder
  Start-Sleep -Seconds 5
  $service = Get-Service -Name splunkforwarder
  if ($service.Status -ne 'Running') {
    throw 'Splunk forwarder service not running'
  }
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Splunk installation complete!"
