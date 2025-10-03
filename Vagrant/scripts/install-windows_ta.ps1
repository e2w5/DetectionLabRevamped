# Purpose: Installs the Windows Splunk Technial Add-On
# Note: This only needs to be installed on the WEF server

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing the Windows TA for Splunk"

If (Test-Path "C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\default") {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Windows TA is already installed. Moving on."
  Exit 0
}

# Install Windows TA (this only needs to be done on the WEF server)
Copy-Item -Path "C:\vagrant\resources\splunk_forwarder\splunk-add-on-for-microsoft-windows_700.tgz" -Destination $env:temp
$windowstaPath = $env:temp + "\splunk-add-on-for-microsoft-windows_700.tgz"
$inputsPath = "C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\local\inputs.conf"

# Ensure Splunk CLI allows local login with default credentials and set a non-default admin password
$serverConfPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\server.conf"
$serverConfDir = Split-Path $serverConfPath
New-Item -ItemType Directory -Force -Path $serverConfDir | Out-Null
$serverConfContent = @()
if (Test-Path $serverConfPath) {
  $serverConfContent = Get-Content $serverConfPath
} else {
  $serverConfContent = @()
}
$hasGeneral = $serverConfContent -match '^\s*\[general\]\s*$'
if (-not $hasGeneral) {
  $serverConfContent = @('[general]') + $serverConfContent
}
$serverConfContent = $serverConfContent | Where-Object { $_ -notmatch '^\s*allowRemoteLogin\s*=.*$' }
$serverConfContent += 'allowRemoteLogin = always'
$serverConfContent | Set-Content -Path $serverConfPath

$SplunkBin = "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
$NewAdminPassword = 'Vagrant!2022'

# Ensure Splunk service is running and new configuration is picked up
& $SplunkBin stop | Out-Null 2>$null
& $SplunkBin start --accept-license --answer-yes --no-prompt 2>$null | Out-Null
$maxTries = 30
for ($i = 0; $i -lt $maxTries; $i++) {
  $status = & $SplunkBin status 2>$null
  if ($LASTEXITCODE -eq 0) { break }
  Start-Sleep -Seconds 2
}
try {
  & $SplunkBin edit user admin -password $NewAdminPassword -roles admin -auth admin:changeme -ErrorAction Stop 2>$null | Out-Null
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Updated Splunk admin password."
} catch {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Splunk admin password already set."
}
Start-Sleep -Seconds 2
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing the Windows TA"
$appsDir = "C:\Program Files\SplunkUniversalForwarder\etc\apps"
$targetDir = Join-Path $appsDir 'Splunk_TA_windows'
$extractDir = Join-Path $env:TEMP 'splunk_ta_extract'
Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $extractDir | Out-Null
try {
  & tar -xf $windowstaPath -C $extractDir
} catch {
  throw ("Failed to extract {0}: {1}" -f $windowstaPath, $_.Exception.Message)
}
$extracted = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
if (-not $extracted) {
  throw "Unable to locate extracted Splunk TA directory"
}
Remove-Item -Path $targetDir -Recurse -Force -ErrorAction SilentlyContinue
Move-Item -Path $extracted.FullName -Destination $targetDir
Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue

# Create local directory
New-Item -ItemType Directory -Force -Path (Join-Path $targetDir 'local')
Copy-Item c:\vagrant\resources\splunk_forwarder\wef_inputs.conf $inputsPath -Force

# Add a check here to make sure the TA was installed correctly
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Sleeping for 15 seconds"
Start-Sleep -s 15
If (Test-Path "C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\default") {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Windows TA installed successfully."
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Something went wrong during installation."
  exit 1
}

