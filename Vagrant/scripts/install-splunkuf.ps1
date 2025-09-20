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

If ((Get-Service -name splunkforwarder).Status -ne "Running") {
  throw "Splunk forwarder service not running"
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Splunk installation complete!"
