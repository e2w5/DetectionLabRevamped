# Purpose: Install additional packages from Chocolatey.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing additional Choco packages..."

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey"
  iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Chocolatey is already installed."
}

# Ensure WinRM allows long-running provisioning tasks (e.g. large Chocolatey installs)
$desiredMaxTimeout = 3600000
$winrmTimeoutPath = 'WSMan:\localhost\Service\MaxTimeoutms'
try {
  $currentTimeout = [int](Get-Item -LiteralPath $winrmTimeoutPath -ErrorAction Stop).Value
  if ($currentTimeout -lt $desiredMaxTimeout) {
    Set-Item -LiteralPath $winrmTimeoutPath -Value $desiredMaxTimeout -ErrorAction Stop
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Increased WinRM MaxTimeoutms to $desiredMaxTimeout"
  }
} catch {
  Write-Warning "Failed to adjust WinRM MaxTimeoutms: $($_.Exception.Message)"
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey extras..."
choco install -y --limit-output --no-progress --execution-timeout=5400 wireshark
choco install -y --limit-output --no-progress --execution-timeout=5400 --version "1.1.36.02" autohotkey.portable

cd choco-winpcap
choco pack WinPcap.nuspec
choco install -y --limit-output --no-progress --execution-timeout=5400 winpcap --source .

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Choco addons complete!"
