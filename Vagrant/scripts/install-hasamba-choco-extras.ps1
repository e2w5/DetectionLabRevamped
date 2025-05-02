# Purpose: Install additional packages from Chocolatey.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Hasamba additional Choco packages..."

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey"
  iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Chocolatey is already installed."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey extras..."
choco install -y --limit-output --no-progress vscode
choco install -y --limit-output --no-progress totalcommander --ignore-dependencies
choco install -y --limit-output --no-progress nirlauncher
choco install -y --limit-output --no-progress 7zip
choco install -y --limit-output --no-progress sharex
choco install -y --limit-output --no-progress everything
choco install -y --limit-output --no-progress gsudo
choco install -y --limit-output --no-progress ericzimmermantools

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Choco addons complete!"
