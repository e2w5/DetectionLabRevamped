# Purpose: Installs chocolatey package manager, then installs custom utilities from Choco.

# First check if .NET Framework 4.8 is already installed
$netKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
if ($netKey -and $netKey.Release -ge 528040) {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) .NET Framework 4.8 is already installed."
} else {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing .NET Framework 4.8..."
    # Download and install .NET Framework 4.8 directly
    $netInstallerUrl = "https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe"
    $netInstallerPath = "$env:TEMP\ndp48-x86-x64-allos-enu.exe"
    
    (New-Object Net.WebClient).DownloadFile($netInstallerUrl, $netInstallerPath)
    Start-Process -FilePath $netInstallerPath -ArgumentList "/quiet /norestart" -Wait
    
    # Verify installation
    $netKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ($netKey -and $netKey.Release -ge 528040) {
        Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) .NET Framework 4.8 installed successfully."
    } else {
        Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) WARNING: .NET Framework 4.8 installation could not be verified."
    }
}

If (-not (Test-Path "C:\ProgramData\chocolatey")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Chocolatey"
  
  # Use the official Chocolatey installation method that doesn't rely on their install.ps1
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Chocolatey is already installed."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing utilities..."
If ($(hostname) -eq "win10") {
  # Because the Windows10 start menu sucks
  choco install -y --limit-output --no-progress classic-shell -installArgs ADDLOCAL=ClassicStartMenu
  & "C:\Program Files\Classic Shell\ClassicStartMenu.exe" "-xml" "c:\vagrant\resources\windows\MenuSettings.xml"
  regedit /s c:\vagrant\resources\windows\MenuStyle_Default_Win7.reg
}
choco install -y --limit-output --no-progress NotepadPlusPlus WinRar processhacker

# This repo often causes failures due to incorrect checksums, so we ignore them for Chrome
choco install -y --limit-output --no-progress --ignore-checksums GoogleChrome 

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Utilties installation complete!"
