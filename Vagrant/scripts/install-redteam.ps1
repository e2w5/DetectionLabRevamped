# Purpose: Installs Mimikatz and Powersploit into c:\Tools\Mimikatz. Used to install redteam related tooling.
$ErrorActionPreference = 'Continue'

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Red Team Tooling..."
$hostname = $(hostname)

$atomicRoot = 'C:\Tools\AtomicRedTeam'
$atomicsPath = Join-Path $atomicRoot 'atomics'
$atomicModulePath = Join-Path $atomicRoot 'invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'

function Install-AtomicRedTeamManual {
  param([string]$Root)

  $tempDir = Join-Path $env:TEMP 'atomic-red-team-temp'
  $zipPath = Join-Path $env:TEMP 'atomic-red-team.zip'
  $moduleZipPath = Join-Path $env:TEMP 'invoke-atomicredteam.zip'
  $moduleExtractRoot = Join-Path $env:TEMP 'invoke-atomicredteam-src'

  Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $moduleZipPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $moduleExtractRoot -Recurse -Force -ErrorAction SilentlyContinue

  try {
    $downloadUrl = 'https://codeload.github.com/redcanaryco/atomic-red-team/zip/refs/heads/master'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

    $extractedRoot = Get-ChildItem -Path $tempDir -Directory | Select-Object -First 1
    if (-not $extractedRoot) { throw 'Failed to extract atomic red team archive.' }

    if (Test-Path $Root) { Remove-Item -LiteralPath $Root -Recurse -Force }
    New-Item -Path $Root -ItemType Directory -Force | Out-Null

    $atomicsSource = Get-ChildItem -Path $extractedRoot.FullName -Directory -Filter 'atomics' -Recurse | Select-Object -First 1
    if (-not $atomicsSource) { throw 'Could not locate atomics folder in archive.' }
    Copy-Item -Path $atomicsSource.FullName -Destination (Join-Path $Root 'atomics') -Recurse -Force

    $moduleCommit = 'cdac4232e6f2df4ab8912a8d5d5845c3a4b9d8f9'
    $moduleZipUrl = "https://github.com/redcanaryco/invoke-atomicredteam/archive/$moduleCommit.zip"
    Invoke-WebRequest -Uri $moduleZipUrl -OutFile $moduleZipPath -UseBasicParsing
    Expand-Archive -Path $moduleZipPath -DestinationPath $moduleExtractRoot -Force

    $moduleSource = Join-Path $moduleExtractRoot ('invoke-atomicredteam-' + $moduleCommit)
    $moduleDest = Join-Path $Root 'invoke-atomicredteam'
    if (Test-Path $moduleDest) { Remove-Item -LiteralPath $moduleDest -Recurse -Force }
    Copy-Item -Path $moduleSource -Destination $moduleDest -Recurse -Force
  } finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $moduleZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $moduleExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Test-AtomicRedTeamInstall {
  param([string]$Root)

  $modulePath = Join-Path $Root 'invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
  $atomicsFolder = Join-Path $Root 'atomics'

  if (-not (Test-Path $modulePath)) { return $false }
  if (-not (Test-Path $atomicsFolder)) { return $false }

  try {
    $yaml = Get-ChildItem -Path $atomicsFolder -Filter '*.yaml' -Recurse -ErrorAction Stop | Select-Object -First 1
    return [bool]$yaml
  } catch {
    return $false
  }
}


# Disabling the progress bar speeds up IWR https://github.com/PowerShell/PowerShell/issues/2138
$ProgressPreference = 'SilentlyContinue'
# GitHub requires TLS 1.2 as of 2/27
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Windows Defender should be disabled already by O&O ShutUp10 and the GPO
If ($hostname -eq "win11" -And (Get-Service -Name WinDefend).StartType -ne 'Disabled' ) {
  # Adding Defender exclusions just in case
  Set-MpPreference -ExclusionPath "C:\Tools"
  Add-MpPreference -ExclusionPath "C:\Users\vagrant\AppData\Local\Temp"

  . c:\vagrant\scripts\Invoke-CommandAs.ps1
  Invoke-CommandAs 'NT SERVICE\TrustedInstaller' {
    Set-Service WinDefend -StartupType Disabled
    Stop-Service WinDefend
  }
}

# Windows Defender should be disabled by the GPO or uninstalled already, but we'll keep this just in case
If ($hostname -ne "win11" -And (Get-Service -Name WinDefend -ErrorAction SilentlyContinue).status -eq 'Running') {
  # Uninstalling Windows Defender (https://github.com/StefanScherer/packer-windows/issues/201)
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Uninstalling Windows Defender..."
  Try {
    Uninstall-WindowsFeature Windows-Defender -ErrorAction Stop
    Uninstall-WindowsFeature Windows-Defender-Features -ErrorAction Stop
  } Catch {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Windows Defender did not uninstall successfully..."
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) We'll try again during install-red-team.ps1"
  }
} Else  {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Windows Defender has already been disabled or uninstalled."
}

# Purpose: Downloads and unzips a copy of the latest Mimikatz trunk
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Determining latest release of Mimikatz..."
$tag = (Invoke-WebRequest "https://api.github.com/repos/gentilkiwi/mimikatz/releases" -UseBasicParsing | ConvertFrom-Json)[0].tag_name
$mimikatzDownloadUrl = "https://github.com/gentilkiwi/mimikatz/releases/download/$tag/mimikatz_trunk.zip"
$mimikatzRepoPath = 'C:\Users\vagrant\AppData\Local\Temp\mimikatz_trunk.zip'
If (-not (Test-Path $mimikatzRepoPath)) {
  Invoke-WebRequest -Uri "$mimikatzDownloadUrl" -OutFile $mimikatzRepoPath
  Expand-Archive -path "$mimikatzRepoPath" -destinationpath 'c:\Tools\Mimikatz' -Force
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Mimikatz was already installed. Moving On."
}

# Download and unzip a copy of PowerSploit
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Powersploit..."
$powersploitDownloadUrl = "https://github.com/PowerShellMafia/PowerSploit/archive/dev.zip"
$powersploitRepoPath = "C:\Users\vagrant\AppData\Local\Temp\powersploit.zip"
If (-not (Test-Path $powersploitRepoPath)) {
  Invoke-WebRequest -Uri "$powersploitDownloadUrl" -OutFile $powersploitRepoPath
  Expand-Archive -path "$powersploitRepoPath" -destinationpath 'c:\Tools\PowerSploit' -Force
  Copy-Item "c:\Tools\PowerSploit\PowerSploit-dev\*" "$Env:windir\System32\WindowsPowerShell\v1.0\Modules" -Recurse -Force
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) PowerSploit was already installed. Moving On."
}

# Download and unzip a copy of BadBlood
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading BadBlood..."
$badbloodDownloadUrl = "https://github.com/davidprowe/BadBlood/archive/master.zip"
$badbloodRepoPath = "C:\Users\vagrant\AppData\Local\Temp\badblood.zip"
If (-not (Test-Path $badbloodRepoPath)) {
  Invoke-WebRequest -Uri "$badbloodDownloadUrl" -OutFile "$badbloodRepoPath"
  Expand-Archive -path "$badbloodRepoPath" -destinationpath 'c:\Tools\BadBlood' -Force
  # Lower the number of default users to be created by BadBlood
  $invokeBadBloodPath = "c:\Tools\BadBlood\BadBlood-master\Invoke-BadBlood.ps1"
  ((Get-Content -path $invokeBadBloodPath -Raw) -replace '1000..5000','500..1500') | Set-Content -Path $invokeBadBloodPath
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) BadBlood was already installed. Moving On."
}

# Download and install Invoke-AtomicRedTeam
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Downloading Invoke-AtomicRedTeam and atomic tests..."
$needsAtomicInstall = -not (Test-AtomicRedTeamInstall -Root $atomicRoot)

if ($needsAtomicInstall) {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing Invoke-AtomicRedTeam via standard installer..."
  if (Test-Path $atomicRoot) {
    Write-Warning "$('[{0:HH:mm}]' -f (Get-Date)) Existing Atomic Red Team install appears incomplete. Reinstalling..."
    Remove-Item -LiteralPath $atomicRoot -Recurse -Force -ErrorAction SilentlyContinue
  }

  $installSucceeded = $false
  try {
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name powershell-yaml -Force
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
    Install-AtomicRedTeam -getAtomics -InstallPath $atomicRoot -ErrorAction Stop
    $installSucceeded = Test-AtomicRedTeamInstall -Root $atomicRoot
  } catch {
    Write-Warning ("$('[{0:HH:mm}]' -f (Get-Date)) Standard Invoke-AtomicRedTeam installer failed: {0}" -f $_.Exception.Message)
    $installSucceeded = $false
  }

  if (-not $installSucceeded) {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Falling back to manual Atomic Red Team download..."
    Install-AtomicRedTeamManual -Root $atomicRoot
    $installSucceeded = Test-AtomicRedTeamInstall -Root $atomicRoot
  }

  if (-not $installSucceeded) {
    throw 'Invoke-AtomicRedTeam installation failed after retry.'
  }
} else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Invoke-AtomicRedTeam already installed. Moving On."
}

$profilePaths = @('C:\Windows\System32\WindowsPowerShell\v1.0\Profile.ps1', (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\profile.ps1'))
$moduleSnippet = @'
$atomicModule = 'C:\Tools\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
if (Test-Path $atomicModule) {
  try {
    Import-Module $atomicModule -Force -ErrorAction Stop
  } catch {
    Write-Verbose ("Invoke-AtomicRedTeam module at {0} failed to load: {1}" -f $atomicModule, $_.Exception.Message)
  }
}
'@.Trim()
$defaultSnippet = '$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\Tools\AtomicRedTeam\atomics"}'
$legacyImportStatements = @(
  'Import-Module "C:\Tools\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force',
  'Import-Module "C:\Tools\Atomic Red Team\atomic-red-team-master\execution-frameworks\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam\Invoke-AtomicRedTeam.psm1"'
)
foreach ($profilePath in $profilePaths) {
  $profileDirectory = Split-Path -Path $profilePath -Parent
  if ($profileDirectory -and -not (Test-Path $profileDirectory)) {
    New-Item -ItemType Directory -Path $profileDirectory -Force | Out-Null
  }

  $profileContent = if (Test-Path $profilePath) { Get-Content -Path $profilePath -Raw } else { '' }

  if ($profileContent) {
    foreach ($legacyImport in $legacyImportStatements) {
      $escapedLegacyImport = [regex]::Escape($legacyImport)
      $profileContent = [regex]::Replace($profileContent, "(?m)^\s*$escapedLegacyImport\s*(\r?\n)?", '')
    }
  }

  if ($profileContent -notmatch [regex]::Escape($moduleSnippet)) {
    if ($profileContent.Length -gt 0 -and -not $profileContent.EndsWith("`r`n")) {
      $profileContent += "`r`n"
    }

    $profileContent += $moduleSnippet + "`r`n"
  }

  if ($profileContent -notmatch 'Invoke-AtomicTest:PathToAtomicsFolder') {
    if ($profileContent.Length -gt 0 -and -not $profileContent.EndsWith("`r`n")) {
      $profileContent += "`r`n"
    }

    $profileContent += $defaultSnippet + "`r`n"
  }

  Set-Content -Path $profilePath -Value ($profileContent.TrimEnd() + "`r`n")
}


# Purpose: Downloads the latest release of PurpleSharpNewtonsoft.Json.dll
If (-not (Test-Path "c:\Tools\PurpleSharp")) {
  New-Item -Path "c:\Tools\" -Name "PurpleSharp" -ItemType "directory"
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) PurpleSharp folder already exists. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Determining latest release of Purplesharp..."
$tag = (Invoke-WebRequest "https://api.github.com/repos/mvelazc0/PurpleSharp/releases" -UseBasicParsing | ConvertFrom-Json)[0].tag_name
$purplesharpDownloadUrl = "https://github.com/mvelazc0/PurpleSharp/releases/download/$tag/PurpleSharp_x64.exe"
If (-not (Test-Path "c:\Tools\PurpleSharp\PurpleSharp.exe")) {
  Invoke-WebRequest -Uri $purplesharpDownloadUrl -OutFile "c:\Tools\PurpleSharp\PurpleSharp.exe"
} Else {
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) PurpleSharp was already installed. Moving On."
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Red Team tooling installation complete!"
