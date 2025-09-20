# Purpose: Joins a Windows host to the windomain.local domain which was created with "create-domain.ps1".
# Source: https://github.com/StefanScherer/adfs2

$hostsFile = "c:\Windows\System32\drivers\etc\hosts"

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Joining the domain..."

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) First, set DNS to DC to join the domain..."
$dcIP = "192.168.57.102"
$subnetPrefix = "192.168.57."
try {
  $ifaces = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4Address.IPAddress -like "$subnetPrefix*" }
  foreach ($if in $ifaces) { Set-DnsClientServerAddress -InterfaceIndex $if.InterfaceIndex -ServerAddresses $dcIP -ErrorAction SilentlyContinue }
} catch {
  # Fallback for older shells
  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -match "^$subnetPrefix" }
  $adapters | ForEach-Object { if (!($_.Description).Contains("Hyper-V")) { $_.SetDNSServerSearchOrder($dcIP); $_.SetWINSServer($dcIP, "") } }
}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Verifying domain controller reachability (DNS/LDAP/Kerberos)..."
# Retry for up to ~5 minutes
for ($i=1; $i -le 30; $i++) {
  $ok = $false
  try { if (Test-Connection -ComputerName $dcIP -Count 1 -Quiet) { $ok = $true } } catch {}
  try { if (Resolve-DnsName -Server $dcIP windomain.local -ErrorAction Stop) { $ok = $ok -and $true } else { $ok = $false } } catch { $ok = $false }
  try {
    $ldap = Test-NetConnection -ComputerName $dcIP -Port 389 -InformationLevel Quiet
    $krb = Test-NetConnection -ComputerName $dcIP -Port 88 -InformationLevel Quiet
    $ok = $ok -and $ldap -and $krb
  } catch { $ok = $false }
  if ($ok) { break }
  if ($i -in 5,10,20) { Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Waiting for DC services... ($i/30)" }
  Start-Sleep -Seconds 10
}

# Ensure time sync to avoid Kerberos skew issues
try { w32tm /config /syncfromflags:manual /manualpeerlist:$dcIP /update | Out-Null; w32tm /resync /force | Out-Null } catch {}

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Now join the domain..."
$hostname = $(hostname)
$user = "windomain.local\vagrant"
$pass = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$DomainCred = New-Object System.Management.Automation.PSCredential $user, $pass

# Place the computer in the correct OU based on hostname
# Retry up to 3 times. Sleep 15 seconds between tries.
If (($hostname -eq "wef") -or ($hostname -eq "exchange")) {
  $tries = 0
  While ($tries -lt 3) {
    Try {
      $tries += 1
      Add-Computer -DomainName "windomain.local" -credential $DomainCred -OUPath "ou=Servers,dc=windomain,dc=local" -PassThru -ErrorAction Stop
      Break
    } Catch {
      $tries += 1
      Write-Host $_.Exception.Message
      Start-Sleep 15
    }
  }
  # Attempt to fix Issue #517
  Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -Type String -Force -ea SilentlyContinue
  New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'AutoEndTasks' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
  Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\Power' -Name 'HiberbootEnabled' -Value 0 -Type DWord -Force -ea SilentlyContinue
} ElseIf ($hostname -eq "win11") {
   Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Win11 to the domain."
  ### Debugging the Win11 domain join issue https://github.com/clong/DetectionLab/issues/801
  $tries = 0
  While ($tries -lt 3) {
    Try {
      $tries += 1
      Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Try # $tries"
      Add-Computer -DomainName "windomain.local" -credential $DomainCred -OUPath "ou=Workstations,dc=windomain,dc=local"
      Break
    } Catch {
      $tries += 1
      ping -n 1 windomain.local
      ipconfig /all
      Write-Host $_.Exception.Message
      Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Sleeping 10s before trying again..."
      Start-Sleep 10
    }
  }
} Else {
  Add-Computer -DomainName "windomain.local" -credential $DomainCred -PassThru
}

# Stop Windows Update
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Disabling Windows Updates and Windows Module Services"
Set-Service wuauserv -StartupType Disabled
Stop-Service wuauserv
Set-Service TrustedInstaller -StartupType Disabled
Stop-Service TrustedInstaller
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Done Disabling Windows Updates and Windows Module Services"

# Uninstall Windows Defender from WEF
# This command isn't supported on win11
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
}
