  $newDNSServers = "127.0.0.1", "8.8.8.8", "4.4.4.4"
  $domain= "windomain.local"

  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -And ($_.IPAddress).StartsWith($subnet) }
  if ($adapters) {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Setting DNS"
    # Don't do this in Azure. If the network adatper description contains "Hyper-V", this won't apply changes.
    $adapters | ForEach-Object {if (!($_.Description).Contains("Hyper-V")) {$_.SetDNSServerSearchOrder($newDNSServers)}}
  }
  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Setting timezone to UTC"
  c:\windows\system32\tzutil.exe /s "UTC"

  Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Excluding NAT interface from DNS"
  $nics = Get-WmiObject "Win32_NetworkAdapterConfiguration where IPEnabled='TRUE'" | Where-Object { $_.IPAddress -and $_.IPAddress[0] -ilike "172.25.*" }
  $dnslistenip = $nics.IPAddress
  if ($dnslistenip) {
    Write-Host "$dnslistenip"
    dnscmd /ResetListenAddresses $dnslistenip | Out-Host
  } else {
    Write-Host "No NAT interface matched 172.25.*; skipping ResetListenAddresses"
  }

  $nics=Get-WmiObject "Win32_NetworkAdapterConfiguration where IPEnabled='TRUE'" |? { $_.IPAddress[0] -ilike "10.*" }
  foreach($nic in $nics) {
    $nic.DomainDNSRegistrationEnabled = $false
    $nic.SetDynamicDNSRegistration($false) |Out-Null
  }

  $RRs = $null
  try {
    $RRs = Get-DnsServerResourceRecord -ZoneName $domain -Type A -Name "@" -ErrorAction SilentlyContinue
  } catch {}
  if ($RRs) {
    foreach ($RR in $RRs) {
      if ($RR -and $RR.RecordData -and $RR.RecordData.IPv4Address -and ($RR.RecordData.IPv4Address.IPAddressToString -ilike "10.*")) {
        Remove-DnsServerResourceRecord -ZoneName $domain -RRType A -Name "@" -RecordData $RR.RecordData.IPv4Address -Force -Confirm:$false -ErrorAction SilentlyContinue
      }
    }
  } else {
    Write-Host "No existing '@' A records found in zone $domain"
  }
  Restart-Service DNS
