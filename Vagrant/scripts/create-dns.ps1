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
  $nics=Get-WmiObject "Win32_NetworkAdapterConfiguration where IPEnabled='TRUE'" |? { $_.IPAddress[0] -ilike "172.25.*" }
  $dnslistenip=$nics.IPAddress
  $dnslistenip
  dnscmd /ResetListenAddresses  $dnslistenip

  $nics=Get-WmiObject "Win32_NetworkAdapterConfiguration where IPEnabled='TRUE'" |? { $_.IPAddress[0] -ilike "10.*" }
  foreach($nic in $nics) {
    $nic.DomainDNSRegistrationEnabled = $false
    $nic.SetDynamicDNSRegistration($false) |Out-Null
  }

  $RRs= Get-DnsServerResourceRecord -ZoneName $domain -type 1 -Name "@"
  foreach($RR in $RRs) {
    if ( (Select-Object  -InputObject $RR HostName,RecordType -ExpandProperty RecordData).IPv4Address -ilike "10.*") {
      Remove-DnsServerResourceRecord -ZoneName $domain -RRType A -Name "@" -RecordData $RR.RecordData.IPv4Address -Confirm
    }
  }
  Restart-Service DNS
