
# Lab Guide

_Last update: 22/09/2025_

## Intro
- **Purpose:** providing a blue team test environment (SIEM and Active Directory) that represents a realistic enterprise deployment.
- Fork of Chris Long’s DetectionLab tuned for VirtualBox (no VMware plugin licensing) with updated images (Ubuntu 24.04 logger, Server 2022 DC/WEF, Windows 11 workstation) while preserving upstream blue/red-team tooling (Splunk stack, osquery/Fleet, Sysmon, Zeek, Suricata, PurpleSharp, AtomicRedTeam, etc.).
## Topology & Services
- Subnet `192.168.57.0/24`.
- **logger (Ubuntu 24.04 – 192.168.57.105):** Splunk Enterprise, Fleet (TLS 8412), Zeek, Suricata, Guacamole (8080), Velociraptor server (9999).
- **dc (Windows Server 2022 – 192.168.57.102):** AD DS, DNS, DHCP, Sysmon, osquery, Velociraptor agent, Splunk UF, ATA lightweight gateway, hardened GPOs (enhanced auditing, PS logging, WEF config).
- **wef (Windows Server 2022 – 192.168.57.103):** WEC subscriptions, PS transcript share (`\\wef\pslogs`), ATA console, Sysmon/osquery/Velociraptor/Splunk UF.
- **win11 (Windows 11 – 192.168.57.104):** Employee workstation sim with Sysmon/osquery/Velociraptor/Splunk UF.
- Red-team tools (Mimikatz, PowerSploit, BadBlood, PurpleSharp, AtomicRedTeam + atomics) preinstalled on Windows hosts.
## Credentials & URLs
- Domain: `windomain.local` – `vagrant:vagrant`.
- Splunk: <https://192.168.57.105:8000> – `admin:changeme`.
- Fleet: <https://192.168.57.105:8412> – `admin@detectionlab.network:Fl33tpassword!`.
- Velociraptor: <https://192.168.57.105:9999> – `admin:changeme`.
## Validation Checklist
- Ping between guests (e.g. `Test-NetConnection 192.168.57.105 -Port 8000`).
- Splunk web UI accessible; indexes exist; Sysmon/osquery/WinEvent data arriving.
- Fleet UI shows all agents (logger, dc, wef, win11) online.
- `Get-WinEvent` on `wef` shows subscription channels; PowerShell transcripts stored under `\\wef\pslogs`.
## Maintenance & Troubleshooting
- `fix-second-network.ps1` enforces static IPs: `vagrant winrm <vm> -c "& 'C:\vagrant\scripts\fix-second-network.ps1' -ip ..."`.
- Reapply provisioning via `vagrant provision <vm>`; rerun individual `install-*` scripts if tooling is missing.
- If a VM corrupts: `vagrant destroy <vm> -f` then `vagrant up <vm>`.
- WinRM flakiness: `vagrant reload <vm> --provision`.
- Defender blocks: temporarily disable real-time/script scanning; re-enable with `$false` when done.
- Keep VirtualBox and Extension Pack current; match documented Vagrant/VirtualBox versions.
## Home Lab Prerequisites
- Host resources: >=55 GB free disk, >=16 GB RAM, virtualization enabled.
- Software: VirtualBox 7.1.12, Vagrant 2.2.2+, Packer (optional), Git; disable unused hypervisor adapters (e.g. Hyper-V vSwitch) on Windows Pro.
- Recommended plugin: `vagrant-reload`.
## Build Steps
1. `git clone https://github.com/e2w5/DetectionLabRevamped.git`
2. `cd DetectionLabRevamped/Vagrant`
3. `vagrant up` (or `vagrant up logger`, `vagrant up dc`, `vagrant up wef`, `vagrant up win11`).
4. If Defender blocks scripts on Win11, run `vagrant winrm win11 -c "Try { Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true } Catch { $_ }"` before retrying.
5. Reinstall Atomic Red Team only: `vagrant winrm <vm> -c "& 'C:\vagrant\scripts\install-redteam.ps1'"`.
