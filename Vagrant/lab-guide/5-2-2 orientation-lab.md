# DetectionLabRevamped Orientation Lab

_Last update: 17/06/2026_

This guided lab walks you through the core systems, telemetry, and tooling shipped with the DetectionLabRevamped VirtualBox fork. Complete the exercises to become comfortable navigating each host, validating data flows, and running basic red-team simulations.

## Learning Objectives
- Review the lab topology, credentials, and network layout.
- Validate host connectivity and remote access workflows.
- Confirm blue-team telemetry (Splunk, Fleet/osquery, Sysmon) is operational.
- Execute a safe Atomic Red Team test and observe resulting artifacts.
- Answer scenario-driven questions to reinforce familiarity with the environment.

## Prerequisites
Ensure the lab has been built via `vagrant up` and the VMs (`logger`, `dc`, `wef`, `win11`) are powered on. Gather the default credentials noted in the README or lab documentation.

## Lab Topology Quick Reference
| Host | IP Address | Role / Key Services |
| --- | --- | --- |
| logger (Ubuntu 24.04) | 192.168.57.105 | Splunk Enterprise, Fleet UI, Zeek, Suricata, Guacamole, Velociraptor server |
| dc (Windows Server 2022) | 192.168.57.102 | Domain Controller, DNS, Sysmon, osquery, Velociraptor agent, Splunk UF, GPOs, ATA GW |
| wef (Windows Server 2022) | 192.168.57.103 | Windows Event Collector, PS transcription share, Sysmon, Velociraptor, Splunk UF |
| win11 (Windows 11) | 192.168.57.104 | Workstation simulation, Sysmon, osquery, Velociraptor, Splunk UF |

## Exercise 1 - Baseline Connectivity & Access
1. Checking the virtual machine on your D: drive (D:\Mirror\VM\Intrusion Response). Copy the virtual machines from the lab server to your computer by running the CleanSync script on the D: drive, if it is not there.

2. - Install the windows terminal.
   - install the git for windows.
   - Clone the lab repository to obtain helper scripts:
      - `mkdir D:\Users\cueh\`
      - `cd D:\Users\cueh\`
      - `git clone https://github.com/e2w5/DetectionLabRevamped.git`
      - `robocopy "D:\Mirror\VM\Intrusion response" "D:\Users\cueh\DetectionLabRevamped\Boxes" /E /COPY:DAT /R:3 /W:5 /V /ETA`

3. Disable VMware network interfaces on the host (Control Panel -> Network Connections -> right-click each "VMware Network Adapter VMnet*" and choose **Disable**).
4. From the cloned repository root, run `Disable-HyperV.bat` as Administrator to turn off Hyper-V before using VirtualBox. 
5. Disable Windows Core Isolation / Memory Integrity (Windows Security -> Device Security -> Core isolation details -> set **Memory integrity** to Off and restart if prompted).
6. Install Vagrant (download from https://developer.hashicorp.com/vagrant/downloads and run the installer).
   - Change into the Vagrant directory: `cd DetectionLabRevamped/Vagrant`
   - Install the reload plugin with `vagrant plugin install vagrant-reload`.
   - Install VirtualBox.
   - Run `$env:VAGRANT_DEFAULT_PROVIDER = "virtualbox"`
   - Run `vagrant up` from within the Vagrant directory.
7. From the host OS, open a terminal and run `vagrant status` to confirm all VMs report `running`.
8. Use `vagrant winrm dc -c "hostname"` and repeat for `wef` and `win11` to verify WinRM reachability.
9. SSH to the logger machine by running `vagrant ssh logger`.
10. Launch an RDP connection or use the VirtualBox console to access `win11` and confirm you can log on as `vagrant\\vagrant`.

## Troubleshooting Build Errors

### `VBoxManage.exe` is not in PATH
If Vagrant cannot find `VBoxManage.exe`, VirtualBox is installed but its install directory is not available in the terminal PATH.

Fix it in PowerShell:

```powershell
$env:Path += ";C:\Program Files\Oracle\VirtualBox"
VBoxManage --version
```

If that works, add it to the user PATH permanently and open a new terminal:

```powershell
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path", "User") + ";C:\Program Files\Oracle\VirtualBox",
  "User"
)
```

Then retry from the Vagrant directory:

```powershell
cd D:\Users\cueh\DetectionLabRevamped\Vagrant
vagrant up logger
```

### `bento/ubuntu-24.04` box provider error
If `vagrant up logger` fails because `bento/ubuntu-24.04` is being requested with provider `virtualbox`, register the local logger box manually.

From the Vagrant directory, run:

```powershell
cd D:\Users\cueh\DetectionLabRevamped\Vagrant
vagrant box add bento/ubuntu-24.04 ..\Boxes\logger.box --provider virtualbox --force
vagrant up logger
```

If `..\Boxes\logger.box` does not exist, copy the VM box files from the lab mirror again:

```powershell
robocopy "D:\Mirror\VM\Intrusion response" "D:\Users\cueh\DetectionLabRevamped\Boxes" /E /COPY:DAT /R:3 /W:5 /V /ETA
```

### VirtualBox host-only adapter error
If `vagrant up`, `vagrant up logger`, or `vagrant up dc` fails with the error below, VirtualBox is installed but its host-only networking driver is missing or only partially registered:

```text
VBoxManage.exe: error: Failed to create the host-only adapter
VBoxManage.exe: error: Could not find Host Interface Networking driver! Please reinstall
VBoxManage.exe: error: Details: code E_FAIL (0x80004005)
```

Fix it from an Administrator PowerShell prompt:

- Install the VirtualBox network drivers:

   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxDrvInst.exe" install --inf-file "C:\Program Files\Oracle\VirtualBox\drivers\network\netlwf\VBoxNetLwf.inf"
   & "C:\Program Files\Oracle\VirtualBox\VBoxDrvInst.exe" install --inf-file "C:\Program Files\Oracle\VirtualBox\drivers\network\netadp6\VBoxNetAdp6.inf"
   ```

   If the command returns `VERR_ACCESS_DENIED`, close the terminal, reopen PowerShell with **Run as Administrator**, and run the commands again. Approve the Windows UAC prompt if one appears.

- Verify the drivers and host-only adapter:

   ```powershell
   pnputil /enum-drivers | Select-String -Pattern "vboxnetlwf|vboxnetadp6" -Context 2
   sc.exe query VBoxNetLwf
   VBoxManage list hostonlyifs
   ```

- If no host-only adapter exists, create one manually:

   ```powershell
   VBoxManage hostonlyif create
   ```

- Retry the lab build:

   ```powershell
   cd D:\Users\cueh\DetectionLabRevamped\Vagrant
   vagrant up logger
   ```

The expected DetectionLab host-only network is `192.168.57.0/24`; after the fix, VirtualBox should show an adapter such as `VirtualBox Host-Only Ethernet Adapter #2` with IP `192.168.57.1`.


## Exercise 2 - Splunk Telemetry Validation
1. Log into Splunk at <https://192.168.57.105:8000> (`admin:changeme`).
2. Confirm the indexes `wineventlog`, `sysmon`, and `osquery` exist via **Settings -> Indexes**.
3. Run the search `index=* | stats count by host`.
4. Export the search results (CSV) to confirm hosts `dc`, `wef`, and `win11` are reporting.
5. Create a dashboard panel that tracks events per host over the last 60 minutes:
   - In Splunk, stay in Search & Reporting and run `index=sysmon earliest=-60m latest=now | stats count by host`.
   - Select **Save As -> Dashboard Panel**, choose an existing dashboard or create a new one (e.g., "Orientation Overview"), and name the panel "Events per Host (Last 60m)".
   - Set visualization to a column chart (or preferred type), make sure the time range is set to **Last 60 minutes**, then save.


## Knowledge Check
1. Which host runs Splunk Enterprise, and what is its IP address?
2. Where can you find PowerShell transcript logs generated across the domain?
3. Name two Windows hosts that forward Sysmon data and explain how to confirm the forwarder service is healthy.

Please attempt the questions before reviewing the answers below.

## Post-Lab Restoration
- Re-enable VMware network adapters (Control Panel -> Network Connections -> right-click each "VMware Network Adapter VMnet*" and choose **Enable**).
- Run `Enable-HyperV.bat` as Administrator (from the repository root) to restore Hyper-V if you disabled it earlier.

<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />

## Answer Key
- `logger` at 192.168.57.105 hosts Splunk Enterprise.
- PowerShell transcripts reside on the WEF server share at `\\wef\pslogs`.
- Both `dc` and `wef` forward Sysmon. Confirm by checking the Splunk UF service status (`services.msc` or `Get-Service`) and verifying recent events in Splunk.



