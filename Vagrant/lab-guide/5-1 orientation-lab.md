# DetectionLabRevamped Orientation Lab

_Last update: 23/09/2025_

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
1. Copy the virtual machines from the lab server to your computer.
2. Clone the lab repository to obtain helper scripts:
   - `git clone https://github.com/e2w5/DetectionLabRevamped.git`
   - Store the clone in an accessible working directory (e.g., `C:\DetectionLabRevamped`).
3. Disable VMware network interfaces on the host (Control Panel -> Network Connections -> right-click each "VMware Network Adapter VMnet*" and choose **Disable**).
4. From the cloned repository vagrant, run `Disable-HyperV.bat` as Administrator to turn off Hyper-V before using VirtualBox.
5. Install Vagrant (download from https://developer.hashicorp.com/vagrant/downloads and run the installer).
   - Change into the Vagrant directory: `cd DetectionLabRevamped/Vagrant`
   - Install the reload plugin with `vagrant plugin install vagrant-reload`.
   - Run `vagrant up` from within the Vagrant directory.
6. From the host OS, open a terminal and run `vagrant status` to confirm all VMs report `running`.
7. Use `vagrant winrm dc -c "hostname"` and repeat for `wef` and `win11` to verify WinRM reachability.
8. SSH to the logger machine by running `vagrant ssh logger`.
9. Launch an RDP connection or use the VirtualBox console to access `win11` and confirm you can log on as `vagrant\vagrant`.

*Checkpoint:* Document any connectivity issues and how you resolved them before moving on.

## Exercise 2 - Splunk Telemetry Validation
1. Log into Splunk at <https://192.168.57.105:8000> (`admin:changeme`).
2. Confirm the indexes `wineventlog`, `sysmon`, and `osquery` exist via **Settings -> Indexes**.
3. Run the search `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | stats count by host`.
4. Export the search results (CSV) to confirm hosts `dc`, `wef`, and `win11` are reporting.
5. Create a dashboard panel that tracks events per host over the last 60 minutes.

*Checkpoint:* Save a screenshot of your dashboard for later review.

## Knowledge Check
1. Which host runs Splunk Enterprise and Fleet, and what is its IP address?
2. Where can you find PowerShell transcript logs generated across the domain?
3. What credential pair grants access to the Fleet UI, and why is TLS important for this interface?
4. Name two Windows hosts that forward Sysmon data and explain how to confirm the forwarder service is healthy.

Please attempt the questions before reviewing the answers below.

## Post-Lab Restoration
- Re-enable VMware network adapters (Control Panel -> Network Connections -> right-click each "VMware Network Adapter VMnet*" and choose **Enable**).
- Run `Enable-HyperV.bat` as Administrator (from the repository vagrant) to restore Hyper-V if you disabled it earlier.











## Answer Key
- `logger` at 192.168.57.105 hosts both Splunk Enterprise and Fleet.
- PowerShell transcripts reside on the WEF server share at `\\wef\pslogs`.
- Use `admin@detectionlab.network` / `Fl33tpassword!`; TLS protects credentials and query results in transit.
- Both `dc` and `wef` forward Sysmon. Confirm by checking the Splunk UF service status (`services.msc` or `Get-Service`) and verifying recent events in Splunk.





