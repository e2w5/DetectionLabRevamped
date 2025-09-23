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

## Exercise 1 – Baseline Connectivity & Access
1. Copy the virtual machines from the lab server to your computer.
2. Install Vagrant. After installation, run `vagrant up`.
3. From the host OS, open a terminal and run `vagrant status` to confirm all VMs report `running`.
4. Use `vagrant winrm dc -c "hostname"` and repeat for `wef` and `win11` to verify WinRM reachability.
5. SSH to the logger machine by running `vagrant ssh logger`.
6. Launch an RDP connection or use the VirtualBox console to access `win11` and confirm you can log on as `vagrant\vagrant`.

*Checkpoint:* Document any connectivity issues and how you resolved them before moving on.

## Exercise 2 – Splunk Telemetry Validation
1. Log into Splunk at <https://192.168.57.105:8000> (`admin:changeme`).
2. Confirm the indexes `wineventlog`, `sysmon`, and `osquery` exist via **Settings -> Indexes**.
3. Run the search `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | stats count by host`.
4. Export the search results (CSV) to confirm hosts `dc`, `wef`, and `win11` are reporting.
5. Create a dashboard panel that tracks events per host over the last 60 minutes.

*Checkpoint:* Save a screenshot of your dashboard for later review.

## Exercise 3 – Fleet/osquery Review
1. Visit Fleet at <https://192.168.57.105:8412> and authenticate (`admin@detectionlab.network` / `Fl33tpassword!`).
2. Ensure all enrolled agents (`logger`, `dc`, `wef`, `win11`) show **Online**.
3. Run a live query using the `processes` pack to list PowerShell processes across Windows hosts.
4. Schedule a query (e.g., listening ports) and note where results are stored in Splunk.

## Exercise 4 – Atomic Red Team Smoke Test
This exercise validates red-team tooling is ready while remaining safe. Run the commands from the `win11` VM after temporarily disabling Defender real-time protection if necessary.

1. On `win11`, open an elevated PowerShell session.
2. Execute `Invoke-AtomicTest T1059.001 -TestGuids 4f14f0c1-9f47-4a01-a513-9a9d2bb80bd0 -PathToAtomicsFolder C:\Tools\AtomicRedTeam\atomics`.
3. Monitor Splunk for new entries in `index=sysmon` where `Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
4. Record observed event IDs and how they map to detection logic in your SIEM.

*Checkpoint:* Re-enable Defender protections when finished if you disabled them.

## Exercise 5 – Windows Event Forwarding & Transcripts
1. On `dc`, trigger a failed logon attempt by entering an incorrect password for a domain user.
2. On `wef`, open **Event Viewer -> Subscriptions** and confirm the event arrives in the **Forwarded Events** channel.
3. Browse to `\\wef\pslogs` and verify PowerShell transcripts from prior steps are present.
4. Note the retention location for transcripts and any permissions required to access them.

## Knowledge Check
1. Which host runs Splunk Enterprise and Fleet, and what is its IP address?
2. Where can you find PowerShell transcript logs generated across the domain?
3. After running an Atomic Red Team test on `win11`, which Splunk index should you check first for process execution artifacts?
4. What credential pair grants access to the Fleet UI, and why is TLS important for this interface?
5. Name two Windows hosts that forward Sysmon data and explain how to confirm the forwarder service is healthy.

Please attempt the questions before reviewing the answers below.



























## Answer Key
- `logger` at 192.168.57.105 hosts both Splunk Enterprise and Fleet.
- PowerShell transcripts reside on the WEF server share at `\\wef\pslogs`.
- Check the `sysmon` index (sourcetype=`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`).
- Use `admin@detectionlab.network` / `Fl33tpassword!`; TLS protects credentials and query results in transit.
- Both `dc` and `wef` forward Sysmon. Confirm by checking the Splunk UF service status (`services.msc` or `Get-Service`) and verifying recent events in Splunk.
