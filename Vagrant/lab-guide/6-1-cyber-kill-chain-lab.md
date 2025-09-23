
# Lab 6-1: Cyber Kill Chain Detection Lab
_Last update: 23/09/2025_

This lab guides you through executing selected Atomic Red Team tests aligned to Lockheed Martin’s Cyber Kill Chain and validating detections in Splunk. You will stage activity on the Win11 host, observe logs on WEF/logger, and create Splunk searches highlighting each phase.
## Learning Objectives
- Map Atomic Red Team techniques to Cyber Kill Chain phases.
- Execute representative atomics on the Win11 endpoint and capture telemetry.
- Build Splunk searches/dashboards to surface the malicious activity.
- Document detection gaps and recommended mitigations.
## Prerequisites
- Lab 5-1 orientation complete; VMs running (`logger`, `dc`, `wef`, `win11`).
- Defender disabled or exclusions configured on `win11` to allow Atomic tests.
- Splunk accessible at <https://192.168.57.105:8000> and Atomic Red Team installed under `C:\Tools\AtomicRedTeam`.
## Scenario Overview
You will execute five phases of the Cyber Kill Chain with curated Atomic Red Team tests. After each execution, pivot to Splunk to validate telemetry and create detections. Use the table below as a roadmap.

| Phase | Atomic Test | Command (Win11 PowerShell) | Key Logs |
| --- | --- | --- | --- |
| Delivery | T1566.001 Phishing via Outlook (simulation) | `Invoke-AtomicTest T1566.001 -TestGuids 87a8d541-0e1d-41b6-9aba-cc41ea76c588` | `index=wineventlog` (WEF), Sysmon event ID 1 |
| Execution | T1059.001 PowerShell | `Invoke-AtomicTest T1059.001 -TestGuids 4f14f0c1-9f47-4a01-a513-9a9d2bb80bd0` | `index=sysmon` Image=`powershell.exe` |
| Persistence | T1547.001 Registry Run Keys | `Invoke-AtomicTest T1547.001 -TestGuids 2d8f0abd-76d8-4a6c-b9f6-0d14d1a4e1cc` | `index=sysmon` EventCode=13, `index=wineventlog` |
| Command & Control | T1071.001 Web C2 | `Invoke-AtomicTest T1071.001 -TestGuids 29d99f6a-7abf-46b8-bd47-1e6bb5e1ca13` | `index=suricata` HTTP beacons, `index=sysmon` EventCode=3 |
| Actions on Objectives | T1003.001 Credential Dumping (LSASS) | `Invoke-AtomicTest T1003.001 -TestGuids 1744e7f1-5ee5-44ad-8744-8bbf1bfe3815` | `index=sysmon` EventCode=10, WEF security logs |
## Exercise 1 – Preparing the Environment
1. On `win11`, disable real-time protection (if required) using `Set-MpPreference -DisableRealtimeMonitoring $true`.
2. Open an elevated PowerShell prompt and change directory to `C:\Tools\AtomicRedTeam`.
3. Ensure dependencies are present via `.in
esolve-atomics.ps1 T1566.001,T1059.001,T1547.001,T1071.001,T1003.001`.
4. In Splunk, create an empty dashboard named "Kill Chain Overview".

*Checkpoint:* Document any dependency download errors.
## Exercise 2 – Delivery Phase (Phishing)
1. On `win11`, run `Invoke-AtomicTest T1566.001 -TestGuids 87a8d541-0e1d-41b6-9aba-cc41ea76c588 -Cleanup` to ensure a clean state, then rerun without `-Cleanup`.
2. In Splunk, search `index=wineventlog host=win11 sourcetype="WinEventLog:Microsoft-Windows-Security-Auditing" EventCode=4688` to locate payload execution.
3. Add a dashboard panel showing `index=wineventlog host=win11 EventCode=4688 | stats count by New_Process_Name`.
4. Note user context and command line used.

*Checkpoint:* Capture evidence showing the phishing simulation triggered process creation.
## Exercise 3 – Execution Phase (PowerShell)
1. Run `Invoke-AtomicTest T1059.001 -TestGuids 4f14f0c1-9f47-4a01-a513-9a9d2bb80bd0 -PathToAtomicsFolder C:\Tools\AtomicRedTeam\atomics`.
2. In Splunk, use `index=sysmon host=win11 Image="*powershell.exe" | table _time, host, CommandLine`.
3. Create a correlation search flagged as "Execution via PowerShell" stored in `detections/execution` folder.
4. Update the dashboard with a panel showing PowerShell executions in the last 60 minutes.

*Checkpoint:* Ensure Sysmon Event ID 1 entries include the Atomic command line.
## Exercise 4 – Persistence Phase (Registry Run Keys)
1. Execute `Invoke-AtomicTest T1547.001 -TestGuids 2d8f0abd-76d8-4a6c-b9f6-0d14d1a4e1cc` on `win11`.
2. In Splunk, search `index=sysmon host=win11 EventCode=13 | table _time, TargetObject, Details` to spot registry modifications.
3. Configure an alert for new Run key entries not matching a known whitelist.
4. Validate cleanup by running the Atomic test with the `-Cleanup` flag.

*Checkpoint:* Document registry path and value created by the Atomic test.
## Exercise 5 – Command & Control Phase (Web Traffic)
1. Execute `Invoke-AtomicTest T1071.001 -TestGuids 29d99f6a-7abf-46b8-bd47-1e6bb5e1ca13`.
2. In Splunk, run `index=suricata OR index=zeek host=logger http_request | stats count by src_ip, dest_host` to view beacon traffic.
3. Add a dashboard visualization (line chart) showing HTTP requests per minute from `win11`.
4. Correlate with `index=sysmon EventCode=3 host=win11` to tie network events to processes.

*Checkpoint:* Verify the beacon destination host/IP and process relationship.
## Exercise 6 – Actions on Objectives (Credential Access)
1. Run `Invoke-AtomicTest T1003.001 -TestGuids 1744e7f1-5ee5-44ad-8744-8bbf1bfe3815`.
2. In Splunk, search `index=sysmon host=win11 EventCode=10` for LSASS access attempts.
3. Augment with `index=wineventlog host=dc EventCode=4625 OR EventCode=4672` to detect privileged access.
4. Add a dashboard panel summarizing suspicious credential dumping events.
5. Execute the Atomic cleanup procedure to revert changes.

*Checkpoint:* Record whether the Atomic test triggered Defender or other alerts and how they were handled.
## Wrap-Up Tasks
1. Review the "Kill Chain Overview" dashboard and ensure panels exist for each phase.
2. Summarize detections and gaps in a short report (include Splunk saved search names).
3. Re-enable Defender protections on `win11` using `Set-MpPreference -DisableRealtimeMonitoring $false`.
4. Optionally export the dashboard to PDF for documentation.

## Knowledge Check
1. Which Atomic Red Team test simulated the Delivery phase and what artifacts confirmed it?
2. What Splunk index captured registry persistence changes?
3. How did you correlate network beaconing with host processes?
4. Which Splunk saved search would alert on LSASS access attempts?
5. What cleanup steps are required after running persistence and credential dumping atomics?

## Answer Key
1. T1566.001 (phishing); observed EventCode 4688 in `index=wineventlog` with the payload command line.
2. `index=sysmon` EventCode 13 captured Run key modifications.
3. Combined `index=suricata`/`zeek` HTTP data with `index=sysmon` EventCode 3 (network connections) filtered on `host=win11`.
4. The correlation search created in Exercise 3 (`detections/execution`) plus a targeted query `index=sysmon EventCode=10 Image=*lsass*`.
5. Run Atomic tests with `-Cleanup`, remove Run keys, and re-enable Defender protections.






