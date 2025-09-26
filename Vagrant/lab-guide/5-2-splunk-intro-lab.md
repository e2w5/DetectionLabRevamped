# Lab 5-2: Splunk Web Interface Introduction

_Last update: 23/09/2025_

This lab provides a guided tour of the Splunk Enterprise UI deployed on the logger host. You will explore navigation, search basics, dashboards, and data sources configured in DetectionLabRevamped, then expand into Fleet/osquery validation, Atomic Red Team telemetry, and Windows Event Forwarding analysis.

## Learning Objectives
- Understand the layout of the Splunk Web interface (Home, Search & Reporting, Apps).
- Identify the preconfigured indexes and sourcetypes used in DetectionLabRevamped.
- Build and save basic searches, reports, and dashboard panels.
- Confirm Fleet/osquery queries surface in Splunk and correlate with host telemetry.
- Observe Atomic Red Team activity and Windows Event Forwarding data inside Splunk.

## Prerequisites
- Splunk Enterprise running on `logger` (confirm with `vagrant status`).
- Browser access to <https://192.168.57.105:8000> from the host. Credentials: `admin:changeme`.
- Atomic Red Team tooling present on `win11` (`C:\Tools\AtomicRedTeam`).
- Host preparation complete (as outlined in Lab 5-1):
  - `git clone https://github.com/e2w5/DetectionLabRevamped.git`
  - Disable VMware network adapters (Control Panel -> Network Connections -> disable each `VMware Network Adapter VMnet*`).
  - Run `Disable-HyperV.bat` as Administrator from the cloned repository root.
  - Disable Windows Core Isolation / Memory Integrity (Windows Security -> Device Security -> Core isolation details).

## Exercise 1 - Navigating Splunk Web – Navigating Splunk Web
1. Sign in to Splunk Web at <https://192.168.57.105:8000> with `admin:changeme`.
2. Explore the **Home** page: note recent searches, dashboards, and data summaries.
3. Open **Apps -> Search & Reporting** to access the primary search workspace.
4. Locate the **Dashboards** tabs and review existing content shipped with the lab.

*Checkpoint:* Record where to access the Data Summary view and list which indexes appear most active.

## Exercise 2 – Validating Data Sources
1. From **Search & Reporting**, click **Data Summary -> Hosts**. Confirm `dc`, `wef`, and `win11` appear with recent events.
2. Switch to the **Source types** tab and identify entries for Sysmon, Windows Event Logs, osquery, and Zeek/Suricata.
3. Use the search `index=* earliest=-15m latest=now | stats count by index` to view recent ingestion.
4. Save this search as a report called "Last 15 Minutes Index Volume".

*Checkpoint:* Document any indexes that show zero events and flag for follow-up.

## Exercise 3 – Building Dashboards
1. Run the search `index=sysmon | stats count by host, Image | sort - count limit=10` to view top processes.
2. Click **Save As -> Dashboard Panel**, create a new dashboard named "Blue Team Overview", and add the panel as a table.
3. Add a second panel using the search `index=osquery result=success | timechart count by host span=15m`.
4. Open the dashboard and adjust visualization settings (table vs. chart) to highlight anomalies.

*Checkpoint:* Capture a screenshot of the dashboard and store it with your lab notes.

## Exercise 4 – Fleet/osquery Review
1. Visit Fleet at <https://192.168.57.105:8412> and authenticate (`admin@detectionlab.network` / `Fl33tpassword!`).
2. Ensure all enrolled agents (`logger`, `dc`, `wef`, `win11`) show **Online**.
3. Run a live query using the `processes` pack to list PowerShell processes across Windows hosts.
4. Schedule a query (e.g., listening ports) and confirm results arrive in Splunk with `index=osquery | stats count by host, name`.

## Exercise 5 – Atomic Red Team Smoke Test
This exercise validates red-team tooling is ready while remaining safe. Run the commands from the `win11` VM after temporarily disabling Defender real-time protection if necessary.

1. On `win11`, open an elevated PowerShell session.
2. Execute `Invoke-AtomicTest T1059.001 -TestGuids 4f14f0c1-9f47-4a01-a513-9a9d2bb80bd0 -PathToAtomicsFolder C:\Tools\AtomicRedTeam\atomics`.
3. Monitor Splunk for new entries in `index=sysmon` where `Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` using `table _time, host, CommandLine`.
4. Record observed event IDs and how they map to detection logic or alerting rules.

*Checkpoint:* Re-enable Defender protections when finished if you disabled them.

## Exercise 6 – Windows Event Forwarding & Transcripts
1. On `dc`, trigger a failed logon attempt by entering an incorrect password for a domain user.
2. On `wef`, open **Event Viewer -> Subscriptions** and confirm the event arrives in the **Forwarded Events** channel.
3. In Splunk, search `index=wineventlog host=win11 OR host=dc sourcetype="WinEventLog:ForwardedEvents"` to verify the forwarded log.
4. Browse to `\\wef\pslogs` and ensure PowerShell transcripts from prior steps are present.

## Knowledge Check
1. Where do you find the Data Summary option in Splunk Web?
2. Which index tracks Sysmon events and how can you confirm hosts are reporting?
3. Describe how to save a search as a dashboard panel.
4. Which sourcetype represents osquery results and how do Fleet queries appear in Splunk?
5. After running an Atomic Red Team PowerShell test, which Splunk search confirms execution details?
6. Where can you review PowerShell transcripts collected via Windows Event Forwarding?

## Post-Lab Restoration
- Re-enable VMware network adapters (Control Panel -> Network Connections -> enable each VMware Network Adapter VMnet*).
- Run Enable-HyperV.bat from the repository root to restore Hyper-V if previously disabled.

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
1. Inside **Search & Reporting -> Data Summary**.
2. `index=sysmon`; run `index=sysmon | stats count by host` or review the Data Summary hosts view.
3. After running a search, use **Save As -> Dashboard Panel**, choose a dashboard, and define visualization options.
4. Sourcetype `osquery:result`; Fleet queries surface in Splunk within `index=osquery` with host and query name fields.
5. `index=sysmon host=win11 Image="*powershell.exe" | table _time, host, CommandLine` displays the atomic execution.
6. PowerShell transcripts reside on the WEF share at `\\wef\pslogs`; forwarded attempts appear in `index=wineventlog` with the ForwardedEvents sourcetype.

