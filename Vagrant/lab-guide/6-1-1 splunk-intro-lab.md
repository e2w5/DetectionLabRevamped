# Lab 6-1-1: Splunk Web Interface Introduction

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

## Exercise 1 - Navigating Splunk Web
1. Sign in to Splunk Web at <https://192.168.57.105:8000> with `admin:changeme`.
2. Explore the **Home** page: note recent searches, dashboards, and data summaries.
3. Open **Apps -> Search & Reporting** to access the primary search workspace.
4. Locate the **Dashboards** tabs and review existing content shipped with the lab.


## Exercise 2 - Validating Data Sources (Splunk 10)
1. In the **Search** app start a new search window and run `| tstats count where index=* earliest=-15m latest=now by host`. Confirm `dc`, `wef`, `win11`, and `logger` report recent events.
2. Run `index=* earliest=-15m latest=now | stats count by sourcetype` to verify Sysmon, Windows Event Logs, osquery results (`osquery:result`), Zeek, and Suricata are arriving. Use the time picker if you need a different window.
3. Validate osquery ingestion with `index=osquery earliest=-15m latest=now | stats count by host, name`.
4. Save the first search through **Actions -> Save As -> Report**, naming it "Last 15 Minutes Index Volume" and keeping sharing set to "This app".
5. From the results, click **Visualize** and choose **Column** to review relative volume before returning to the search workspace.

## Exercise 3 - Simple Keyword Searches
1. In **Search & Reporting**, set the time picker to **Last 4 hours**.
2. Run `index=* error` and watch the timeline populate. Click a bar to filter to that time slice.
3. Narrow the scope by host with `index=* error host=win11*` and observe how the results change.
4. Using quotes: `index=* "login" host=dc` and note which sourcetypes report the message. Expand the time ticker if no results.

## Exercise 4 - Quick Counts

**Tip:** Splunk chains commands with the pipe character (`|`). Each pipe hands the current results to the next command, so you can stack transformations like filters, stats, and display helpers (`table`, `top`, `fields`, etc.).

1. With the time picker still at **Last 4 hours**, run `index=* | stats count by sourcetype | sort -count`.
2. Identify the top few sourcetypes, then rerun the search as `index=* sourcetype=zeek | stats count by host` to check which machines have Sysmon data.
3. Try the `top` command: `index=* | top limit=5 host` to list the busiest hosts for security logs.
4. Use `fields` to tidy the output: append `| fields host, count` or `| fields - percent`. When you want to present only specific columns, pipe into `| table host count` to render a clean table.

## Knowledge Check
1. Where do you find the Data Summary option in Splunk Web?
2. Which index tracks Sysmon events and how can you confirm hosts are reporting?
3. Describe how to save a search as a dashboard panel.
4. Which SPL command quickly lists the most common values for a field?
5. What does the pipe symbol do in a Splunk search and which command turns the results into columns?

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
4. The `top` command (for example, `| top limit=5 host`) shows the most frequent field values.
5. The pipe (`|`) passes results to the next command; use `table` (for example, `| table host count`) to present selected fields as columns.






