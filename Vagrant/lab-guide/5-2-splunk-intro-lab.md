
# Lab 5-2: Splunk Web Interface Introduction
\n_Last update: 23/09/2025_\n
\nThis lab provides a guided tour of the Splunk Enterprise UI deployed on the logger host. You will explore navigation, search basics, dashboards, and data sources configured in DetectionLabRevamped.
## Learning Objectives
- Understand the layout of the Splunk Web interface (Home, Search & Reporting, Apps).
- Identify the preconfigured indexes and sourcetypes used in DetectionLabRevamped.
- Build and save a basic search and dashboard panel.
- Review data inputs forwarded from Windows hosts and Linux sensors.
## Prerequisites
- Splunk Enterprise running on `logger` (confirm with `vagrant status`).
- Credentials: `admin:changeme`.
- Browser access to <https://192.168.57.105:8000> from the host or via Guacamole.
## Exercise 1 – Navigating Splunk Web
1. Sign in to Splunk Web at <https://192.168.57.105:8000> with `admin:changeme`.
2. Explore the **Home** page: note recent searches, dashboards, and data summaries.
3. Open **Apps → Search & Reporting** to access the primary search workspace.
4. Locate the **Datasets**, **Reports**, and **Dashboards** tabs and review existing content shipped with the lab.

*Checkpoint:* Record where to access the Data Summary view and list which indexes appear most active.
## Exercise 2 – Validating Data Sources
1. From **Search & Reporting**, click **Data Summary** → **Hosts**. Confirm `dc`, `wef`, and `win11` appear with recent events.
2. Switch to the **Source types** tab and identify entries for Sysmon, Windows Event Logs, osquery, and Zeek/Suricata.
3. Use the search `index=* earliest=-15m latest=now | stats count by index` to view recent ingestion.
4. Save this search as a report called "Last 15 Minutes Index Volume".

*Checkpoint:* Document any indexes that show zero events and flag for follow-up.
## Exercise 3 – Building Dashboards
1. Run the search `index=sysmon | stats count by host, Image | sort - count limit=10` to view top processes.
2. Click **Save As → Dashboard Panel**, create a new dashboard named "Blue Team Overview", and add the panel as a table.
3. Add a second panel using the search `index=osquery result=success | timechart count by host span=15m`.
4. Open the dashboard and adjust visualization settings (table vs. chart) to highlight anomalies.

*Checkpoint:* Capture a screenshot of the dashboard and store it with your lab notes.
## Knowledge Check
1. Where do you find the Data Summary option in Splunk Web?
2. Which index tracks Sysmon events and how can you confirm hosts are reporting?
3. Describe how to save a search as a dashboard panel.
4. Which sourcetype represents osquery results in this lab?
5. How would you identify if the Windows Event Forwarding pipeline stops delivering data?

## Answer Key
1. Inside **Search & Reporting** → **Data Summary**.
2. `index=sysmon`; run `index=sysmon | stats count by host` or review the Data Summary hosts view.
3. After running a search, use **Save As → Dashboard Panel**, choose a dashboard, and define visualization options.
4. Sourcetype `osquery:result` (or similar) under the Source types tab; confirms osquery ingestion.
5. Check `index=wineventlog` for recent events from `wef`; if empty, inspect the WEF server, subscriptions, and Splunk UF service.
