# Lab 6-2: Suricata, Zeek, and Velociraptor Operations

_Last update: 23/09/2025_

This lab focuses on the network-centric tooling shipped with DetectionLabRevamped: Suricata, Zeek, and Velociraptor. You will generate traffic, inspect alerts and logs, and leverage Velociraptor hunts to tie host telemetry back to network detections.

## Learning Objectives
- Validate Suricata alerting and Zeek logging on the `logger` sensor VM.
- Correlate network events with Splunk indexes (`suricata`, `zeek`).
- Use Velociraptor to hunt for artifacts on Windows endpoints and escalate alerts to host investigations.
- Produce a consolidated dashboard/report summarizing findings.

## Prerequisites
- Lab 5-2 Splunk lab completed; Lab 6-1 optional but recommended.
- `logger`, `dc`, `wef`, and `win11` running.
- Access to Splunk (<https://192.168.57.105:8000>) and Velociraptor console (<https://192.168.57.105:9999>, `admin:changeme`).
- Ability to generate network traffic from `win11` (curl, web browsers, etc.).
- Host preparation complete (clone repository, disable VMware adapters, run `Disable-HyperV.bat`, disable Windows Core Isolation / Memory Integrity).

## Exercise 1 – Survey the Sensor Stack – Survey the Sensor Stack
1. SSH to `logger` (`vagrant ssh logger`).
2. Verify Suricata service status with `sudo systemctl status suricata` and Zeek with `sudo systemctl status zeek`.
3. List active log files: `ls -1 /var/log/suricata/` and `/opt/zeek/logs/current/`.
4. In Splunk, run `index=suricata OR index=zeek earliest=-15m` to confirm recent ingestion.

*Checkpoint:* Note Suricata version, rule set location, and Zeek log rotation schedule.

## Exercise 2 – Generate Suspicious Traffic
1. On `win11`, open PowerShell and execute `Invoke-WebRequest http://testmynids.org/uid/index.html -UseBasicParsing` to trigger Suricata signatures.
2. Browse to a known malicious test domain (e.g., `http://www.malware-traffic-analysis.net/`) using Edge/IE to generate HTTP requests.
3. In Splunk, search `index=suricata signature=*` and identify new alerts; note `src_ip`, `dest_ip`, and `signature`.
4. Pivot to Zeek logs via `index=zeek sourcetype=zeek:http` filtering on the same `src_ip`.

*Checkpoint:* Capture alert IDs and matching Zeek entries that describe the session.

## Exercise 3 – Build Splunk Views for Network Alerts
1. Create a Splunk dashboard "Network Threat Overview".
2. Panel 1: `index=suricata | stats count by signature | sort - count` (bar chart).
3. Panel 2: `index=zeek sourcetype=zeek:http | timechart count by host span=15m`.
4. Panel 3: comparison table `search index=suricata | stats dc(dest_ip) AS destinations, values(signature) AS signatures BY src_ip`.
5. Save the dashboard for use in later labs.

*Checkpoint:* Export the dashboard to PDF or capture a screenshot.

## Exercise 4 – Velociraptor Quick Hunt
1. Log into Velociraptor at <https://192.168.57.105:9999> (`admin:changeme`).
2. Confirm endpoints (`logger`, `dc`, `wef`, `win11`) show **Online** under **Clients**.
3. Launch a hunt using artifact `Windows.System.Pslist` targeting `win11` to collect process listings.
4. After the hunt finishes, download results and note processes associated with recent Suricata alerts (e.g., browser/PowerShell).
5. Upload relevant findings to Splunk or reference in your incident notes.

*Checkpoint:* Document hunt ID, duration, and any suspicious processes identified.

## Exercise 5 – Correlate Network Alerts with Host Telemetry
1. In Splunk, search `index=suricata signature=*` and select one alert from Exercise 2.
2. Extract timestamp and source IP, then run `index=sysmon host=win11 earliest=-5m@m latest=+5m@m` to correlate host events during the same window.
3. Use Velociraptor artifact `Windows.EventLogs.EvtxHunter` to pull relevant Sysmon or Security logs for the time range.
4. Combine findings in a short narrative summarizing network-to-host relationships.

*Checkpoint:* Ensure narrative includes Suricata signature, Zeek session ID, process name, and Velociraptor hunt reference.

## Exercise 6 – Validate Detection and Cleanup
1. Review Suricata rule hits via `sudo tail -f /var/log/suricata/fast.log` on `logger`.
2. Disable or revert any test traffic (close browsers, stop scripts).
3. In Velociraptor, stop or archive hunts and remove collected artifacts if desired.
4. Update the "Network Threat Overview" dashboard with annotations summarizing the test campaign.

*Checkpoint:* Confirm services (Suricata, Zeek, Velociraptor) remain healthy after tests.

## Wrap-Up Tasks
1. Export or screenshot the network dashboard and Velociraptor hunt results.
2. Summarize key alerts, affected hosts, and recommended remediation steps in a short report.
3. Re-enable any security controls (Defender, proxies) you temporarily disabled.
4. Plan follow-up detections (e.g., Splunk correlation searches for repeated Suricata signatures).

## Knowledge Check
1. Which log directories store raw Suricata and Zeek output on `logger`?
2. How did you confirm Suricata alerts were ingested into Splunk?
3. What Velociraptor artifact did you use to enumerate processes on `win11`?
4. Which Splunk indexes capture Zeek HTTP data and Suricata alerts?
5. How can you tie a Suricata signature to a specific Windows process using available tooling?

## Post-Lab Restoration
- Re-enable VMware network adapters (Control Panel -> Network Connections -> enable each VMware Network Adapter VMnet*).
- Run Enable-HyperV.bat as Administrator from the repository root to restore Hyper-V.

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
1. Suricata: `/var/log/suricata/`; Zeek: `/opt/zeek/logs/current/`.
2. By running `index=suricata` searches and reviewing the Network Threat Overview dashboard.
3. `Windows.System.Pslist` hunt artifact.
4. `index=zeek` (sourcetype `zeek:http`, etc.) and `index=suricata`.
5. Correlate Splunk `index=suricata` alerts with Zeek logs, then use Sysmon (`index=sysmon`) and Velociraptor hunts to identify the process responsible on `win11`.

