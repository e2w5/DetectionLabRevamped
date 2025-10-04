# Splunk BOTSv2 Intro Walkthrough

_Last update: 04/10/2025_

This walkthrough helps new analysts explore the Splunk Boss of the SOC v2 **attack-only** dataset on the DetectionLabRevamped logger. The goal is to verify the dataset, tour the preinstalled content, and practise a few high-value hunts without getting bogged down in every storyline detail.

## Prerequisites
- Logger VM provisioned and accessible (`vagrant up logger`).
- BOTS v2 attack dataset loaded by running `sudo ./scripts/install-botsv2.sh` inside the logger VM (reboot Splunk if prompted).
- Splunk Web available at <https://192.168.57.105:8000> (`admin:changeme`).
- Familiarity with basic SPL (`search`, `stats`, `table`).

## Quick Dataset Sanity Checks
1. Log into Splunk Web and open **Settings → Indexes**. Confirm the BOTS indexes exist (`botsv2`, `botsv2_summary`, `botsv2_lookups`).
2. In **Search & Reporting**, run:
   ```spl
   | tstats count where index=botsv2 earliest=-24h latest=now by sourcetype
   ```
   Ensure counts appear for key sourcetypes (e.g. `pan:traffic`, `wineventlog`, `xmlwineventlog:microsoft-windows-sysmon/operational`).
3. Verify lookup health:
   ```spl
   | inputlookup botsv2_attribution.csv | stats count
   ```
   A non-zero count means the supporting lookups loaded correctly.

## Exercise 1 – Orientation Dashboards
_Focus: learn where to pivot quickly._
1. Open **Apps → Splunk Security Essentials** and browse to **Content → BOTSv2**. Note the featured detections.
2. Launch the **Enterprise Security → Incident Review** dashboard. Filter on `index=botsv2` to see pre-generated notables.
3. Review the **BOTS v2 Scoreboard** app (Search → `bot_scoreboard`). Observe the scenario storyline timeline.

## Exercise 2 – Authentication Outliers
_Focus: Windows Event Log & lookups._
1. Run:
   ```spl
   index=botsv2 sourcetype="WinEventLog:Security" EventCode=4625
   | stats count by user, src, dest
   | sort - count
   ```
   Identify the top failing users. Pivot into a specific host by clicking the user value.
2. Correlate with successful logons to spot brute-force success:
   ```spl
   index=botsv2 sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
   | stats values(EventCode) as events, count by user, src, dest
   | where mvcount(events)=2
   ```
3. Record findings: who got in, from where, and the approximate timeframe.

## Exercise 3 – Endpoint Execution (Sysmon)
_Focus: ProcessCreate and CommandLine.
1. Search for suspicious PowerShell:
   ```spl
   index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
   EventCode=1 Image="*\\powershell.exe"
   | stats count, values(CommandLine) as cmds by host
   | sort - count
   ```
2. Drill into one host’s command lines. Pivot to the parent process:
   ```spl
   index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" host=<HOST>
   | stats values(Image) as Image values(ParentImage) as Parent values(CommandLine) as CommandLine by _time
   | sort _time
   ```
3. Note suspicious parameters (base64, download cradle, encoded command). Capture `_time`, `host`, `ParentImage` for reporting.

## Exercise 4 – Network Beacons (Suricata/PAN)
_Focus: network telemetry correlations._
1. Examine Suricata alerts:
   ```spl
   index=botsv2 sourcetype=suricata:json
   | stats count by alert.signature, src_ip, dest_ip
   | sort - count
   ```
2. For a chosen alert, pivot to firewall logs:
   ```spl
   index=botsv2 sourcetype=pan:traffic dest_ip=<DEST_IP>
   | table _time src_ip dest_ip app threatid action bytes
   ```
3. If available, cross-check DNS:
   ```spl
   index=botsv2 sourcetype=pan:dns dest_ip=<DEST_IP>
   | stats values(query) as domains by src_ip
   ```
4. Summarise the beacon: source host, destination domain/IP, signatures involved.

## Exercise 5 – Exfiltration Clues
_Focus: identify large transfers.
1. Run:
   ```spl
   index=botsv2 sourcetype=pan:traffic action=allow
   | eval mb_out=round(bytes_out/1024/1024,2)
   | where mb_out > 50
   | table _time src_ip dest_ip app action mb_out
   | sort - mb_out
   ```
2. Pivot back to Sysmon for the same `src_ip` and timeframe to identify the process performing the transfer.

## Reporting & Wrap-Up
1. Create a short summary for each exercise: what you found, affected hosts, and recommended next step.
2. Optional: save pivotal searches as reports or dashboard panels for future reuse.
3. Consider exploring additional BOTS v2 scenarios via the Splunk Security Essentials guided content.

## Knowledge Check
1. Which indexes does BOTSv2 introduce and how can you confirm they’re populated?
2. Which SPL command extracts XML fields when add-ons are missing?
3. Name two dashboards/widgets that accelerate BOTS investigations.
4. What SPL helps correlate failed and successful Windows logons for the same user?
5. How do you spot large data transfers in the dataset?

## Next Steps
- Dive into the official BOTS v2 story guide: <https://github.com/splunk/botsv2>
- Install BOTSv3 when you are comfortable and repeat the hunting pattern against multi-cloud data.
- Automate your findings by converting saved searches into alerts or analytics stories.
