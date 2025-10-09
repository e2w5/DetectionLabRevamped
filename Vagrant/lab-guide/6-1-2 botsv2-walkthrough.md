# Lab 6-1-2: BOTSv2 Investigation Guide

## Prepare the Lab
1. **Open DetectionLabRevamped** on your host and move into the Vagrant folder: `cd DetectionLabRevamped/Vagrant`.
2. **Start the Splunk server VM** (named `logger`) if it is not already running: `vagrant up logger`. This boots the Splunk Enterprise instance shipped with DetectionLab.
3. **SSH into the logger VM**: `vagrant ssh logger`. You will land in `/home/vagrant`.
4. **Run the bundled BOTSv2 installer**: `sudo /vagrant/scripts/install-botsv2.sh`. The script installs required Splunk apps and downloads the attack-only BOTSv2 dataset into `/opt/splunk/etc/apps/`. Keep the terminal open until you see `BOTSv2 Installation complete!`.
5. **Restart Splunk and verify ingestion**: `sudo /opt/splunk/bin/splunk restart`. After the restart, browse to `https://logger:8000` (or `https://127.0.0.1:8000` via port forwarding), log in with `admin/changeme`, and run `| eventcount summarize=false index=botsv2`. Roughly 16 million events confirm a successful import.
6. **(Optional) Disable Palo Alto auto lookups when KV Store is unstable**:
   ```cd /opt/splunk/etc/apps/Splunk_TA_paloalto
   sudo mkdir -p local
   cat <<'EOF' | sudo tee local/props.conf >/dev/null
   [pan:traffic]
   LOOKUP-minemeldfeeds_dest_lookup =
   LOOKUP-minemeldfeeds_src_lookup =

   [pan:threat]
   LOOKUP-minemeldfeeds_dest_lookup =
   LOOKUP-minemeldfeeds_src_lookup =
   EOF
   sudo /opt/splunk/bin/splunk restart```

This override keeps `index=botsv2 sourcetype="pan:traffic"` searches from failing when KV Store is offline. Delete the file later (and restart) to restore default lookups.

---

## The Background
Frothly is a craft beer startup that asked you to investigate a string of suspicious events. Amber Turing (head brewer) has been exchanging emails with rival Berk Beer, the Taedonggang APT keeps surfacing in chatter, and Frothly’s e-commerce site has been processing odd orders. This guide walks you through the 2017 “Boss of the SOC v2” dataset so you can replay the incident, understand the narrative, and answer key questions. Content is adapted from Cyber Security Free Resource’s blog post *Cyberdefenders.org – Boss of the SOC v2 Walkthrough* (February 2022).

## Dataset & Environment Overview
- **Corporate scenario:** BOTSv2 captures Frothly Brewing’s production environment in late August 2017, including on-prem Active Directory, Apache/MySQL web stacks, cloud services (O365, Azure AD), and the public brewertalk.com forum.
- **Security telemetry:** Palo Alto Networks firewall (`pan:traffic`, `pan:threat`, `pan:system`), Zeek/Stream network captures (`stream:*`), Suricata IDS (`suricata`), Symantec Endpoint Protection (`symantec:ep:*`), Microsoft Sysmon (`xmlwineventlog:microsoft-windows-sysmon/operational`), osquery (`osquery_*`), Linux audit (`auditd`, `linux_audit`), and collectd/perfmon metrics.
- **Endpoint/server logs:** Windows event logs (security, system, application), Active Directory health (`msad:*`), O365 management logs (`ms:o365:management`), Apache access/error, MySQL stats (`mysql:*`), PowerShell transcript records, and Autoruns inventories.
- **Distribution:** Provided as a pre-indexed Splunk app (`botsv2_data_set_attack_only.tgz` or full dataset). Install by extracting into `$SPLUNK_HOME/etc/apps/` and restarting Splunk; search via `index=botsv2 earliest=0`.





## Phase 1 – Amber Turing’s Insider Prep
**Goal:** Prove Amber exfiltrated intellectual property and prepared covert browsing.

1. **Profile Amber’s browsing history.**
   ```spl
   index=botsv2 sourcetype="pan:traffic" amber
   ```
   Identify Amber’s workstation IP from the field sidebar, then pivot into HTTP traffic:
   ```spl
   index=botsv2 sourcetype="stream:http" src_ip=<Amber_IP> | dedup site | table site
   ```
   Sort the `site` column, filter out routine services, and highlight rival brewery domains. Record suspicious destinations (and timestamps) for correlation with later email and download activity.

2. **Interrogate her email trail.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "aturing@froth.ly"
   ```
   Open the earliest thread with Berk Beer and:
   - Capture the CEO’s name from the email signature.
   - Record the secondary contact email Martin provides.
   - Expand attachment metadata (for example, `attach_filename{}`) to log the document Amber sent.
   Link each finding with the date and tone of Amber's messages; patterns of proprietary data sharing or after-hours contact bolster the insider narrative.

**Phase 1 Answers:** berkbeer.com, Martin Berk, hbernhard@berkbeer.com, Saccharomyces_cerevisiae_patent.docx.

---

## Phase 2 - Breach at brewertalk.com
**Goal:** Reconstruct the external compromise that weaponised Amber's access.

1. **Spot the hostile scanner.**  
   Frothly runs its customer forum on brewertalk.com; Amber tracks competitors there and adversaries launch reconnaissance from the same site. The firewall logs captured spray-and-pray probes, so isolating the chattiest source IP confirms the attacker's infrastructure. Plug in the forum IP you discovered during DNS analysis (for example, `52.42.208.228`):
   ```spl
   index=botsv2 sourcetype="stream:http" dest_ip=<brewertalk_IP> | stats count by src_ip | sort -count
   ```
   The top `src_ip` should align with automated probing. Inspect a sample event to confirm the repeated `uri_path` and note the IP; you will pivot off it in later searches.

2. **Confirm SQL injection.**  
   After finding a weak endpoint, the attacker moved into SQL injection. Review `_raw` or expand `form_data`; you should see `updatexml()` calls that target the `mybb_users` table. MyBB runs on MySQL, and the attacker weaponises MySQL's `updatexml()` by concatenating the query result into the XML payload and deliberately breaking the XML syntax. MySQL then throws an "XPath syntax error" that echoes the requested data in clear text, effectively dumping the field you asked for. Keep each payload open so you can capture Frank Ester's salt value.
   ```spl
   index=botsv2 sourcetype="stream:http" src_ip=<scanner_IP> uri_path="/member.php" salt "xpath syntax error"
   | reverse
   ```
   The first event shows the `updatexml` payload measuring salt length; the next reveals the salt itself (for example, `gGsxysZL`) inside the XPath error returned by MySQL. Additional events iterate through other users.
   ```spl
   index=botsv2 dest_ip=<brewertalk_IP> uri_path="/member.php" | table _time src_ip form_data
   ```
   Inspect each `form_data` block for `salt` and record which usernames appear. This produces a list of exposed accounts for your breach assessment. Pair the salt with the hashed password in the same payload to reconstruct forum credentials—those logins are what the adversary later uses to plant client-side attacks.

3. **Decode the XSS lure.**  
   With forum credentials in hand, the adversary planted cross-site scripting to steal session cookies from forum users. They do this because a stolen cookie grants access even if passwords are reset, letting them impersonate trusted users and preserve persistence. The injected `<script>` runs in each visitor's browser, calls `document.cookie`, and exfiltrates the stolen session back to the attacker's host. This lets the attacker reuse authenticated sessions without logging in, so capturing the script and stolen value is crucial for tracing their persistence.
   ```spl
   index=botsv2 sourcetype="stream:http" "kevin" "<script>"
   ```
   Unescape the injected script to confirm the banner text ("Daedong"), then note how the code posts `document.cookie` to the attacker-controlled URL. Session cookies identify a user to MyBB; once the attacker replays Kevin's cookie, they can act as him inside the forum, replay the anti-CSRF token, and create the rogue `klagerfield` admin account that ultimately hosts the malicious invoice Kevin downloads. Pair the stolen cookie with Kevin's session ID to show how the forum compromise set up the later endpoint breach.

**Phase 2 Answers:** hostile IP `45.77.65.211`, URI `/member.php`, SQL function `updatexml`, salt `gGsxysZL`, cookie value `1502408189`.

---

## Phase 3 – Ransomware Detonation on Frothly Hosts
**Goal:** Track lateral movement and encryption activity triggered by the phishing chain.

1. **Follow the forged admin creation.**
   ```spl
   index=botsv2 sourcetype="stream:http" "klagerfield" "admin"
   ```
   The forum breach let the attacker pivot inside Frothly and issue an admin creation request. Capture the `form_data` containing the anti-CSRF token and confirm the rogue `klagerfield` account. Note the requester IP, user agent, and timestamp—they tie back to the web infrastructure from Phase 2.

2. **Timeline the encryption window.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "ransom"
   ```
   Pivot into file-rename events on Kevin’s host, identify the earliest encryption timestamp, and calculate counts with `stats count by host` (or `dc(TargetFilename)`).
   Compare these times with SOC alerts or EDR telemetry; any delay highlights detection gaps to document.

3. **Document USB staging details.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "DeviceName" "USB"
   ```
   The incident narrative references a suspicious thumb drive. Review `DeviceName` and `Volume` to confirm which device mounted right before encryption. Check whether the same device ID appears on other hosts to assess spread.

4. **List command-and-control infrastructure.**
   ```spl
   index=botsv2 sourcetype="stream:dns" "eidk"
   ```
   Each beacon reveals C2 hosts you can block or hunt for elsewhere. Enumerate all returned hostnames/IPs and enrich them with WHOIS or threat intelligence where possible.

**Phase 3 Answers:** CSRF token `1bc3eab741900ab25c98eee86bf20feb`, account `klagerfield`, encryption start `14:50:22`, 132 encrypted files, USB label `Alcor`, C2 hosts `eidk.duckdns.org` and `eidk.hopto.org`.

---





