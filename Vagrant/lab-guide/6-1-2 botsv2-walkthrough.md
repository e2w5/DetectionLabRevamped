# Lab 6-1-2: BOTSv2 Investigation Guide

## Story So Far
Frothly is a craft beer startup that asked you to investigate a string of suspicious events. Amber Turing (head brewer) has been exchanging emails with rival Berk Beer, the Taedonggang APT keeps surfacing in chatter, and Frothly’s e-commerce site has been processing odd orders. This guide walks you through the 2017 “Boss of the SOC v2” dataset so you can replay the incident, understand the narrative, and answer key questions. Content is adapted from Cyber Security Free Resource’s blog post *Cyberdefenders.org – Boss of the SOC v2 Walkthrough* (February 2022).

## Prepare the Lab
1. **Open DetectionLabRevamped** on your host and move into the Vagrant folder: `cd DetectionLabRevamped/Vagrant`.
2. **Start the Splunk server VM** (named `logger`) if it is not already running: `vagrant up logger`. This boots the Splunk Enterprise instance shipped with DetectionLab.
3. **SSH into the logger VM**: `vagrant ssh logger`. You will land in `/home/vagrant`.
4. **Run the bundled BOTSv2 installer**: `sudo /vagrant/scripts/install-botsv2.sh`. The script installs required Splunk apps and downloads the attack-only BOTSv2 dataset into `/opt/splunk/etc/apps/`. Keep the terminal open until you see `BOTSv2 Installation complete!`.
5. **Restart Splunk and verify ingestion**: `sudo /opt/splunk/bin/splunk restart`. After the restart, browse to `https://logger:8000` (or `https://127.0.0.1:8000` via port forwarding), log in with `admin/changeme`, and run `| eventcount summarize=false index=botsv2`. Roughly 16 million events confirm a successful import.
6. **(Optional) Disable Palo Alto auto lookups when KV Store is unstable**:
   ```bash
   cd /opt/splunk/etc/apps/Splunk_TA_paloalto
   sudo mkdir -p local
   cat <<'EOF' | sudo tee local/props.conf >/dev/null
[pan:traffic]
LOOKUP-minemeldfeeds_dest_lookup =
LOOKUP-minemeldfeeds_src_lookup =

[pan:threat]
LOOKUP-minemeldfeeds_dest_lookup =
LOOKUP-minemeldfeeds_src_lookup =
EOF
   sudo /opt/splunk/bin/splunk restart
   ```
   This override keeps `index=botsv2 sourcetype="pan:traffic"` searches from failing when KV Store is offline. Delete the file later (and restart) to restore default lookups.

---

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
   Link each finding with the date and tone of Amber’s messages—patterns of proprietary data sharing or after-hours contact bolster the insider narrative.

**Phase 1 Answers:** berkbeer.com, Martin Berk, hbernhard@berkbeer.com, Saccharomyces_cerevisiae_patent.docx.

---

## Phase 2 – Breach at brewertalk.com
**Goal:** Reconstruct the external compromise that weaponised Amber’s access.

1. **Spot the hostile scanner.**  
   Frothly runs its customer forum on brewertalk.com; Amber tracks competitors there and adversaries launch reconnaissance from the same site. The firewall logs captured spray-and-pray probes, so isolating the chattiest source IP confirms the attacker’s infrastructure. Plug in the forum IP you discovered during DNS analysis (for example, `52.42.208.228`):
   ```spl
   index=botsv2 sourcetype="stream:http" dest_ip=<brewertalk_IP> | stats count by src_ip | sort -count
   ```
   The top `src_ip` should align with automated probing. Inspect a sample event to confirm the repeated `uri_path` and note the IP; you will pivot off it in later searches.

2. **Confirm SQL injection.**  
   After finding a weak endpoint, the attacker moved into SQL injection to dump user data. Review `_raw` or expand `form_data`; you should see `updatexml` calls against `mybb_users`. Keep each payload open so you can capture Frank Ester’s salt value.
   ```spl
   index=botsv2 sourcetype="stream:http" src_ip=<scanner_IP> uri_path="/member.php" salt "xpath syntax error"
   | reverse
   ```
   The first event shows the `updatexml` payload measuring salt length; the next reveals the salt itself (for example, `gGsxysZL`). Additional events iterate through other users.
   ```spl
   index=botsv2 dest_ip=<brewertalk_IP> uri_path="/member.php" | table _time src_ip form_data
   ```
   Inspect each `form_data` block for `salt` and record which usernames appear. This produces a list of exposed accounts for your breach assessment.

3. **Decode the XSS lure.**  
   With credentials in hand, the adversary planted cross-site scripting to steal session cookies from forum users.
   ```spl
   index=botsv2 sourcetype="stream:http" "kevin" "<script>"
   ```
   Unescape the injected script, extract the banner text (“Daedong”), and capture the stolen cookie value. Pair that cookie with Kevin’s session ID to link the forum compromise to later ransomware staging on his workstation.

**Phase 2 Answers:** hostile IP `45.77.65.211`, URI `/member.php`, SQL function `updatexml`, salt `gGsxysZL`, XSS output “Daedong”, cookie value `1502408189`.

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

## Phase 4 – Taedonggang APT and the Frothly Store Fraud
**Goal:** Tie the phishing kit to Taedonggang infrastructure and expose the later retail fraud scheme.

1. **Unpack the spearphish attachment.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "Malware Alert Text.txt"
   ```
   The campaign began with a malicious invoice. Decode the base64 blob, recover the ZIP, note the password hint, and record the SSL issuer. Also capture file hashes, filenames, and the lure text so malware responders can quarantine matching samples.

2. **Correlate host alerts to shared infrastructure.**
   ```spl
   index=botsv2 sourcetype="stream:dns" <taedonggang_ip>
   ```
   Multiple hosts contacted the same destination; mapping those alerts ties the phishing email to outbound callbacks. Once you know the domain/IP, sweep firewall, proxy, and EDR logs to find every machine that touched it.

3. **Trace the follow-on download.**
   ```spl
   index=botsv2 "winsys32.dll" | table process_name process_path
   ```
   After initial access, Taedonggang staged additional tooling. Follow FTP `RETR` commands to identify the Hangul-named document dropped on the endpoint. Document both the filename and the parent process (for example, `ftp.exe` launched by `cmd.exe`) to show the download was scripted rather than user-driven.

4. **Decode scheduled-task persistence.**
   ```spl
   index=botsv2 sourcetype="WinRegistry" "Taedonggang"
   ```
   The group relies on scheduled tasks for persistence. Decode the PowerShell payload, note the beacon URL, and list any C2 IPs with different first octets. Keep the decoded script and GUIDs—they support attribution. Compare the callback path with Phase 3 indicators to show how the compromise progressed from web to endpoint.

5. **Quantify the store exfiltration.**
   ```spl
   index=botsv2 sourcetype="stream:ftp" method=STOR "successfully transferred"
   ```
   Sum the successful transfers to gauge data loss. Translate the final byte count to MB/GB and pair it with the destination host so leadership understands scale and destination.

6. **Track fraudulent customer sessions.**
   ```spl
   index=botsv2 sourcetype="stream:http" "customer/account/loginPost"
   | rex field=cookie "form_key=(?<session>[^;]+)"
   ```
   The fraud crew used hijacked sessions to place orders. Filter to `dberry398@mail.com`, decode the cookie, and capture the initial session ID. Correlate that session with the timestamp of the first fraudulent order to show exactly when monetisation began.

7. **Identify high-value abuse patterns.**
   ```spl
   index=botsv2 sourcetype="stream:http" dest_content="grand_total"
   | rex "\"grand_total\":\"(?<total>\d+)"
   | where total >= 1000
   | stats values(form_data) by cookie
   ```
   High-dollar orders highlight monetised accounts. Pivot on `/magento2/customer/account/editPost/` to see who edited profiles mid-session. Record each affected address and order total so customer support can coordinate outreach and refunds.

8. **Expose account automation artefacts.**
   ```spl
   index=botsv2 sourcetype="stream:http" "login[username]" "login[password]"
   | rex field=form_data "login\[username\]=(?<user>[^&]+)@(?<domain>[^&]+)"
   ```
   Repeated login attempts expose burner domains, shared passwords, and automation tooling. Use `stats` on `domain`, `pw`, `http_referrer`, and `http_user_agent` to profile them, then share the recurring artefacts with fraud/SRE teams so they can seed blocklists and proactive detections.

**Phase 4 Answers:** `invoice.zip`, SSL issuer `C = US`, IP `160.153.91.7`, domain `hildegardsfarm.com`, document `I_Love_David.hwp`, beacon page `process.php`, unique IP `104.238.159.19`, exfil bytes `1394847505`, session `lwh9Ql7oUbnJUqxR`, high-value buyers `7`, profile editor `bkildcare@yandex.com`, burner domain `elude.in`, coupon `WINTER2017`, shared password `HardwareBasedEasterEggs2017`, top product `http://store.froth.ly/magento2/mens-frothly-tee.html`, fraudulent user agent `Mozilla/5.0 (Windows NT 6.333; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36`.

---

Use this playbook as your field manual: each phase explains why the step matters, the SPL to run, and how to interpret the evidence so you can build a coherent incident narrative.




