# Lab 6-1-2: BOTSv2 Investigation Guide

## Story So Far
Frothly is a craft beer startup that just asked you to dig into some suspicious activity. Amber Turing, the head brewer, has been sending odd emails to a rival called Berk Beer, the Taedonggang APT keeps getting mentioned, and the Frothly store has started to log strange orders. This guide walks you through the 2017 Boss of the SOC v2 investigation dataset so you can replay the incident, understand what happened, and answer the key questions without getting lost. The searches and answers below are adapted from Cyber Security Free Resource's blog post 'Cyberdefenders.org - Boss of the SOC v2 Walkthrough' (February 2022).

## Prepare the Lab
1. **Open DetectionLabRevamped** on your host and move into the Vagrant folder: `cd DetectionLabRevamped/Vagrant`.
2. **Start the Splunk server VM** (named `logger`) if it is not already running: `vagrant up logger`. This boots the Splunk Enterprise instance that DetectionLab ships with.
3. **SSH into the logger VM**: `vagrant ssh logger`. You will land in `/home/vagrant`.
4. **Run the bundled BOTSv2 installer**: `sudo /vagrant/scripts/install-botsv2.sh`. The script installs the required Splunk apps and pulls down the attack-only BOTSv2 dataset into `/opt/splunk/etc/apps/`. Keep the terminal open until you see `BOTSv2 Installation complete!`.
5. **Restart Splunk and verify the index**: `sudo /opt/splunk/bin/splunk restart`. After the restart, browse to `https://logger:8000` (or `https://127.0.0.1:8000` via port forwarding), log in with `admin/changeme`, and run `| eventcount summarize=false index=botsv2`. You should see roughly 16 million events when the ingestion finishes.
6. **(Optional) Disable Palo Alto auto lookups if KV Store is unstable**:
   `ash
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
   `
   This override keeps searches such as index=botsv2 sourcetype="pan:traffic" from failing when the KV Store is offline. Delete the file later (and restart Splunk) to restore the default lookup behaviour.

---

## Phase 1 - Amber Turing's Insider Prep
**Goal:** Prove Amber exfiltrated intellectual property and prepared covert browsing.

1. **Profile Amber's browsing history.**
   ```spl
   index=botsv2 sourcetype="pan:traffic" amber
   ```
   In the field sidebar, note the `src_ip` value (Amber's workstation) and pivot into HTTP traffic:
   ```spl
   index=botsv2 sourcetype="stream:http" src_ip=<Amber_IP> | dedup site | table site
   ```
   Sort the `site` column, filter out routine services, and flag any rival brewery domains that appear.

2. **Interrogate her email trail.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "aturing@froth.ly"
   ```
   Open the earliest thread with Berk Beer and:
   - Capture the CEO's name from the signature block in the replies.
   - Record the secondary contact email address that Martin forwards to Amber.
   - Expand attachment metadata (e.g., `attach_filename{}`) to log the document Amber transmitted.


**Phase 1 Answers:** berkbeer.com, Martin Berk, hbernhard@berkbeer.com, Saccharomyces_cerevisiae_patent.docx.

## Phase 2 - Breach at brewertalk.com
**Goal:** Reconstruct the external compromise that weaponised Amber's access.

1. **Locate infrastructure that touched the forum.**
   ```spl
   index=botsv2 sourcetype="stream:dns" "brewertalk.com" | stats values(answer)
   ```
   After the results populate, run `| stats count by answer` (or simply sort the table) to see how many unique DNS responses you captured. The most frequent IPv4 in the `answer` field is the live address brewertalk.com resolved to during the compromise - record that value and keep the search handy in case you need to watch for TTL or resolution changes later.

2. **Spot the hostile scanner.**
   ```spl
   index=botsv2 sourcetype="stream:http" dest_ip=<brewertalk_IP> | stats count by src_ip | sort -count
   ```
   The top source IP should align with automated probing; drill into a sample event to confirm which URI path it repeatedly targeted.

3. **Confirm SQL injection.**
   ```spl
   index=botsv2 dest_ip=<brewertalk_IP> uri_path="/member.php" | table _time src_ip form_data
   ```
   Inspect the `form_data` payloads to identify the SQL function being abused and capture the credential dump rows containing Frank Ester's salt value.

4. **Decode the XSS lure.**
   ```spl
   index=botsv2 sourcetype="stream:http" "kevin" "<script>"
   ```
   Unescape the injected script to read the banner text it displays and pull the stolen cookie's epoch value from the associated request headers.


**Phase 2 Answers:** 52.42.208.228, 45.77.65.211, `/member.php`, `updatexml`, salt `gGsxysZL`, banner "Daedong", cookie value `1502408189`.

---

## Phase 3 - Ransomware Detonation on Frothly Hosts
**Goal:** Track the lateral movement and encryption activity triggered by the phishing chain.

1. **Follow the forged admin creation.**
   ```spl
   index=botsv2 sourcetype="stream:http" "klagerfield" "admin"
   ```
   Examine `form_data` to capture the anti-CSRF token used and confirm the rogue `klagerfield` account that was added.

2. **Timeline the encryption window.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "ransom"
   ```
   Pivot into file rename events on Kevin's host, note the first timestamp when encryption starts, and use `stats count by host` (or `dc(TargetFilename)`) to measure how many files were touched.

3. **Document USB staging details.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "DeviceName" "USB"
   ```
   Review the `DeviceName` and `Volume` fields to record which removable media label appeared just before encryption began.

4. **List command-and-control infrastructure.**
   ```spl
   index=botsv2 sourcetype="stream:dns" "eidk"
   ```
   Capture every hostname returned so you can enumerate the full set of C2 endpoints contacted during the attack.


**Phase 3 Answers:** CSRF token `1bc3eab741900ab25c98eee86bf20feb`, account `klagerfield`, start `14:50:22`, 132 encrypted files, USB label `Alcor`, C2 hosts `eidk.duckdns.org` and `eidk.hopto.org`.

---

## Phase 4 - Taedonggang APT and the Frothly Store Fraud
**Goal:** Tie the phishing kit to Taedonggang infrastructure and expose the later retail fraud scheme.

1. **Unpack the spearphish attachment.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "Malware Alert Text.txt"
   ```
   Decode the base64 blob to recover the ZIP, note the password hint embedded in the email body, and record the SSL issuer revealed once you inspect the extracted payload.

2. **Correlate host alerts to shared infrastructure.**
   Use the incident review dashboard or search:
   ```spl
   index=botsv2 sourcetype="stream:dns" <taedonggang_ip>
   ```
   to map the destination IP back to its domain and add it to your indicator list.

3. **Trace the follow-on download.**
   ```spl
   index=botsv2 "winsys32.dll" | table process_name process_path
   ```
   Follow the FTP `RETR` commands to identify the unusual document (including its Hangul filename) that was staged inside Frothly.

4. **Decode scheduled task persistence.**
   ```spl
   index=botsv2 sourcetype="WinRegistry" "Taedonggang"
   ```
   Extract the encoded PowerShell payload, decode it with CyberChef, and note the web page it repeatedly calls as well as any C2 IPs that differ in their first octet.

5. **Quantify the store exfiltration.**
   ```spl
   index=botsv2 sourcetype="stream:ftp" method=STOR "successfully transferred"
   ```
   Parse the `reply_content` field to total the volume of data that successfully left the environment during the final exfiltration attempt.

6. **Track fraudulent customer sessions.**
   ```spl
   index=botsv2 sourcetype="stream:http" "customer/account/loginPost"
   | rex field=cookie "form_key=(?<session>[^;]+)"
   ```
   Filter to the first visit by `dberry398@mail.com`, decode the cookie string, and note the session identifier assigned on first login.

7. **Identify high-value abuse patterns.**
   ```spl
   index=botsv2 sourcetype="stream:http" dest_content="grand_total"
   | rex "\"grand_total\":\"(?<total>\d+)"
   | where total >= 1000
   | stats values(form_data) by cookie
   ```
   Count the unique users placing orders over $1000 and pivot on `/magento2/customer/account/editPost/` to determine who edited their profile mid-session before purchasing.

8. **Expose account automation artifacts.**
   ```spl
   index=botsv2 sourcetype="stream:http" "login[username]" "login[password]"
   | rex field=form_data "login\[username\]=(?<user>[^&]+)@(?<domain>[^&]+)"
   ```
   Use `stats` on `domain`, `pw`, `http_referrer`, and `http_user_agent` to spot burner email domains, the most successful coupon code, shared passwords across accounts, the top product page before checkout, and the user agent tied to failed coupon spamming.


**Phase 4 Answers:** `invoice.zip`, SSL issuer `C = US`, IP `160.153.91.7`, domain `hildegardsfarm.com`, document `I_Love_David.hwp`, beacon page `process.php`, unique IP `104.238.159.19`, exfil bytes `1394847505`, session `lwh9Ql7oUbnJUqxR`, high-value buyers `7`, profile editor `bkildcare@yandex.com`, burner domain `elude.in`, coupon code `WINTER2017`, shared password `HardwareBasedEasterEggs2017`, top product `http://store.froth.ly/magento2/mens-frothly-tee.html`, fraudster user agent `Mozilla/5.0 (Windows NT 6.333; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36`.

---

Use this condensed playbook as your field manual: each phase walks you from the investigative cue to the SPL to the verified answer without wading through every original BOTSv2 micro-question.
















