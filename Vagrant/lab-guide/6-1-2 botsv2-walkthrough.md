# Lab 6-1-2: BOTSv2 Investigation Guide

## Story So Far
Frothly is a craft beer startup that just asked you to dig into some suspicious activity. Amber Turing, the head brewer, has been sending odd emails to a rival called Berk Beer, the Taedonggang APT keeps getting mentioned, and the Frothly store has started to log strange orders. This guide walks you through the 2017 Boss of the SOC v2 investigation dataset so you can replay the incident, understand what happened, and answer the key questions without getting lost.

## Prepare the Lab
1. **Open DetectionLabRevamped** on your host and move into the Vagrant folder: `cd DetectionLabRevamped/Vagrant`.
2. **Start the Splunk server VM** (named `logger`) if it is not already running: `vagrant up logger`. This boots the Splunk Enterprise instance that DetectionLab ships with.
3. **SSH into the logger VM**: `vagrant ssh logger`. You will land in `/home/vagrant`.
4. **Run the bundled BOTSv2 installer**: `sudo /vagrant/scripts/install-botsv2.sh`. The script installs the required Splunk apps and pulls down the attack-only BOTSv2 dataset into `/opt/splunk/etc/apps/`. Keep the terminal open until you see `BOTSv2 Installation complete!`.
5. **Restart Splunk and verify the index**: `sudo /opt/splunk/bin/splunk restart`. After the restart, browse to `https://logger:8000` (or `https://127.0.0.1:8000` via port forwarding), log in with `admin/changeme`, and run `| eventcount summarize=false index=botsv2`. You should see roughly 16 million events when the ingestion finishes.

---

## Phase 1 - Amber Turing's Insider Prep
**Goal:** Prove Amber exfiltrated intellectual property and prepared covert browsing.

1. **Profile Amber's browsing history.**
   ```spl
   index=botsv2 sourcetype="pan:traffic" amber
   ```
   Note her workstation IP (`10.0.2.101`). Pivot to HTTP traffic:
   ```spl
   index=botsv2 sourcetype="stream:http" src_ip=10.0.2.101 | dedup site | table site
   ```
   -> Answer: Rival domain `berkbeer.com`.
2. **Interrogate her email trail.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "aturing@froth.ly"
   ```
   Review headers and body text to recover:
   - CEO she contacted -> `Martin Berk`
   - Secondary contact -> `hbernhard@berkbeer.com`
   - Attached document -> `Saccharomyces_cerevisiae_patent.docx`
3. **Decode exfil signals hidden in base64.** In the same events, copy the MIME part, decode with `| eval decoded=base64decode(field)` or an external tool to uncover Amber's personal drop:
   -> `ambersthebest@yeastiebeastie.com`
4. **Verify anonymisation tooling.**
   ```spl
   index=botsv2 sourcetype="stream:http" amber "torbrowser"
   ```
   or simply search `amber tor install` to spot the HTTP download log -> Version `7.0.4`.

**Phase 1 Answers:** berkbeer.com, Martin Berk, hbernhard@berkbeer.com, Saccharomyces_cerevisiae_patent.docx, ambersthebest@yeastiebeastie.com, Tor Browser 7.0.4.

---

## Phase 2 - Breach at brewertalk.com
**Goal:** Reconstruct the external compromise that weaponised Amber's access.

1. **Locate infrastructure that touched the forum.**
   ```spl
   index=botsv2 sourcetype="stream:dns" "brewertalk.com" | stats values(answer)
   ```
   -> Public IP `52.42.208.228`.
2. **Spot the hostile scanner.**
   ```spl
   index=botsv2 sourcetype="stream:http" dest_ip=52.42.208.228 | stats count by src_ip | sort -count
   ```
   -> Scanner IP `45.77.65.211` relentlessly probes `/member.php`.
3. **Confirm SQL injection.**
   ```spl
   index=botsv2 dest_ip=52.42.208.228 uri_path="/member.php" | table _time src_ip form_data
   ```
   Payloads call the `updatexml` function. Extract credential dump rows to capture Frank Ester's salt `gGsxysZL`.
4. **Decode the XSS lure.** Search the same HTTP stream for embedded `<script>` tags tied to user Kevin Lagerfield:
   ```spl
   index=botsv2 sourcetype="stream:http" "kevin" "<script>"
   ```
   Unescape the payload to read the banner text "Daedong" and pull the stolen cookie's epoch value `1502408189`.

**Phase 2 Answers:** 52.42.208.228, 45.77.65.211, `/member.php`, `updatexml`, salt `gGsxysZL`, banner "Daedong", cookie value `1502408189`.

---

## Phase 3 - Ransomware Detonation on Frothly Hosts
**Goal:** Track the lateral movement and encryption activity triggered by the phishing chain.

1. **Follow the forged admin creation.**
   ```spl
   index=botsv2 sourcetype="stream:http" "klagerfield" "admin"
   ```
   Inspect `form_data` to capture the anti-CSRF token -> `1bc3eab741900ab25c98eee86bf20feb` and confirm the rogue account username `klagerfield`.
2. **Timeline the encryption window.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "ransom"
   ```
   or pivot from file rename events on Kevin's host to read the precise start `14:50:22` and tally encrypted files via:
   ```spl
   ... | stats count by host
   ```
   -> 132 files hit.
3. **Document USB staging details.**
   ```spl
   index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "DeviceName" "USB"
   ```
   -> Volume label `Alcor` mounted before encryption.
4. **List command-and-control infrastructure.**
   ```spl
   index=botsv2 sourcetype="stream:dns" "eidk"
   ```
   reveals `eidk.duckdns.org` and `eidk.hopto.org` as the sequential beacons.

**Phase 3 Answers:** CSRF token `1bc3eab741900ab25c98eee86bf20feb`, account `klagerfield`, start `14:50:22`, 132 encrypted files, USB label `Alcor`, C2 hosts `eidk.duckdns.org` and `eidk.hopto.org`.

---

## Phase 4 - Taedonggang APT and the Frothly Store Fraud
**Goal:** Tie the phishing kit to Taedonggang infrastructure and expose the later retail fraud scheme.

1. **Unpack the spearphish attachment.**
   ```spl
   index=botsv2 sourcetype="stream:smtp" "Malware Alert Text.txt"
   ```
   Decode the base64 blob to recover `invoice.zip` and note the email's password hint (`912345678`). Extracting the payload shows an SSL certificate issued by `C = US`.
2. **Correlate host alerts to shared infrastructure.** Incident review points to destination IP `160.153.91.7`; DNS logs map it to `hildegardsfarm.com`.
3. **Trace the follow-on download.**
   ```spl
   index=botsv2 "winsys32.dll" | table process_name process_path
   ```
   reveals FTP retrieval of the Korean document `I_Love_David.hwp` (original Hangul file name).
4. **Decode scheduled task persistence.**
   ```spl
   index=botsv2 sourcetype="WinRegistry" "Taedonggang"
   ```
   Extract the encoded PowerShell payload, decode with CyberChef, and identify the beaconed page `process.php`. Among the Taedonggang IPs, `104.238.159.19` is the outlier with a unique first octet.
5. **Quantify the store exfiltration.**
   ```spl
   index=botsv2 sourcetype="stream:ftp" method=STOR "successfully transferred"
   ```
   Parse the byte totals to sum the final upload -> `1394847505` bytes.
6. **Track fraudulent customer sessions.**
   ```spl
   index=botsv2 sourcetype="stream:http" "customer/account/loginPost"
   | rex field=cookie "form_key=(?<session>[^;]+)"
   ```
   Filter to the first visit by `dberry398@mail.com` -> session `lwh9Ql7oUbnJUqxR`.
7. **Identify high-value abuse patterns.**
   ```spl
   index=botsv2 sourcetype="stream:http" dest_content="grand_total"
   | rex "\"grand_total\":\"(?<total>\d+)"
   | where total >= 1000
   | stats values(form_data) by cookie
   ```
   Counting unique users yields `7` distinct buyers. The profile edit URI `/magento2/customer/account/editPost/` ties the culprit email `bkildcare@yandex.com` to one such order.
8. **Expose account automation artifacts.**
   ```spl
   index=botsv2 sourcetype="stream:http" "login[username]" "login[password]"
   | rex field=form_data "login\[username\]=(?<user>[^&]+)@(?<domain>[^&]+)"
   ```
   Domain frequency shows disposable domain `elude.in`. Sorting successful coupon validations (HTTP PUT with `dest_content=true`) identifies the winning code `WINTER2017`. Grouping passwords highlights the shared string `HardwareBasedEasterEggs2017`. Referrer counts point to the product page `http://store.froth.ly/magento2/mens-frothly-tee.html`, and failed coupon spam all use the user agent `Mozilla/5.0 (Windows NT 6.333; Win64; x64) ... Safari/537.36`.

**Phase 4 Answers:** `invoice.zip`, SSL issuer `C = US`, IP `160.153.91.7`, domain `hildegardsfarm.com`, document `I_Love_David.hwp`, beacon page `process.php`, unique IP `104.238.159.19`, exfil bytes `1394847505`, session `lwh9Ql7oUbnJUqxR`, high-value buyers `7`, profile editor `bkildcare@yandex.com`, burner domain `elude.in`, coupon code `WINTER2017`, shared password `HardwareBasedEasterEggs2017`, top product `http://store.froth.ly/magento2/mens-frothly-tee.html`, fraudster user agent `Mozilla/5.0 (Windows NT 6.333; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36`.

---

## Outstanding Gaps
The 2022 blog could not validate Alexa ranking averages (original Q27), Mallory's decrypted photo caption (Q28), or the most common fraudulent shipping street (Q42). If you obtain the missing data sources, slot the findings into the relevant phases above.

Use this condensed playbook as your field manual: each phase walks you from the investigative cue to the SPL to the verified answer without wading through every original BOTSv2 micro-question.
