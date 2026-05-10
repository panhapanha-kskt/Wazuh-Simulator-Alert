# 🛡️ Wazuh Platform

> **CBSA Project — Group 7 | Blue Team Operations Center**  

A unified Security Operations Center (SOC) monitoring and automated defense platform built on top of Wazuh SIEM, integrating Zeek network analysis, Cilium Tetragon runtime security, VirusTotal threat intelligence, and a real-time SOAR engine with Gmail alerting.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Components](#components)
  - [Wazuh Manager](#1-wazuh-manager)
  - [Wazuh Agent (Kali)](#2-wazuh-agent-kali)
  - [Custom Detection Rules](#3-custom-detection-rules)
  - [SOC Monitoring Engine](#4-soc-monitoring-engine-monitoringpy)
  - [SOC Alert Simulator](#5-soc-alert-simulator-soc_alert_simulatorpy)
- [Detection Coverage](#detection-coverage)
- [SOAR Automated Responses](#soar-automated-responses)
- [Email Alerting](#email-alerting)
- [REST API Reference](#rest-api-reference)
- [Setup & Installation](#setup--installation)
- [Running the Platform](#running-the-platform)
- [Testing with the Simulator](#testing-with-the-simulator)
- [Log Sources](#log-sources)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Security Notes](#security-notes)

---

## Overview

This platform extends Wazuh's default capabilities with:

- **Multi-source log interception** — tails Wazuh alerts, Zeek, Tetragon, Apache2, Nginx, and active-response logs simultaneously
- **Rule-based classification** — exact match against custom rule tables (CRITICAL / HIGH / MEDIUM / LOW) before falling back to Wazuh numeric levels
- **SOAR engine** — automatically blocks IPs via `firewall-drop`, disables compromised accounts, and quarantines suspicious files
- **HTML Gmail alerts** — richly formatted email notifications for all MEDIUM+ severity events
- **Flask REST API** — exposes alert data and metrics to the SOC Dashboard v2 frontend on port `5050`
- **SQLite persistence** — all alerts, IP blocks, and health history stored locally
- **Safe rule validation** — `soc_alert_simulator.py` triggers every custom rule without executing real attacks

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NETWORK LAYER                            │
│   Zeek (passive tap)          Tetragon (eBPF kernel hooks)      │
│         │                              │                        │
│         ▼                              ▼                        │
│  /opt/zeek/logs/current/    /var/log/tetragon/tetragon.log      │
└────────────────────┬───────────────────┬────────────────────────┘
                     │                   │
┌────────────────────▼───────────────────▼────────────────────────┐
│                    WAZUH AGENT  (192.168.200.130 — Kali)        │
│                                                                  │
│  syscheck (FIM) · rootcheck · SCA · syscollector                │
│  localfile collectors: Zeek, Tetragon, Apache2, Nginx, journald │
│                                                                  │
│  Active Response: firewall-drop (rules 651, 5763, 100200…)      │
└──────────────────────────────┬──────────────────────────────────┘
                               │ TCP 1514 (encrypted)
┌──────────────────────────────▼──────────────────────────────────┐
│                  WAZUH MANAGER  (192.168.200.129)               │
│                                                                  │
│  ossec.conf · local_rules.xml · zeek_rules.xml                  │
│  700000-tetragon.xml · malware-hashes · blacklist-alienvault    │
│                                                                  │
│  VirusTotal integration · Vulnerability detection               │
│  → /var/ossec/logs/alerts/alerts.json                           │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│              SOC MONITORING ENGINE  (monitoring.py)             │
│                                                                  │
│  LogInterceptor  →  AlertProcessor  →  EmailNotifier            │
│       │                   │                    │                 │
│  reads 6 log         SOAR actions         Gmail HTML            │
│  sources live        (block/lock/         (MEDIUM+)             │
│                       quarantine)                               │
│                           │                                      │
│                    SQLite DB + deque                            │
│                           │                                      │
│              Flask REST API  :5050                              │
│                           │                                      │
│              SOC Dashboard v2  :8080                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
wazuh-soc-platform/
│
├── manager/                          # Files deployed on Wazuh Manager (192.168.200.129)
│   ├── etc/
│   │   ├── ossec.conf                # Main Wazuh manager configuration
│   │   ├── rules/
│   │   │   ├── local_rules.xml       # Custom detection rules (SSH, RDP, malware, IP blocklist)
│   │   │   ├── zeek_rules.xml        # Zeek network event rules (100900–100907)
│   │   │   └── 700000-tetragon.xml   # Cilium Tetragon container rules (700000–700006)
│   │   └── lists/
│   │       ├── malware-hashes        # MD5 hash blocklist (FIM integration)
│   │       ├── malicious-ioc/
│   │       │   ├── malicious-ip      # Known malicious IPs
│   │       │   └── malicious-domains # Known malicious domains
│   │       └── blacklist-alienvault  # AlienVault OTX IP reputation blocklist
│
├── agent/                            # Files deployed on Kali agent (192.168.200.130)
│   └── etc/
│       └── ossec.conf                # Agent configuration (FIM, Zeek, Tetragon, active response)
│
├── monitoring/                       # SOC engine — runs on the Wazuh manager
│   ├── monitoring.py                 # Main SOC Defense Platform v3 (this file)
│   └── soc_simulator.log             # Auto-generated simulator run log
│
├── tools/
│   └── soc_alert_simulator.py        # Safe rule validation / alert trigger tool
│
├── dashboard/
│   └── dashboard-V2.html             # SOC Dashboard v2 frontend (served on :8080)
│
└── README.md                         # This file
```

---

## Components

### 1. Wazuh Manager

**File:** `manager/etc/ossec.conf`  
**Host:** `192.168.200.129`

Key configuration sections:

| Section | Description |
|---|---|
| `<remote>` | Listens on TCP 1514 for agent traffic |
| `<rootcheck>` | Rootkit and trojan detection every 12 hours |
| `<syscheck>` | File Integrity Monitoring on `/etc`, `/usr/bin`, `/bin`, `/sbin`, `/boot` |
| `<vulnerability-detection>` | CVE feeds for Ubuntu, Debian, RHEL, Amazon Linux, SUSE, Windows |
| `<integration>` VirusTotal | Scans FIM-flagged files via VirusTotal API |
| `<indexer>` | Ships alerts to OpenSearch on port 9200 (TLS) |
| `<auth>` | Agent enrollment on port 1515 |
| `<active-response>` | `netsh` active response for RDP brute-force rules 100100, 100200, 100500 |

**Vulnerability providers enabled:**

```
canonical (Ubuntu) · debian · redhat · alas (Amazon Linux)
suse · arch · almalinux · msu (Windows) · nvd (NVD aggregate)
```

---

### 2. Wazuh Agent (Kali)

**File:** `agent/etc/ossec.conf`  
**Host:** `192.168.200.130`  
**Agent Name:** `TSC-Agent`

Key additions beyond the default agent config:

| Feature | Detail |
|---|---|
| FIM — Downloads | `whodata=yes, check_all=yes` on `/home/kali/Downloads` |
| FIM — Videos | `realtime=yes` on `/home/kali/Videos` |
| Zeek log collection | `json` format from `/opt/zeek/logs/current/*.log` |
| Tetragon collection | `json` format from `/var/log/tetragon/tetragon.log` |
| Active Response | `firewall-drop` triggered by rules 651, 5763, 100200, 5712, 5758, 5503 (180s timeout) |
| Web logs | Apache2 and Nginx access/error logs (apache + syslog formats) |

---

### 3. Custom Detection Rules

#### `local_rules.xml`

| Rule ID | Level | Trigger | Description |
|---|---|---|---|
| 100001 | 5 | SSH fail from 1.1.1.1 | SSH auth failure from specific IP |
| 100100 | 10 | 3 RDP fails in 120s | RDP brute-force on Windows 10 |
| 110002 | 13 | FIM + MD5 match | File with known malware hash detected |
| 100200 | 10 | Web attack + AlienVault blocklist | IP found in AlienVault reputation DB |
| 100300 | 12 | `firewall-drop` in log | Active response execution confirmed |

#### `zeek_rules.xml`

| Rule ID | Level | Zeek Event | Description |
|---|---|---|---|
| 100900 | 0 | Any JSON | Base Zeek alert (parent rule) |
| 100901 | 5 | DNS query | DNS query logged with resolution |
| 100902 | 0 | mDNS (port 5353) | Benign mDNS — suppressed |
| 100903 | 7 | `conn_state: REJ` | Single rejected connection |
| 100904 | 10 | 5× REJ in 20s | Port scan detected |
| 100905 | 0 | cti.wazuh.com DNS | Suppressed — internal Wazuh CTI |
| 100906 | 8 | Self-signed cert | SSL self-signed certificate |
| 100907 | 12 | Expired cert | SSL expired certificate |

#### `700000-tetragon.xml`

| Rule ID | Level | Event Type | Description |
|---|---|---|---|
| 700000 | 3 | `process_exec` | Any process execution (base) |
| 700001 | 3 | `process_exit` | Process exit detected |
| 700002 | 3 | `process_kprobe` | Kernel probe detected |
| 700003 | 5 | `process_exit` + status | Error exit code detected |
| 700004 | 8 | exec bash/sh/zsh | Shell execution in container |
| 700005 | 7 | exec wget/curl | Remote fetch inside container |
| 700006 | 7 | exec apt/yum/dpkg/rpm/apk | Package install inside container |

---

### 4. SOC Monitoring Engine (`monitoring.py`)

The main platform process. Run on the Wazuh manager.

#### Sub-systems

**`LogInterceptor`** — Tails all log sources every `POLL_INTERVAL` (15s):

| Source | Path | Parser |
|---|---|---|
| Wazuh alerts | `/var/ossec/logs/alerts/alerts.json` | Full JSON alert parsing |
| Zeek | `/opt/zeek/logs/current/*.log` | Per-log-type mapping to rules 100900–100907 |
| Tetragon | `/var/log/tetragon/tetragon.log` | Process event → rules 700000–700006 |
| Active Response | `/var/ossec/logs/active-responses.log` | Regex match for firewall-drop/account-disable |
| Apache2 | `/var/log/apache2/access.log` + error | SQLi, path traversal, XSS, scanner detection |
| Nginx | `/var/log/nginx/access.log` + error | Same attack pattern detection |

**`AlertProcessor`** — SOAR pipeline per alert:

```
Incoming alert
    │
    ├─ Skip level=0 or whitelisted rules
    ├─ Brute-force escalation (track srcip failed logins in SQLite)
    ├─ Deduplication (5-min window per rule_id+srcip)
    ├─ SOAR: firewall-drop (ACTIVE_RESPONSE_RULES set)
    ├─ SOAR: account-disable (ACCOUNT_DISABLE_RULES set)
    ├─ SOAR: file quarantine (QUARANTINE_RULES set)
    ├─ Gmail HTML email (CRITICAL / HIGH / MEDIUM only)
    └─ Persist to SQLite + push to in-memory ring buffer
```

**`ServiceMonitor`** — Checks `wazuh-manager`, `wazuh-dashboard`, `filebeat` via `systemctl` every 60s.

**`AgentMonitor`** — Polls `/var/ossec/bin/agent_control -l` every 5 minutes.

**`DiskMonitor`** — Checks disk usage on alerts, archives, queue, and backup dirs every 10 minutes. Warns at 80%, alerts at 90%.

**`EmailNotifier`** — Sends HTML emails via Gmail SMTP (TLS on port 587). Cooldown of 5 minutes per rule+IP pair to prevent inbox flooding.

---

### 5. SOC Alert Simulator (`soc_alert_simulator.py`)

A **safe, non-destructive** testing tool that validates your detection pipeline end-to-end. Run on the Kali agent.

| Test Key | Rule | Level | Method |
|---|---|---|---|
| `110002` | 110002 | 13 CRITICAL | Drops EICAR-variant test file into `/home/kali/Downloads` |
| `100300` | 100300 | 12 HIGH | Appends `firewall-drop` line to active-responses log |
| `700004` | 700004 | 8 MEDIUM | Injects fake Tetragon bash exec JSON to tetragon.log |
| `700005` | 700005 | 7 MEDIUM | Injects fake Tetragon curl JSON to tetragon.log |
| `100904` | 100904 | 10 HIGH | Writes 6 REJ conn entries to Zeek conn.log (loopback IPs only) |
| `100907` | 100907 | 12 HIGH | Writes expired-cert SSL entry to Zeek ssl.log |
| `ssh` | 5712 | 5 LOW | Runs `ssh` with invalid user to localhost (real sshd log) |

**Safety guarantees:**
- No real network attacks — loopback only
- No real malware — EICAR test pattern only
- All log injections tagged `[SOC-SIM]` / `_soc_sim: true`
- Test files auto-deleted after 30 seconds
- `--dry-run` mode prints every action without writing anything

---

## Detection Coverage

### Severity Classification

| Severity | Wazuh Level | Email | SOAR |
|---|---|---|---|
| CRITICAL | 13–15 | ✅ | ✅ Block + Quarantine |
| HIGH | 10–12 | ✅ | ✅ Block |
| MEDIUM | 7–9 | ✅ | Conditional |
| LOW | 4–6 | ❌ | ❌ |
| INFO | 0–3 | ❌ | ❌ |

### Threat Categories Covered

- SSH / RDP brute-force
- Web attacks (SQLi, Path Traversal, XSS, web scanners)
- File integrity violations + malware hash detection
- Container runtime anomalies (shell exec, remote fetch, package install)
- Network anomalies (port scans, rejected connections)
- SSL/TLS issues (self-signed, expired certificates)
- IP reputation (AlienVault OTX, malicious-ioc lists)
- Active response confirmation logging
- Vulnerability management (CVE feeds for 9 OS families)

---

## SOAR Automated Responses

| Action | Script | Trigger Rules | Timeout |
|---|---|---|---|
| `firewall-drop` | `/var/ossec/active-response/bin/firewall-drop` | SSH brute-force, web attacks, blocklist hits, TOR nodes | 3600s |
| `disable-account` | `/var/ossec/active-response/bin/disable-account` | SSH brute-force confirmed (rule 100901) | 300s |
| `file-quarantine` | `/var/ossec/active-response/bin/quarantine-file.sh` | Reverse shell tools, critical file mods (rules 100101, 550, 100117) | — |
| `netsh` (Windows) | `route-null.exe` | RDP brute-force (rules 100100, 100200, 100500) | — |

---

## Email Alerting

Alerts are sent via Gmail SMTP to `sopanha.tith@student.cadt.edu.kh` for all events at level ≥ 7 (MEDIUM and above).

Each HTML email includes:

- Severity badge and level indicator
- Rule ID, description, and classification reason
- Agent name, IP, source IP, destination IP
- Log source and location
- Groups and MITRE ATT&CK technique links
- Automated SOAR actions taken
- Raw log excerpt (truncated to 700 chars)
- Analyst checklist
- VirusTotal and MITRE Navigator quick-links

A 5-minute cooldown per rule+IP pair prevents duplicate emails during sustained attacks.

---

## REST API Reference

The engine exposes a REST API on port **5050** consumed by SOC Dashboard v2.

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Engine liveness check |
| `/api/alerts` | GET | Paginated alert list with filters |
| `/api/metrics` | GET | Severity counts, SOAR stats, source breakdown |
| `/api/agents` | GET | Agent online/offline status |
| `/api/config` | GET | Runtime configuration dump |
| `/api/send_alert` | POST | Manually dispatch an alert email |

### `/api/alerts` Query Parameters

| Parameter | Type | Example | Description |
|---|---|---|---|
| `limit` | int | `200` | Max alerts to return |
| `min_level` | int | `7` | Filter by minimum Wazuh level |
| `severity` | string | `HIGH` | Filter by severity label |
| `source` | string | `zeek` | Filter by log source prefix |
| `search` | string | `192.168` | Free-text search across fields |

---

## Setup & Installation

### Prerequisites

| Component | Version | Host |
|---|---|---|
| Wazuh Manager | 4.x | 192.168.200.129 (Amazon Linux 2023) |
| Wazuh Agent | 4.x | 192.168.200.130 (Kali Linux) |
| Python | 3.10+ | Wazuh Manager |
| Zeek | 6.x | Kali Agent |
| Cilium Tetragon | Latest | Kali Agent |
| OpenSearch | 2.x | Wazuh Manager (port 9200) |

### Python Dependencies

```bash
pip install flask flask-cors requests
```

### One-Time Manager Setup

**1. Add the EICAR test hash to the malware-hashes list** (required for rule 110002 testing):
```bash
sudo bash -c 'echo "<MD5_FROM_SIMULATOR>:EICAR_SOC_SIM" >> \
    /var/ossec/etc/lists/malware-hashes'
```

**2. Reload Wazuh lists:**
```bash
sudo /var/ossec/bin/wazuh-maild -f
```

**3. Set up Gmail App Password** — go to your Google account → Security → App Passwords and generate a password for "Mail". Use that as `GMAIL_PASS`.

**4. Create backup directory:**
```bash
sudo mkdir -p /home/wazuh-user/backup/log
sudo chown -R wazuh:wazuh /home/wazuh-user/backup
```

**5. Copy custom rules to the manager:**
```bash
sudo cp local_rules.xml      /var/ossec/etc/rules/
sudo cp zeek_rules.xml       /var/ossec/etc/rules/
sudo cp 700000-tetragon.xml  /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-control restart
```

---

## Running the Platform

### Start the Monitoring Engine (on manager)

```bash
# With environment variables for credentials
export GMAIL_USER=sop98886@gmail.com
export GMAIL_PASS=your_app_password_here
export ALERT_TO=sopanha.tith@student.cadt.edu.kh

sudo python3 monitoring.py
```

### Run as a Systemd Service (recommended)

```ini
# /etc/systemd/system/soc-monitor.service
[Unit]
Description=Wazuh SOC Defense Platform v3
After=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/soc-platform
Environment=GMAIL_USER=sop98886@gmail.com
Environment=GMAIL_PASS=your_app_password
Environment=ALERT_TO=sopanha.tith@student.cadt.edu.kh
ExecStart=/usr/bin/python3 monitoring.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-monitor
sudo journalctl -u soc-monitor -f
```

---

## Testing with the Simulator

Run on the **Kali agent** (192.168.200.130) as root.

```bash
# List all available tests
sudo python3 soc_alert_simulator.py --list

# Dry-run — see what would happen without writing anything
sudo python3 soc_alert_simulator.py --dry-run

# Run all tests
sudo python3 soc_alert_simulator.py

# Run a single rule test
sudo python3 soc_alert_simulator.py --rule 700004
sudo python3 soc_alert_simulator.py --rule 100904
sudo python3 soc_alert_simulator.py --rule 110002
```

### Verifying Results

After running the simulator, check these locations:

```bash
# Wazuh alert stream (manager)
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool

# SOC engine REST API
curl http://localhost:5050/api/alerts?min_level=7 | python3 -m json.tool

# Blocked IPs
cat /home/wazuh-user/backup/log/firewall.log

# Engine console output
sudo journalctl -u soc-monitor -f

# Clean up simulator tags from Tetragon log
grep -v SOC-SIM /var/log/tetragon/tetragon.log > /tmp/t.log
sudo mv /tmp/t.log /var/log/tetragon/tetragon.log
```

---

## Log Sources

| Log File | Format | Parsed By | Rules Triggered |
|---|---|---|---|
| `/var/ossec/logs/alerts/alerts.json` | Wazuh JSON | `read_wazuh_alerts()` | All custom rules |
| `/opt/zeek/logs/current/conn.log` | Zeek JSON | `read_zeek_logs()` | 100903, 100904 |
| `/opt/zeek/logs/current/ssl.log` | Zeek JSON | `read_zeek_logs()` | 100906, 100907 |
| `/opt/zeek/logs/current/dns.log` | Zeek JSON | `read_zeek_logs()` | 100901, 100905 |
| `/opt/zeek/logs/current/http.log` | Zeek JSON | `read_zeek_logs()` | 100900 |
| `/var/log/tetragon/tetragon.log` | JSON | `read_tetragon_logs()` | 700000–700006 |
| `/var/ossec/logs/active-responses.log` | Syslog | `read_active_response_log()` | 100950, 100951 |
| `/var/log/apache2/access.log` | Apache CLF | `read_web_logs()` | 100800, 100805, 100807, 100808 |
| `/var/log/nginx/access.log` | Apache CLF | `read_web_logs()` | 100803, 100806 |

---

## MITRE ATT&CK Coverage

| Technique | ID | Rules |
|---|---|---|
| Brute Force | T1110 | 100105, 100116, 100901 |
| Command and Scripting Interpreter | T1059 | 100101, 100204, 700004 |
| Exploitation for Initial Access | T1190 | 100800–100810 |
| Network Denial of Service | T1498 | 100700 |
| File and Directory Permissions Modification | T1222 | 100117, 100123 |
| Resource Hijacking (Crypto Mining) | T1496 | 100119 |
| Proxy / TOR | T1090.003 | 100625, 100650, 100651 |
| Network Service Discovery | T1046 | 100903, 100904 |
| Ingress Tool Transfer | T1105 | 700005 |
| Exfiltration Over C2 | T1041 | 100660–100663 |
| Gather Victim Network Info | T1596 | 100628, 100629 |
| Active Scanning | T1595 | 100652, 100808 |

---

## Security Notes

> ⚠️ **Important:** The `monitoring.py` file currently contains a hardcoded Gmail App Password and API key. Before committing to version control:

1. **Remove hardcoded credentials** — use environment variables or a secrets manager:
   ```bash
   export GMAIL_PASS=your_app_password
   export GMAIL_USER=your_email
   ```

2. **Rotate the VirusTotal API key** shown in `ossec.conf` if it has been exposed publicly.

3. **The cluster key** in `ossec.conf` is empty — set a strong key before enabling clustering:
   ```xml
   <key>your_strong_random_key_here</key>
   ```

4. **Add `.env` to `.gitignore`** if you switch to a dotenv-based credential approach.

---

