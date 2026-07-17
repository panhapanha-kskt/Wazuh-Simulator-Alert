# Wazuh SOC Defense 
**SOC Project - Blue Team Operations Center**

A fully automated, multi-source SOC (Security Operations Center) monitoring and
response platform built on top of Wazuh. It intercepts alerts from Wazuh,
Zeek, Tetragon, Apache/Nginx, and active-response logs, classifies them
against a custom rule table, executes automated SOAR actions (firewall
blocking, account lockout, file quarantine), sends HTML email alerts, and
exposes everything through a REST API consumed by a SOC dashboard.

**Analysts:** Tith Sopanha

---

## 1. What this project does

At a high level, the platform sits between your Wazuh manager and your
analysts, and does three jobs:

1. **Intercept** — tails multiple raw log sources (not just Wazuh's own
   `alerts.json`) so nothing is missed even if Wazuh's own rule engine
   doesn't classify something.
2. **Decide** — classifies every event against a hand-maintained rule table
   (`CRITICAL_RULES` / `HIGH_RULES` / `MEDIUM_RULES` / `LOW_RULES`), maps it
   to MITRE ATT&CK, and escalates severity dynamically for things like
   brute-force login patterns.
3. **Act** — automatically blocks IPs, disables accounts, quarantines files,
   emails the on-call analyst, and stores everything for the dashboard.

---

## 2. Architecture / data flow

```
┌─────────────────────────────┐
│   Kali Linux Agent           │   ossec.conf (agent)
│   "TSC-Agent"                 │   - syscheck (FIM)
│                               │   - rootcheck / sca / syscollector
│  ┌─────────────────────────┐ │   - localfile taps:
│  │ Zeek (network sensor)   │ │       Zeek JSON logs
│  │ Tetragon (eBPF/K8s)     │ │       Tetragon JSON logs
│  │ nginx / apache2         │ │       nginx/apache access+error
│  │ sshd / journald         │ │       netstat, last -n 20, dpkg.log
│  └─────────────────────────┘ │   - active-response (firewall-drop)
└───────────────┬───────────────┘
                │ TCP :1514 (encrypted, agent enrollment via authd)
                ▼
┌─────────────────────────────┐
│   Wazuh Manager               │   ossec.conf (manager, Amazon Linux 2023)
│   192.168.200.129             │   - ruleset: local_rules.xml,
│                               │     zeek_rules.xml, 700000-tetragon.xml
│                               │   - VirusTotal integration (syscheck group)
│                               │   - writes alerts.json / archives.json
│                               │   - indexer/filebeat forwarding
└───────────────┬───────────────┘
                │ tails alerts.json + raw Zeek/Tetragon/web logs directly
                ▼
┌─────────────────────────────────────────────────────────────┐
│   monitoring.py  —  "SOC Defense Platform v3"                 │
│                                                                │
│   LogInterceptor  ──▶  AlertProcessor (SOAR engine)            │
│     - read_wazuh_alerts()      - dedup (5 min window)          │
│     - read_zeek_logs()         - brute-force escalation        │
│     - read_tetragon_logs()     - firewall-drop / disable-       │
│     - read_active_response_log()  account / quarantine-file     │
│     - read_web_logs()          - Gmail HTML alert (level ≥7)    │
│                                 - SQLite persistence             │
│                                 - in-memory ring buffer (2000)   │
│                                                                │
│   ServiceMonitor / AgentMonitor / DiskMonitor                  │
│     - periodic health checks → health email on state change     │
│                                                                │
│   Flask REST API  :5050                                        │
│     /api/health   /api/alerts   /api/metrics                   │
│     /api/agents   /api/config   /api/send_alert (POST)          │
└───────────────┬────────────────────────────────────────────────┘
                │
                ▼
        SOC Dashboard v2 (consumes REST API)          Gmail (SMTP alerts)
```

---

## 3. Components

### 3.1 Agent configuration (`ossec.conf` — Kali agent)
- Connects to manager `192.168.200.129:1514` over TCP with AES encryption,
  auto-enrolls as `TSC-Agent`.
- **FIM (syscheck):** monitors `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`,
  `/sbin`, `/boot`; whodata + full checksum on `~/Downloads`; real-time
  watch on `~/Videos`.
- **Rootcheck / SCA / Syscollector:** rootkit checks, security configuration
  assessment, full system inventory (hardware, OS, network, packages, ports,
  processes, users, groups, services, browser extensions).
- **Log sources tailed locally:** Zeek current logs, Tetragon JSON log,
  nginx/apache access+error, sshd via journald, `df -P`, `netstat -tulpn`,
  `last -n 20`, dpkg log.
- **Active response:** `firewall-drop` bound to rules
  `651,5763,100200,5712,5758,5503`, 180s timeout.

### 3.2 Manager configuration (`ossec.conf` — Amazon Linux 2023)
- JSON alert output enabled, remote TCP `:1514`.
- Vulnerability-detection feeds enabled for Canonical, Debian, RedHat,
  Amazon Linux, SUSE, Arch, AlmaLinux, Windows (MSU), and NVD.
- VirusTotal integration wired to the `syscheck` group.
- Custom active-response commands registered: `disable-account`,
  `firewall-drop`, `host-deny`, `route-null`, `netsh` (Windows only),
  `restart-wazuh`.
- Custom ruleset loaded from `etc/rules` / `etc/decoders`, plus IOC lists
  (`malware-hashes`, `malicious-ip`, `malicious-domains`,
  `blacklist-alienvault`).
- Indexer (OpenSearch) wired at `https://0.0.0.0:9200` via filebeat certs.

### 3.3 Custom detection rules (`local_rules.xml` + friends)
Rules are grouped by log source:

| Group | Rule IDs | Purpose |
|---|---|---|
| `malware` | 110002 | FIM hash match against `malware-hashes` list → CRITICAL |
| `active_response,firewall` | 100300 | Detects that `firewall-drop` AR actually fired |
| `attack` | 100200 | Source IP found in AlienVault reputation list |
| `local,syslog,sshd` | 100001 | SSH auth failure from a specific hardcoded IP (see Known Issues) |
| `rdp` | 100100 | RDP brute-force (Windows agents, frequency-based) |
| `zeek` | 100900–100907 | DNS queries, mDNS, rejected connections, port-scan burst (freq=5/20s), self-signed / expired SSL certs |
| `tetragon` | 700000–700006 | Process exec/exit/kprobe, shell exec in container, curl/wget, package manager exec |

### 3.4 `monitoring.py` — the SOAR engine
This is the core orchestrator. Key classes:

- **`LogInterceptor`** — byte-offset tailing of five independent sources
  (`alerts.json`, Zeek `*.log`, Tetragon log, active-responses log, web
  logs), each normalized into one common alert schema.
- **`classify_rule()`** — looks up rule ID against the
  `CRITICAL/HIGH/MEDIUM/LOW_RULES` tables first, falls back to numeric
  Wazuh level if the rule ID isn't in the table.
- **`AlertProcessor`** — the SOAR pipeline: brute-force escalation (5 / 10 /
  20 hits in a 5-minute window bump severity to MEDIUM/HIGH/CRITICAL),
  5-minute dedup by `rule_id+srcip`, then fires whichever of
  `firewall-drop` / `disable-account` / `quarantine-file` applies, then
  emails if severity is MEDIUM or above.
- **`EmailNotifier`** — builds a dark-terminal-themed HTML email
  (`build_html_email`) with rule metadata, MITRE links, SOAR actions taken,
  a raw-log excerpt, and an analyst checklist. Separately sends platform
  **health** emails only on state change (or every 30 min while unhealthy).
- **`MonitorDatabase`** — SQLite store for alerts, failed-login tracking,
  IP block history, health history, and arbitrary metrics.
- **`ActiveResponseManager`** — thin wrapper around the Wazuse
  active-response scripts (`firewall-drop`, `disable-account`,
  `quarantine-file.sh`, `cleanup-timeouts.sh`).
- **Flask REST API (`:5050`)** — `/api/health`, `/api/alerts` (filterable
  by level/severity/source/search text), `/api/metrics`, `/api/agents`,
  `/api/config`, and `/api/send_alert` (manual/analyst-triggered email).

### 3.5 `soc_alert_simulator.py` — rule validation harness
A safe, self-contained test script for proving the pipeline works
end-to-end without any real attack traffic:

| Test key | Rule | What it does |
|---|---|---|
| `110002` | CRITICAL L13 | Drops an EICAR-pattern file into the FIM-watched directory |
| `100300` | HIGH L12 | Appends a realistic `firewall-drop` line to the AR log |
| `700004` | MEDIUM L8 | Injects a fake Tetragon shell-exec JSON event |
| `700005` | MEDIUM L7 | Injects a fake Tetragon curl/wget JSON event |
| `100904` | HIGH L10 | Writes 6 rapid REJ connections to Zeek `conn.log` (loopback only) |
| `100907` | HIGH L12 | Writes a Zeek SSL expired-certificate entry |
| `ssh` | LOW L5 | Real SSH failed-login attempt against localhost |

Run modes: `--list`, `--dry-run`, `--rule <key>`, or no flag for all tests.
All injected artifacts are tagged `[SOC-SIM]` and the FIM test file
self-deletes after 30 seconds.

---

## 4. Requirements

```bash
pip install flask flask-cors requests
pip install python-dotenv   # optional, for .env support
```

- Python 3.10+
- A running Wazuh manager writing `alerts.json`
- Root/sudo on the agent for active-response and FIM-watched paths
- A Gmail account with an **App Password** (not your normal password) for
  SMTP alerting

---

## 5. Configuration

All operational config lives at the top of `monitoring.py`. **Do not commit
real credentials** — use environment variables:

```bash
export GMAIL_USER=your_account@gmail.com
export GMAIL_PASS=your_16_char_app_password
export ALERT_TO=analyst_inbox@example.com
```

Key tunables:

| Setting | Default | Meaning |
|---|---|---|
| `EMAIL_MIN_LEVEL` | 7 | Minimum Wazuh level that triggers an email (MEDIUM+) |
| `FAILED_LOGIN_THRESHOLD` / `SEVERE_THRESHOLD` / `CRITICAL_THRESHOLD` | 5 / 10 / 20 | Brute-force escalation thresholds within `FAILED_LOGIN_WINDOW_SEC` (300s) |
| `ALERT_DEDUP_WINDOW` | 300s | Suppresses duplicate `rule_id+srcip` alerts |
| `POLL_INTERVAL` | 15s | How often the main loop re-tails all log sources |
| `DISK_WARNING_PERCENT` / `DISK_CRITICAL_PERCENT` | 80 / 90 | Disk usage thresholds for health checks |
| `MAX_ALERTS` | 2000 | In-memory ring buffer size for the REST API |

The **VirusTotal API key** in the manager's `ossec.conf` should also be
moved out of plaintext XML — reference it via a secrets manager or restrict
file permissions tightly (`chmod 600`) at minimum.

---

## 6. Running it

```bash
# 1. Bring up the SOAR engine + REST API
python3 monitoring.py

# 2. Validate the pipeline fires end-to-end (in a separate terminal, on the agent)
sudo python3 soc_alert_simulator.py --list
sudo python3 soc_alert_simulator.py --dry-run          # preview, no writes
sudo python3 soc_alert_simulator.py --rule 110002       # one rule
sudo python3 soc_alert_simulator.py                     # everything
```

Then check:
1. **Dashboard** → `http://localhost:8080/dashboard-V2.html`
2. **REST API** → `http://localhost:5050/api/alerts?min_level=7`
3. **Inbox** → alerts with level ≥ 10 should arrive within seconds
4. **Raw alerts** → `tail -f /var/ossec/logs/alerts/alerts.json`
5. **Manager UI** → `https://192.168.200.129`

---

## 7. Known issues / things to fix before this runs unattended long-term

- **Duplicate classification path.** `monitoring.py` classifies Zeek and
  Tetragon events itself *in addition to* consuming Wazuh's own
  `alerts.json` (which already ran them through `zeek_rules.xml` /
  `700000-tetragon.xml`). The two paths can diverge and rely entirely on
  the dedup window to avoid double-alerting.
- **SQLite connections are never closed.** `with self._conn() as conn:`
  commits/rolls back but does not call `.close()` — long-running processes
  will leak file descriptors.
- **`_dedup` and `_cooldown` dicts grow unbounded.** No periodic pruning of
  old keys.
- **Rule `100001` is effectively dead** — it hardcodes `srcip=1.1.1.1` and
  will never match real traffic. Actual SSH brute-force detection runs
  through 100105 / 100901 / 5712 instead.
- **`netsh` active-response command only works on Windows agents** but is
  bound to rules active on the Kali/Linux agent — confirm intended scope.
- **Flask API has no authentication** on `:5050`, and `/api/send_alert`
  allows unauthenticated POSTs that mutate the global alert recipient. Fine
  for a closed lab network; needs auth before any wider exposure.
- **Secrets currently in source:** Gmail app password (fallback default in
  `monitoring.py`) and VirusTotal API key (manager `ossec.conf`). Rotate
  both once removed from version control.

---

**SOC Project — Tith Sopanha**

*For official SOC use only.*
