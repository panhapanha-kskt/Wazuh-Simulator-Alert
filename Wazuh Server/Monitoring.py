#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                                                                              ║
# ║    ███████╗ ██████╗  ██████╗      ██████╗ ██████╗ ███████╗                  ║
# ║    ██╔════╝██╔═══██╗██╔════╝     ██╔════╝██╔═══██╗██╔════╝                  ║
# ║    ███████╗██║   ██║██║          ██║     ██║   ██║█████╗                    ║
# ║    ╚════██║██║   ██║██║          ██║     ██║   ██║██╔══╝                    ║
# ║    ███████║╚██████╔╝╚██████╗     ╚██████╗╚██████╔╝███████╗                  ║
# ║    ╚══════╝ ╚═════╝  ╚═════╝      ╚═════╝ ╚═════╝╚══════╝                  ║
# ║                                                                              ║
# ║    ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗███████╗               ║
# ║    ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝               ║
# ║    ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗█████╗                 ║
# ║    ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝                 ║
# ║    ██████╔╝███████╗██║     ███████╗██║ ╚████║███████║███████╗               ║
# ║    ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝               ║
# ║                                                                              ║
# ╠══════════════════════════════════════════════════════════════════════════════╣
# ║  CBSA PROJECT — GROUP 7  │  BLUE TEAM OPERATIONS CENTER                     ║
# ║  WAZUH UNIFIED MONITORING & DEFENSE PLATFORM  (v3 — SOC Dashboard Edition)  ║
# ║  Analysts: Kosal Karuna · Cho Davon · Tith Sopanha                           ║
# ╠══════════════════════════════════════════════════════════════════════════════╣
# ║  WHAT CHANGED IN v3 (this file):                                             ║
# ║  ① Log interception via tail of /var/ossec/logs/alerts/alerts.json          ║
# ║    PLUS Zeek · Tetragon · Apache2 · Nginx · Active-Response logs             ║
# ║  ② Rule classification aligned EXACTLY with local_rules.xml,                ║
# ║    zeek_rules.xml, 700000-tetragon.xml, criminal_ip_ruleset.xml              ║
# ║  ③ CRITICAL / HIGH / MEDIUM → HTML Gmail alert (project template)           ║
# ║  ④ REST API exposed on :5050 consumed by SOC Dashboard v2                   ║
# ║  ⑤ All SOAR actions (firewall-drop, account-disable, quarantine) intact      ║
# ║  ⑥ SQLite persistence, sparkline metrics, health checks unchanged            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

import json
import time
import subprocess
import logging
import os
import smtplib
import sys
import hashlib
import sqlite3
import threading
import signal
import shutil
import glob
import re
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Any

# ── Flask REST API (consumed by SOC Dashboard v2) ──────────────────────────
from flask import Flask, jsonify, request
from flask_cors import CORS

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ANSI TERMINAL COLOR PALETTE  (Blue Team SOC theme)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class C:
    RESET = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m"
    NAVY  = "\033[38;5;17m";  BLUE  = "\033[38;5;27m"
    CYAN  = "\033[38;5;51m";  SKY   = "\033[38;5;117m"
    STEEL = "\033[38;5;153m"; GREEN = "\033[38;5;47m"
    YELLOW= "\033[38;5;226m"; ORANGE= "\033[38;5;208m"
    RED   = "\033[38;5;196m"; WHITE = "\033[38;5;255m"
    GRAY  = "\033[38;5;244m"; BG_RED= "\033[41m"

    @staticmethod
    def risk(level: str) -> str:
        return {"CRITICAL": C.RED+C.BOLD, "HIGH": C.ORANGE+C.BOLD,
                "MEDIUM": C.YELLOW, "LOW": C.SKY}.get(level, C.WHITE)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ① CONFIGURATION
#     All paths match your existing backup structure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BACKUP_BASE       = "/home/wazuh-user/backup"

# ── Log sources to intercept ───────────────────────
ALERT_FILE        = "/var/ossec/logs/alerts/alerts.json"        # Wazuh JSON alerts
ARCHIVE_FILE      = "/var/ossec/logs/archives/archives.json"
ACTIVE_RESP_LOG   = "/var/ossec/logs/active-responses.log"
ZEEK_LOG_DIR      = "/opt/zeek/logs/current"                    # Zeek network logs
TETRAGON_LOG      = "/var/log/tetragon/tetragon.log"            # Cilium Tetragon
APACHE_ACCESS     = "/var/log/apache2/access.log"
APACHE_ERROR      = "/var/log/apache2/error.log"
NGINX_ACCESS      = "/var/log/nginx/access.log"
NGINX_ERROR       = "/var/log/nginx/error.log"

# ── Derived paths ──────────────────────────────────
LOG_FILE          = f"{BACKUP_BASE}/log/complete-monitor.log"
BLOCKED_IPS_FILE  = f"{BACKUP_BASE}/log/blocked_ips.log"
STATS_FILE        = f"{BACKUP_BASE}/log/stats.json"
QUARANTINE_LOG    = f"{BACKUP_BASE}/log/quarantine.log"
FIREWALL_LOG      = f"{BACKUP_BASE}/log/firewall.log"
ACCOUNT_LOG       = f"{BACKUP_BASE}/log/disable-account.log"
DB_FILE           = f"{BACKUP_BASE}/complete-monitor.db"
HEALTH_STATE_FILE = f"{BACKUP_BASE}/log/health_state.json"
PID_FILE          = "/var/run/complete-monitor.pid"

# ── Gmail credentials (your existing account) ──────
EMAIL_ENABLED    = True
SMTP_SERVER      = "smtp.gmail.com"
SMTP_PORT        = 587
SMTP_USER        = os.getenv("GMAIL_USER",  "sop98886@gmail.com")
SMTP_PASSWORD    = os.getenv("GMAIL_PASS",  "kizagpavcmgoodpi")   # App Password
ALERT_EMAIL      = os.getenv("ALERT_TO",    "sopanha.tith@student.cadt.edu.kh")

# ── Email threshold: CRITICAL + HIGH + MEDIUM all get emailed ──────────────
#    LOW and INFO are stored in DB + shown on dashboard but NOT emailed.
EMAIL_MIN_LEVEL  = 7    # level >= 7 → MEDIUM → send email

# ── Thresholds ─────────────────────────────────────
FAILED_LOGIN_THRESHOLD   = 5
SEVERE_THRESHOLD         = 10
CRITICAL_THRESHOLD       = 20
FAILED_LOGIN_WINDOW_SEC  = 300   # 5 min
ALERT_DEDUP_WINDOW       = 300   # 5 min — suppress exact duplicate (rule+IP)
CLEANUP_INTERVAL         = 50
HEALTH_CHECK_INTERVAL    = 300   # 5 min
SERVICE_CHECK_INTERVAL   = 60
AGENT_CHECK_INTERVAL     = 300
DISK_CHECK_INTERVAL      = 600
INTEGRATION_CHECK_INTERVAL = 1800
BACKUP_CHECK_INTERVAL    = 3600
POLL_INTERVAL            = 15    # seconds between REST API polls

# ── Disk monitoring ────────────────────────────────
DISK_WARNING_PERCENT  = 80
DISK_CRITICAL_PERCENT = 90
DISK_PATHS = [
    '/var/ossec/logs/alerts',
    '/var/ossec/logs/archives',
    '/var/ossec/queue',
    BACKUP_BASE,
]

# ── Wazuh services to monitor ─────────────────────
WAZUH_SERVICES   = ['wazuh-manager', 'wazuh-dashboard', 'filebeat']
CRITICAL_SERVICES = ['wazuh-manager']

# ── Flask REST API (SOC Dashboard v2 backend) ──────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5050
MAX_ALERTS = 2000   # in-memory ring buffer


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ② RULE CLASSIFICATION
#     Exactly matches your local_rules.xml,
#     zeek_rules.xml, 700000-tetragon.xml,
#     and criminal_ip_ruleset.xml
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ── CRITICAL rules (level 13-15) ──────────────────
CRITICAL_RULES = {
    '100666': 'ACTIVE COMPROMISE — Criminal IP Critical + critical file modified',
    '100667': 'ACTIVE EXPLOITATION — Criminal IP Critical + reverse shell confirmed',
    '100668': 'POST-COMPROMISE MINER — Criminal IP Critical + crypto miner',
    '100650': 'TOR + CRITICAL SCORE — TOR exit node with critical inbound risk',
    '100652': 'SCANNER + CRITICAL SCORE — Known scanner critical inbound',
    '100654': 'DARK WEB + SCANNER — Dark web IP actively scanning',
    '100655': 'DARK WEB + CRITICAL SCORE — Dark web IP critical inbound',
    '100656': 'SNORT + CRITICAL SCORE — Snort-flagged critical inbound',
    '100663': 'INTERNAL HOST TO TOR — C2 channel suspected',
    '100123': 'REPEATED CRITICAL FILE MODS — 3+ modifications in 300s',
}

# ── HIGH rules (level 10-12) ──────────────────────
HIGH_RULES = {
    '100117': 'CRITICAL FILE MODIFIED — /etc/passwd, /etc/shadow, /etc/sudoers',
    '100119': 'CRYPTO MINING TOOL — xmrig/minerd/cpuminer in process list',
    '100101': 'REVERSE SHELL TOOL — msfconsole/meterpreter/nc -e detected',
    '100204': 'NETWORK RELAY TOOL — netcat/ncat/socat in process list',
    '100700': 'DDOS ATTACK — Suricata network flood detection',
    '100805': 'SQL INJECTION VIA APACHE — union select / drop table',
    '100806': 'SQL INJECTION VIA NGINX — union select / or 1=1',
    '100808': 'WEB SCANNER — nikto/sqlmap/dirb/gobuster user-agent',
    '100628': 'CRIMINAL IP CRITICAL INBOUND — rated Critical by Criminal IP',
    '100105': 'MULTIPLE SSH FAILURES — 8 failures from same IP in 60s',
    '100901': 'SSH BRUTE FORCE CONFIRMED — 5 failures same IP in 60s',
    '100106': 'MULTIPLE FAILED SUDO — 5 priv-esc attempts in 120s',
    '100651': 'TOR + DANGEROUS SCORE — TOR node with dangerous inbound',
    '100653': 'SCANNER + DANGEROUS SCORE — Scanner with dangerous inbound',
    '100657': 'ANONYMOUS VPN + CRITICAL — Anon VPN critical inbound',
    '100662': 'OUTBOUND CRITICAL IP — Exfiltration to Critical-rated IP confirmed',
    '100664': 'REPEATED DANGEROUS CRIMINAL IP — 3+ hits in 300s',
    '100665': 'REPEATED CRITICAL CRIMINAL IP — 3+ hits in 300s',
    '100625': 'TOR NODE DETECTED — IP associated with TOR network',
    # Zeek high-severity (zeek_rules.xml)
    '100907': 'ZEEK SSL — Client connected to expired certificate server',
    '100904': 'ZEEK PORT SCAN — 5+ rejected connections in 20s',
}

# ── MEDIUM rules (level 7-9) ──────────────────────
MEDIUM_RULES = {
    '100116': 'SSH BRUTE FORCE EARLY — 4 failures in 30s',
    '100800': 'PATH TRAVERSAL VIA APACHE — directory traversal in URL',
    '100803': 'PATH TRAVERSAL VIA NGINX — directory traversal in URL',
    '100807': 'XSS ATTEMPT — script/javascript:/onerror= in request',
    '100809': 'PATH TRAVERSAL BURST — 20+ traversal hits in 30s',
    '100810': 'SQL INJECTION BURST — 20+ SQLi hits in 30s',
    '100205': 'PROCESS FROM TEMP PATH — running from /tmp/ or /dev/shm/',
    '100629': 'CRIMINAL IP DANGEROUS INBOUND — rated Dangerous',
    '100658': 'HIGH-RISK PROXY — proxy with Dangerous/Critical score',
    '100661': 'OUTBOUND DANGEROUS IP — exfil to Dangerous IP suspected',
    '100627': 'DARK WEB IP — IP in dark web infrastructure',
    '100635': 'SNORT-FLAGGED IP — IP in Snort signature database',
    '100638': 'ANONYMOUS VPN — anonymous VPN IP detected',
    '100624': 'VPN SERVICE — IP associated with VPN service',
    '100660': 'OUTBOUND MODERATE IP — connection to Moderate-risk IP',
    '100636': 'SCANNER IP — IP associated with scanning activity',
    '100630': 'CRIMINAL IP MODERATE INBOUND — rated Moderate',
    # Zeek medium (zeek_rules.xml)
    '100906': 'ZEEK SSL SELF-SIGNED — self-signed certificate detected',
    '100903': 'ZEEK CONNECTION REJECTED — connection rejected by target',
    # Tetragon medium (700000-tetragon.xml)
    '700004': 'CONTAINER SHELL EXEC — shell binary in container',
    '700005': 'CONTAINER REMOTE FETCH — wget/curl inside container',
    '700006': 'CONTAINER PKG INSTALL — package manager inside container',
    '700003': 'CONTAINER PROC ERROR — process exited with error code',
}

# ── LOW rules (level 0-6) ─────────────────────────
LOW_RULES = {
    '100200': 'FILE MODIFIED IN /root — FIM syscheck alert',
    '100201': 'NEW FILE IN /root — FIM syscheck new file',
    '100092': 'VIRUSTOTAL REMOVED THREAT — threat file cleaned',
    '100093': 'VIRUSTOTAL REMOVAL ERROR — threat file not removed',
    '100950': 'AR FIREWALL-DROP FIRED — source IP blocked',
    '100951': 'AR ACCOUNT DISABLED — user account disabled',
    '100626': 'PROXY IP — IP associated with proxy service',
    '100633': 'HOSTING SERVICE IP — IP from hosting provider',
    '100634': 'CLOUD SERVICE IP — IP from cloud provider',
    '100631': 'CRIMINAL IP SAFE INBOUND — IP rated Safe',
    '100632': 'CRIMINAL IP LOW INBOUND — IP rated Low risk',
    '100669': 'OUTBOUND SAFE IP — connection to Safe-rated IP',
    '100670': 'OUTBOUND LOW RISK IP — connection to Low-risk IP',
    # Zeek low (zeek_rules.xml)
    '100901': 'ZEEK DNS QUERY — DNS query logged',
    '100902': 'ZEEK MDNS TRAFFIC — normal mDNS traffic',
    '100900': 'ZEEK ALERT — general Zeek JSON event',
    '100905': 'ZEEK DNS EXCLUDE — cti.wazuh.com suppressed',
    # Tetragon low (700000-tetragon.xml)
    '700000': 'TETRAGON PROCESS EXEC — process execution detected',
    '700001': 'TETRAGON PROCESS EXIT — process exit detected',
    '700002': 'TETRAGON KPROBE — kernel probe detected',
}

# ── Rules that trigger active response ────────────
ACTIVE_RESPONSE_RULES = {
    '100105', '100116', '100901',
    '100700',
    '100800', '100803', '100805', '100806',
    '100628', '100650', '100651', '100652', '100653',
    '100654', '100655', '100656', '100657', '100658',
    '100662', '100663', '100666', '100667', '100668',
}

ACCOUNT_DISABLE_RULES = {'100901'}
QUARANTINE_RULES      = {'100101', '550', '100117'}
FAILED_LOGIN_RULES    = {'5716', '100105', '100116', '100901'}

# ── MITRE ATT&CK mapping ──────────────────────────
MITRE_MAPPING = {
    '100117': ['T1222', 'TA0005'],   '100123': ['T1222', 'TA0005'],
    '100200': ['T1083', 'TA0007'],   '100201': ['T1083', 'TA0007'],
    '100101': ['T1059', 'TA0002'],   '100204': ['T1059', 'TA0002'],
    '100205': ['T1059', 'TA0002'],   '100119': ['T1496', 'TA0040'],
    '100105': ['T1110', 'TA0006'],   '100116': ['T1110', 'TA0006'],
    '100901': ['T1110', 'TA0006'],   '100106': ['T1068', 'TA0004'],
    '100800': ['T1190', 'TA0001'],   '100803': ['T1190', 'TA0001'],
    '100805': ['T1190', 'TA0001'],   '100806': ['T1190', 'TA0001'],
    '100807': ['T1190', 'TA0001'],   '100808': ['T1595', 'TA0043'],
    '100809': ['T1190', 'TA0001'],   '100810': ['T1190', 'TA0001'],
    '100700': ['T1498', 'TA0040'],
    '100628': ['T1596', 'TA0043'],   '100629': ['T1596', 'TA0043'],
    '100624': ['T1090', 'TA0011'],   '100625': ['T1090.003', 'TA0011'],
    '100627': ['T1583', 'TA0042'],   '100635': ['T1595', 'TA0043'],
    '100636': ['T1595', 'TA0043'],   '100638': ['T1090.003', 'TA0011'],
    '100650': ['T1090.003', 'TA0011'], '100651': ['T1090.003', 'TA0011'],
    '100652': ['T1595', 'TA0043'],   '100653': ['T1595', 'TA0043'],
    '100654': ['T1583', 'TA0042'],   '100655': ['T1583', 'TA0042'],
    '100656': ['T1595', 'TA0043'],   '100657': ['T1090.003', 'TA0011'],
    '100658': ['T1090', 'TA0011'],   '100660': ['T1041', 'TA0011'],
    '100661': ['T1041', 'TA0011'],   '100662': ['T1041', 'TA0011'],
    '100663': ['T1041', 'TA0011'],   '100664': ['T1595', 'TA0043'],
    '100665': ['T1595', 'TA0043'],   '100666': ['T1222', 'T1595', 'TA0005'],
    '100667': ['T1059', 'T1190', 'TA0002'], '100668': ['T1496', 'T1190', 'TA0040'],
    # Zeek
    '100903': ['T1046', 'TA0007'],   '100904': ['T1046', 'TA0007'],
    '100906': ['T1071', 'TA0011'],   '100907': ['T1071', 'TA0011'],
    # Tetragon
    '700004': ['T1059', 'TA0002'],   '700005': ['T1105', 'TA0011'],
    '700006': ['T1072', 'TA0008'],
}

# ── Severity → numeric level for display ─────────
SEV_TO_LEVEL = {"CRITICAL": 13, "HIGH": 10, "MEDIUM": 7, "LOW": 4, "INFO": 1}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UTILITY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime): return obj.isoformat()
        if isinstance(obj, timedelta): return str(obj)
        if isinstance(obj, set): return list(obj)
        return super().default(obj)


def level_to_severity(level: int) -> str:
    """Map Wazuh rule level → project severity label."""
    if level >= 13: return "CRITICAL"
    if level >= 10: return "HIGH"
    if level >= 7:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFO"


def classify_rule(rule_id: str, level: int, desc: str) -> tuple[str, str]:
    """
    Classify an alert by rule ID first (exact match against project rule tables),
    then fall back to numeric level.
    Returns (severity_label, reason_string).
    """
    if rule_id in CRITICAL_RULES:
        return "CRITICAL", CRITICAL_RULES[rule_id]
    if rule_id in HIGH_RULES:
        return "HIGH", HIGH_RULES[rule_id]
    if rule_id in MEDIUM_RULES:
        return "MEDIUM", MEDIUM_RULES[rule_id]
    if rule_id in LOW_RULES:
        return "LOW", LOW_RULES[rule_id]
    # Numeric fallback (for built-in Wazuh rules not in our tables)
    sev = level_to_severity(level)
    return sev, f"{sev} via level {level}: {desc[:80]}"


SEV_COLOR_CSS = {
    "CRITICAL": {"accent": "#E24B4A", "bg": "#791F1F", "dim": "rgba(226,75,74,.12)"},
    "HIGH":     {"accent": "#EF9F27", "bg": "#633806", "dim": "rgba(239,159,39,.12)"},
    "MEDIUM":   {"accent": "#378ADD", "bg": "#0C447C", "dim": "rgba(55,138,221,.12)"},
    "LOW":      {"accent": "#639922", "bg": "#27500A", "dim": "rgba(99,153,34,.12)"},
    "INFO":     {"accent": "#888780", "bg": "#444441", "dim": "rgba(136,135,128,.12)"},
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ③ HTML EMAIL BUILDER
#     Uses same dark-terminal template as Gmail-Alert.py
#     but enriched with SOAR actions, MITRE, and reason
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def build_html_email(alert: dict, actions_taken: list[str]) -> str:
    """
    Build a fully self-contained HTML email matching the SOC Dashboard v2 aesthetic.
    All CSS is inline for Gmail/Outlook compatibility.
    """
    sev         = alert.get("severity", "INFO")
    colors      = SEV_COLOR_CSS.get(sev, SEV_COLOR_CSS["INFO"])
    accent      = colors["accent"]
    level       = alert.get("level", 0)
    rule_id     = alert.get("rule_id", "—")
    description = alert.get("description", "No description")
    agent_name  = alert.get("agent_name", "—")
    agent_id    = alert.get("agent_id", "—")
    agent_ip    = alert.get("agent_ip", "—") or "—"
    srcip       = alert.get("srcip", "") or "—"
    dstip       = alert.get("dstip", "") or "—"
    location    = alert.get("location", "") or "—"
    source      = alert.get("source", "") or "—"
    reason      = alert.get("reason", "—")
    groups      = alert.get("groups", [])
    mitre_ids   = alert.get("mitre", [])
    full_log    = (alert.get("full_log") or "")[:700]

    ts_raw = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts = ts_raw

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def kv(label, value, val_color=None):
        vc = f"color:{val_color};" if val_color else "color:#cccccc;"
        return (f'<tr>'
                f'<td style="padding:7px 12px;border-bottom:1px solid #2a2a2a;font-size:10px;'
                f'color:#666;text-transform:uppercase;letter-spacing:.1em;'
                f'font-family:Courier New,monospace;width:130px;vertical-align:top;">{label}</td>'
                f'<td style="padding:7px 12px;border-bottom:1px solid #2a2a2a;font-size:12px;'
                f'{vc}font-family:Courier New,monospace;word-break:break-all;">{value}</td>'
                f'</tr>')

    kv_rows = "".join([
        kv("Timestamp",  ts),
        kv("Rule ID",    rule_id,    accent),
        kv("Reason",     reason),
        kv("Agent",      f"{agent_name} (ID: {agent_id})"),
        kv("Agent IP",   agent_ip),
        kv("Source IP",  srcip,      accent if srcip != "—" else None),
        kv("Dest IP",    dstip),
        kv("Location",   location),
        kv("Log Source", source),
    ])

    groups_html = " ".join(
        f'<span style="display:inline-block;background:#222;border:1px solid #333;'
        f'border-radius:3px;padding:2px 7px;font-size:9px;color:#888;margin:2px;">{g}</span>'
        for g in groups
    ) or '<span style="color:#555;">—</span>'

    mitre_html = " ".join(
        f'<a href="https://attack.mitre.org/techniques/{m.replace(".","/")}" '
        f'style="display:inline-block;background:rgba(55,138,221,.15);border:1px solid rgba(55,138,221,.3);'
        f'border-radius:3px;padding:2px 7px;font-size:9px;color:#378ADD;margin:2px;text-decoration:none;">'
        f'{m}</a>'
        for m in mitre_ids
    ) or '<span style="color:#555;">No MITRE mapping</span>'

    actions_html = "".join(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">'
        f'<span style="color:{accent};font-size:12px;">✔</span>'
        f'<span style="font-size:12px;color:#ccc;">{a}</span></div>'
        for a in actions_taken
    ) or '<span style="color:#555;">No automated response triggered</span>'

    vt_link = ""
    if srcip != "—":
        vt_link = (f'<a href="https://www.virustotal.com/gui/ip-address/{srcip}" '
                   f'style="display:inline-block;background:#1a1a1a;border:1px solid #333;'
                   f'border-radius:4px;padding:5px 10px;font-size:11px;color:#888;'
                   f'text-decoration:none;margin-right:7px;font-family:Courier New,monospace;">'
                   f'🔍 Check {srcip} on VirusTotal</a>')

    raw_log_section = ""
    if full_log:
        raw_log_section = (f'<div style="margin-bottom:18px;">'
                           f'<div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;'
                           f'color:#555;margin-bottom:7px;">Raw Log (truncated)</div>'
                           f'<pre style="background:#0d0d0d;border:1px solid #222;border-radius:4px;'
                           f'padding:10px;font-family:Courier New,monospace;font-size:10px;color:#888;'
                           f'white-space:pre-wrap;word-break:break-all;margin:0;">{full_log}</pre></div>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>[SOC {sev}] Rule {rule_id}</title></head>
<body style="margin:0;padding:0;background:#f0f0f0;font-family:Courier New,monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:28px 12px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0"
  style="background:#111;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.4);">

  <!-- ── IDENTITY STRIP ── -->
  <tr><td style="background:rgba(0,0,0,.4);padding:5px 22px;">
    <span style="font-size:9px;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.5);">
      CBSA GROUP 7 · BLUE TEAM OPERATIONS CENTER · WAZUH SOC DEFENSE PLATFORM
    </span>
  </td></tr>

  <!-- ── HEADER ── -->
  <tr><td style="background:{accent};padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:18px 22px 18px;">
          <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;
            color:rgba(255,255,255,.75);margin-bottom:5px;">Security Alert</div>
          <div style="font-size:30px;font-weight:700;color:#fff;letter-spacing:.05em;line-height:1;">
            {sev}
          </div>
        </td>
        <td align="right" style="padding:18px 22px;vertical-align:top;">
          <div style="background:rgba(0,0,0,.3);border-radius:6px;padding:8px 14px;text-align:center;">
            <div style="font-size:9px;color:rgba(255,255,255,.6);letter-spacing:.1em;margin-bottom:3px;">LEVEL</div>
            <div style="font-size:34px;font-weight:700;color:#fff;line-height:1;">{level}</div>
          </div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- ── DESCRIPTION ── -->
  <tr><td style="background:#1a1a1a;padding:16px 22px;border-bottom:1px solid #222;">
    <div style="font-size:14px;color:#fff;font-weight:600;
      border-left:3px solid {accent};padding-left:11px;line-height:1.5;">
      {description}
    </div>
  </td></tr>

  <!-- ── BODY ── -->
  <tr><td style="background:#111;padding:22px;">

    <!-- KV Table -->
    <table width="100%" cellpadding="0" cellspacing="0"
      style="border-collapse:collapse;margin-bottom:18px;">
      {kv_rows}
    </table>

    <!-- Groups -->
    <div style="margin-bottom:14px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#555;margin-bottom:7px;">Groups</div>
      {groups_html}
    </div>

    <!-- MITRE -->
    <div style="margin-bottom:18px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#555;margin-bottom:7px;">MITRE ATT&amp;CK</div>
      {mitre_html}
    </div>

    <!-- SOAR Actions -->
    <div style="background:#1a1a1a;border:1px solid #2a2a2a;border-left:3px solid {accent};
      border-radius:0 4px 4px 0;padding:12px 14px;margin-bottom:18px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#666;margin-bottom:9px;">
        Automated Response Actions
      </div>
      {actions_html}
    </div>

    {raw_log_section}

    <!-- Analyst guidance -->
    <div style="background:#0d0d0d;border:1px solid #222;border-radius:4px;padding:12px 14px;margin-bottom:18px;">
      <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#555;margin-bottom:8px;">
        Analyst Checklist
      </div>
      <div style="font-size:11px;color:#888;line-height:1.9;">
        ▸ Verify source IP in Criminal IP / VirusTotal<br>
        ▸ Check agent logs for correlated activity within ±5 min window<br>
        ▸ Escalate to Tier-2 if source IP is internal (RFC1918)<br>
        ▸ Review MITRE ATT&amp;CK techniques linked above<br>
        ▸ Confirm active-response firewall-drop was applied on agent side
      </div>
    </div>

    <!-- Quick actions -->
    <div style="margin-bottom:20px;">
      {vt_link}
      <a href="https://attack.mitre.org/"
        style="display:inline-block;background:#1a1a1a;border:1px solid #333;border-radius:4px;
        padding:5px 10px;font-size:11px;color:#888;text-decoration:none;
        font-family:Courier New,monospace;">🛡 MITRE Navigator</a>
    </div>

    <!-- Footer -->
    <div style="border-top:1px solid #222;padding-top:14px;font-size:10px;color:#444;text-align:center;line-height:1.8;">
      Auto-generated by <strong style="color:#666;">Wazuh SOC Defense Platform v3</strong>
      &nbsp;·&nbsp; {now_str}<br>
      Trigger: Rule level {level} classified as <strong style="color:{accent};">{sev}</strong>
      &nbsp;·&nbsp; Email threshold: level ≥ {EMAIL_MIN_LEVEL} (MEDIUM+)<br>
      <span style="color:#333;">Team: Kosal Karuna · Cho Davon · Tith Sopanha
      &nbsp;·&nbsp; FOR OFFICIAL SOC USE ONLY</span>
    </div>

  </td></tr>
  <tr><td style="background:{accent};height:3px;"></td></tr>
</table>
</td></tr></table>
</body></html>"""


def build_health_email_html(report: dict) -> str:
    """Build health-check HTML email in matching SOC v2 style."""
    overall = report.get("overall_status", "UNKNOWN")
    ts      = report.get("timestamp", datetime.now().isoformat())
    accent  = {"HEALTHY": "#639922", "DEGRADED": "#EF9F27", "CRITICAL": "#E24B4A"}.get(overall, "#888780")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def section(title, content):
        return (f'<div style="margin-bottom:16px;">'
                f'<div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;'
                f'color:#555;border-bottom:1px solid #222;padding-bottom:5px;margin-bottom:9px;">{title}</div>'
                f'{content}</div>')

    def row(label, value, color="#ccc"):
        return (f'<div style="display:flex;gap:8px;margin-bottom:5px;font-size:11px;">'
                f'<span style="color:#666;width:160px;flex-shrink:0;">{label}</span>'
                f'<span style="color:{color};">{value}</span></div>')

    services_html = "".join(
        row(svc, "OPERATIONAL" if st.get("healthy") else "DEGRADED",
            "#639922" if st.get("healthy") else "#E24B4A")
        for svc, st in report.get("services", {}).get("services", {}).items()
    )
    summary = report.get("agents", {}).get("summary", {})
    agents_html = (row("Online agents", summary.get("active_count", 0), "#639922") +
                   row("Offline agents", summary.get("disconnected_count", 0), "#E24B4A" if summary.get("disconnected_count") else "#ccc") +
                   row("Fleet coverage", f"{summary.get('healthy_percent', 0):.1f}%"))

    issues = report.get("issues", [])
    issues_html = ("".join(f'<div style="font-size:11px;color:#EF9F27;margin-bottom:4px;">▸ {i}</div>' for i in issues[:8])
                   or '<div style="font-size:11px;color:#639922;">No anomalies detected</div>')

    stats = report.get("stats", {})
    stats_html = (row("Alerts processed",   stats.get("alerts_processed", 0)) +
                  row("IPs blocked",         stats.get("ips_blocked", 0)) +
                  row("Accounts locked",     stats.get("accounts_disabled", 0)) +
                  row("Files quarantined",   stats.get("files_quarantined", 0)) +
                  row("Emails sent",         stats.get("emails_sent", 0)))

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>SOC Platform Health — {overall}</title></head>
<body style="margin:0;padding:0;background:#f0f0f0;font-family:Courier New,monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 12px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0"
  style="background:#111;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.4);">
  <tr><td style="background:rgba(0,0,0,.4);padding:4px 20px;">
    <span style="font-size:9px;letter-spacing:.25em;text-transform:uppercase;color:rgba(255,255,255,.45);">
      CBSA GROUP 7 · BLUE TEAM · PLATFORM HEALTH REPORT
    </span>
  </td></tr>
  <tr><td style="background:{accent};padding:16px 20px;">
    <div style="font-size:10px;letter-spacing:.2em;color:rgba(255,255,255,.7);margin-bottom:4px;">Platform Status</div>
    <div style="font-size:26px;font-weight:700;color:#fff;">{overall}</div>
    <div style="font-size:10px;color:rgba(255,255,255,.6);margin-top:3px;">{ts}</div>
  </td></tr>
  <tr><td style="padding:20px;">
    {section("Core Services", services_html)}
    {section("Agent Telemetry", agents_html)}
    {section("SOAR Engine Metrics", stats_html)}
    {section("Action Items", issues_html)}
    <div style="border-top:1px solid #222;padding-top:12px;font-size:10px;color:#444;text-align:center;">
      Auto-generated · {now_str} · Wazuh SOC Defense Platform v3<br>
      <span style="color:#333;">FOR OFFICIAL SOC USE ONLY</span>
    </div>
  </td></tr>
  <tr><td style="background:{accent};height:3px;"></td></tr>
</table>
</td></tr></table>
</body></html>"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  EMAIL NOTIFIER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class EmailNotifier:
    """
    Sends security alerts and health reports via Gmail SMTP.
    Uses Gmail App Password — NOT your account password.
    """

    def __init__(self):
        self._health_state = self._load_state()
        self._cooldown: dict[str, float] = {}   # rule_id+ip → last sent timestamp
        self.COOLDOWN_SEC = 300   # suppress exact-duplicate email for 5 min

    # ── health state persistence ────────────────────
    def _load_state(self) -> dict:
        if os.path.exists(HEALTH_STATE_FILE):
            try:
                with open(HEALTH_STATE_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"last_healthy": True, "last_alert_time": 0}

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(HEALTH_STATE_FILE), exist_ok=True)
            with open(HEALTH_STATE_FILE, "w") as f:
                json.dump(self._health_state, f)
        except Exception:
            pass

    # ── cooldown guard ──────────────────────────────
    def _in_cooldown(self, key: str) -> bool:
        last = self._cooldown.get(key, 0)
        if time.time() - last < self.COOLDOWN_SEC:
            return True
        self._cooldown[key] = time.time()
        return False

    # ── core send ───────────────────────────────────
    def _send(self, subject: str, html_body: str, plain_body: str = "") -> bool:
        if not EMAIL_ENABLED:
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = SMTP_USER
            msg["To"]      = ALERT_EMAIL
            msg["Subject"] = subject

            if plain_body:
                msg.attach(MIMEText(plain_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)

            logging.info(f"Email sent: {subject[:60]}")
            return True
        except Exception as exc:
            logging.error(f"Email FAILED ({subject[:40]}): {exc}")
            return False

    # ── security alert ──────────────────────────────
    def send_security_alert(self, alert: dict, actions_taken: list[str]) -> bool:
        """
        Send a per-alert HTML email for CRITICAL / HIGH / MEDIUM events.
        Suppressed for LOW and INFO to avoid inbox flooding.
        """
        sev     = alert.get("severity", "INFO")
        rule_id = alert.get("rule_id", "?")
        srcip   = alert.get("srcip", "") or "N/A"
        level   = alert.get("level", 0)
        desc    = alert.get("description", "")

        # Gate: only email CRITICAL, HIGH, MEDIUM
        if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
            return False

        # Cooldown: don't spam identical rule+IP pairs
        cooldown_key = f"{rule_id}_{srcip}"
        if self._in_cooldown(cooldown_key):
            logging.debug(f"Email cooldown active for {cooldown_key}")
            return False

        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵"}.get(sev, "⚪")
        subject = (f"[SOC {sev}] {icon} Rule {rule_id} — "
                   f"{desc[:55]}{'…' if len(desc) > 55 else ''}")

        html = build_html_email(alert, actions_taken)

        # Plain-text fallback
        plain = (
            f"WAZUH SOC DEFENSE PLATFORM — SECURITY ALERT\n"
            f"{'='*60}\n"
            f"Severity   : {sev}\n"
            f"Level      : {level}\n"
            f"Rule ID    : {rule_id}\n"
            f"Description: {desc}\n"
            f"Source IP  : {srcip}\n"
            f"Agent      : {alert.get('agent_name','N/A')}\n"
            f"Timestamp  : {alert.get('timestamp','')}\n"
            f"MITRE      : {', '.join(alert.get('mitre', [])) or 'N/A'}\n"
            f"\nAutomated Actions:\n" +
            "\n".join(f"  ✔ {a}" for a in actions_taken) +
            "\n\nAnalyst: verify in VirusTotal and Criminal IP.\n"
            f"{'='*60}\n"
            f"Team: Kosal Karuna · Cho Davon · Tith Sopanha\n"
            f"FOR OFFICIAL SOC USE ONLY"
        )

        return self._send(subject, html, plain)

    # ── health report ───────────────────────────────
    def should_send_health_alert(self, currently_healthy: bool) -> bool:
        now = time.time()
        changed = (currently_healthy != self._health_state["last_healthy"])
        repeat  = (not currently_healthy and
                   now - self._health_state["last_alert_time"] > 1800)
        if changed or repeat:
            self._health_state["last_healthy"] = currently_healthy
            self._health_state["last_alert_time"] = now
            self._save_state()
            return True
        return False

    def send_health_alert(self, report: dict) -> bool:
        overall = report.get("overall_status", "UNKNOWN")
        icon    = {"HEALTHY": "✅", "DEGRADED": "⚠️", "CRITICAL": "🔴"}.get(overall, "❓")
        subject = f"[SOC MONITOR] {icon} Platform Health: {overall}"
        html    = build_health_email_html(report)
        return self._send(subject, html)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DATABASE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class MonitorDatabase:
    """SQLite store — thread-safe via per-call connections."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._init()

    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT, srcip TEXT, timestamp TEXT,
                    level INTEGER, severity TEXT, description TEXT,
                    reason TEXT, blocked INTEGER DEFAULT 0,
                    quarantined INTEGER DEFAULT 0,
                    account_disabled INTEGER DEFAULT 0,
                    email_sent INTEGER DEFAULT 0,
                    mitre_ids TEXT, source TEXT, groups TEXT,
                    agent_name TEXT, agent_id TEXT, agent_ip TEXT,
                    dstip TEXT, location TEXT, full_log TEXT
                );
                CREATE TABLE IF NOT EXISTS failed_logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    srcip TEXT, timestamp TEXT, rule_id TEXT
                );
                CREATE TABLE IF NOT EXISTS ip_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT, rule_id TEXT, timestamp TEXT,
                    expiry TEXT, reason TEXT, unblocked INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS health_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, overall_status TEXT,
                    services_ok INTEGER, agents_ok INTEGER,
                    disk_ok INTEGER, details TEXT
                );
                CREATE TABLE IF NOT EXISTS metrics (
                    key TEXT PRIMARY KEY, value TEXT, updated TEXT
                );
            """)

    def save_alert(self, a: dict) -> str:
        aid = a.get("id") or f"mon_{int(time.time()*1000)}_{random.randint(1000,9999)}"
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO alerts
                (id,rule_id,srcip,timestamp,level,severity,description,
                 reason,blocked,quarantined,account_disabled,email_sent,
                 mitre_ids,source,groups,agent_name,agent_id,agent_ip,
                 dstip,location,full_log)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (aid, a.get("rule_id"), a.get("srcip"), a.get("timestamp"),
                  a.get("level"), a.get("severity"), a.get("description"),
                  a.get("reason"), int(a.get("blocked",0)),
                  int(a.get("quarantined",0)), int(a.get("account_disabled",0)),
                  int(a.get("email_sent",0)),
                  ",".join(a.get("mitre",[])),
                  a.get("source"), ",".join(a.get("groups",[])),
                  a.get("agent_name"), a.get("agent_id"), a.get("agent_ip"),
                  a.get("dstip"), a.get("location"),
                  (a.get("full_log") or "")[:500]))
        return aid

    def record_failed_login(self, srcip: str, rule_id: str):
        with self._conn() as conn:
            conn.execute("INSERT INTO failed_logins(srcip,timestamp,rule_id) VALUES(?,?,?)",
                         (srcip, datetime.now().isoformat(), rule_id))

    def failed_login_count(self, srcip: str, seconds: int = 300) -> int:
        cutoff = (datetime.now() - timedelta(seconds=seconds)).isoformat()
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM failed_logins WHERE srcip=? AND timestamp>?",
                                (srcip, cutoff)).fetchone()[0]

    def record_ip_block(self, ip: str, rule_id: str, reason: str, timeout: int = 3600):
        exp = (datetime.now() + timedelta(seconds=timeout)).isoformat()
        with self._conn() as conn:
            conn.execute("INSERT INTO ip_blocks(ip,rule_id,timestamp,expiry,reason) VALUES(?,?,?,?,?)",
                         (ip, rule_id, datetime.now().isoformat(), exp, reason))

    def save_health(self, status: str, s_ok: bool, a_ok: bool, d_ok: bool, details: dict):
        with self._conn() as conn:
            conn.execute("""INSERT INTO health_history
                (timestamp,overall_status,services_ok,agents_ok,disk_ok,details)
                VALUES(?,?,?,?,?,?)""",
                (datetime.now().isoformat(), status, int(s_ok), int(a_ok), int(d_ok),
                 json.dumps(details, cls=DateTimeEncoder)[:4000]))

    def get_recent_alerts(self, limit: int = 500) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_metrics(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM metrics").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def set_metric(self, key: str, value):
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO metrics(key,value,updated) VALUES(?,?,?)",
                         (key, str(value), datetime.now().isoformat()))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ACTIVE RESPONSE MANAGER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ActiveResponseManager:
    FW_SCRIPT      = "/var/ossec/active-response/bin/firewall-drop"
    ACCT_SCRIPT    = "/var/ossec/active-response/bin/disable-account"
    QUAR_SCRIPT    = "/var/ossec/active-response/bin/quarantine-file.sh"
    CLEANUP_SCRIPT = "/var/ossec/active-response/bin/cleanup-timeouts.sh"

    def block_ip(self, ip: str, rule_id: str, reason: str, timeout: int = 3600) -> bool:
        try:
            r = subprocess.run([self.FW_SCRIPT, "add", "monitor-engine", ip, str(timeout)],
                               capture_output=True, text=True, timeout=10)
            ok = r.returncode == 0
            self._log("FIREWALL", f"{'Blocked' if ok else 'FAIL block'} {ip} ({reason})")
            return ok
        except Exception as e:
            self._log("FIREWALL_ERR", str(e)); return False

    def disable_account(self, username: str, rule_id: str, srcip: str, timeout: int = 300) -> bool:
        try:
            r = subprocess.run([self.ACCT_SCRIPT, "add", "monitor-engine", username, str(timeout)],
                               capture_output=True, text=True, timeout=10)
            ok = r.returncode == 0
            self._log("ACCOUNT", f"{'Disabled' if ok else 'FAIL disable'} {username} from {srcip}")
            return ok
        except Exception as e:
            self._log("ACCOUNT_ERR", str(e)); return False

    def quarantine_file(self, path: str, rule_id: str) -> bool:
        try:
            r = subprocess.run([self.QUAR_SCRIPT, "add", "monitor-engine"],
                               input=json.dumps({"rule": {"id": rule_id}, "data": {"file": path}}),
                               capture_output=True, text=True, timeout=10)
            ok = r.returncode == 0
            self._log("QUARANTINE", f"{'Quarantined' if ok else 'FAIL quarantine'} {path}")
            return ok
        except Exception as e:
            self._log("QUARANTINE_ERR", str(e)); return False

    def run_cleanup(self) -> bool:
        try:
            r = subprocess.run([self.CLEANUP_SCRIPT], capture_output=True, text=True, timeout=30)
            ok = r.returncode == 0
            self._log("CLEANUP", "OK" if ok else r.stderr[:100])
            return ok
        except Exception as e:
            self._log("CLEANUP_ERR", str(e)); return False

    @staticmethod
    def _log(action: str, msg: str):
        try:
            os.makedirs(f"{BACKUP_BASE}/log", exist_ok=True)
            with open(LOG_FILE, "a") as f:
                f.write(f"{datetime.now().isoformat()} [{action}] {msg}\n")
        except Exception:
            pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ① LOG INTERCEPTION — parser for each source type
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class LogInterceptor:
    """
    Tails all configured log sources and converts each raw line
    into a normalized internal alert dict.

    Schema (matches SOC Dashboard v2 REST API expectations):
    {
        id, timestamp, level, severity, color, rule_id,
        description, reason, groups, mitre,
        agent_id, agent_name, agent_ip,
        srcip, dstip, location, full_log, source,
        blocked, quarantined, account_disabled, email_sent
    }
    """

    def __init__(self):
        self._pos: dict[str, int] = {}   # file path → byte offset

    # ── generic tail ────────────────────────────────
    def _tail(self, path: str) -> list[str]:
        if not Path(path).exists():
            return []
        pos = self._pos.get(path, 0)
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                lines = f.readlines()
                self._pos[path] = f.tell()
            return [l.rstrip() for l in lines if l.strip()]
        except Exception:
            return []

    # ── build normalized alert ──────────────────────
    @staticmethod
    def _normalize(rule_id: str, level: int, desc: str, source: str,
                   groups: list = None, agent_name: str = "", agent_id: str = "000",
                   agent_ip: str = "", srcip: str = "", dstip: str = "",
                   location: str = "", full_log: str = "",
                   ts: str = None) -> dict:
        """Build a fully normalized alert dict from parsed fields."""
        sev, reason = classify_rule(rule_id, level, desc)
        mitre = MITRE_MAPPING.get(rule_id, [])
        color = SEV_COLOR_CSS.get(sev, SEV_COLOR_CSS["INFO"])["accent"]
        uid = f"{source}_{rule_id}_{int(time.time()*1000)}_{random.randint(100,999)}"
        return {
            "id":          uid,
            "timestamp":   ts or datetime.now(timezone.utc).isoformat(),
            "level":       level,
            "severity":    sev,
            "color":       color,
            "rule_id":     rule_id,
            "description": desc,
            "reason":      reason,
            "groups":      groups or [],
            "mitre":       mitre,
            "agent_id":    agent_id,
            "agent_name":  agent_name or "wazuh-server",
            "agent_ip":    agent_ip,
            "srcip":       srcip,
            "dstip":       dstip,
            "location":    location,
            "full_log":    full_log[:600],
            "source":      source,
            "blocked":     False,
            "quarantined": False,
            "account_disabled": False,
            "email_sent":  False,
        }

    # ── SOURCE 1: Wazuh alerts.json ─────────────────
    def read_wazuh_alerts(self) -> list[dict]:
        """
        PRIMARY source — tails /var/ossec/logs/alerts/alerts.json.
        Each line is a complete JSON alert from the Wazuh manager.
        """
        results = []
        for line in self._tail(ALERT_FILE):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule  = raw.get("rule", {})
            rule_id = str(rule.get("id", ""))
            level   = int(rule.get("level", 0))
            desc    = rule.get("description", "")
            groups  = rule.get("groups", [])
            agent   = raw.get("agent", {})
            data    = raw.get("data", {})

            a = self._normalize(
                rule_id   = rule_id,
                level     = level,
                desc      = desc,
                source    = "wazuh_api",
                groups    = groups,
                agent_id  = agent.get("id", "000"),
                agent_name= agent.get("name", "manager"),
                agent_ip  = agent.get("ip", ""),
                srcip     = data.get("srcip", raw.get("srcip", "")),
                dstip     = data.get("dstip", ""),
                location  = raw.get("location", ""),
                full_log  = raw.get("full_log", ""),
                ts        = raw.get("timestamp"),
            )
            # Preserve original Wazuh alert ID when available
            if raw.get("id"):
                a["id"] = str(raw["id"])
            results.append(a)
        return results

    # ── SOURCE 2: Zeek logs ──────────────────────────
    def read_zeek_logs(self) -> list[dict]:
        """
        Tails all *.log files in ZEEK_LOG_DIR.
        Maps Zeek log types to rules 100900-100907 (zeek_rules.xml).
        """
        results = []
        for logfile in glob.glob(f"{ZEEK_LOG_DIR}/*.log") if Path(ZEEK_LOG_DIR).exists() else []:
            log_type = Path(logfile).stem
            for line in self._tail(logfile):
                if line.startswith("#"):
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                srcip = raw.get("id.orig_h", raw.get("orig_h", ""))
                dstip = raw.get("id.resp_h", raw.get("resp_h", ""))
                dstport = str(raw.get("id.resp_p", raw.get("resp_p", "")))
                ts_f  = raw.get("ts", time.time())
                try:
                    ts = datetime.fromtimestamp(float(ts_f), tz=timezone.utc).isoformat()
                except Exception:
                    ts = None

                # Map Zeek log type → rule ID + description
                rule_id, level, desc = "100900", 0, f"Zeek {log_type} event"

                if log_type == "notice":
                    rule_id, level = "100900", 10
                    desc = raw.get("msg", "Zeek notice alert")
                elif log_type == "dns":
                    query = raw.get("query", "")
                    if "cti.wazuh.com" in query:
                        rule_id, level = "100905", 0    # suppressed
                        continue
                    rule_id, level = "100901", 5
                    desc = f"DNS query: {query} from {srcip}"
                elif log_type == "ssl":
                    val = raw.get("validation_status", "")
                    if "expired" in val:
                        rule_id, level, desc = "100907", 12, f"Expired cert: {srcip} → {dstip}"
                    elif "self signed" in val:
                        rule_id, level, desc = "100906", 8,  f"Self-signed cert: {srcip} → {dstip}"
                    else:
                        continue
                elif log_type == "conn":
                    if raw.get("conn_state") == "REJ":
                        rule_id, level = "100903", 7
                        desc = f"Rejected connection {srcip} → {dstip}:{dstport}"
                    else:
                        continue
                elif log_type == "http":
                    method = raw.get("method", "")
                    uri    = raw.get("uri", "")
                    status = str(raw.get("status_code", ""))
                    level  = 5
                    rule_id = "100900"
                    desc = f"HTTP {method} {uri[:80]} [{status}] from {srcip}"
                else:
                    continue

                results.append(self._normalize(
                    rule_id=rule_id, level=level, desc=desc,
                    source=f"zeek_{log_type}",
                    groups=["zeek", log_type],
                    agent_name="TSC-Agent", agent_id="001",
                    agent_ip=srcip, srcip=srcip, dstip=dstip,
                    location=logfile, full_log=json.dumps(raw)[:500], ts=ts,
                ))
        return results

    # ── SOURCE 3: Tetragon ──────────────────────────
    def read_tetragon_logs(self) -> list[dict]:
        """
        Tails /var/log/tetragon/tetragon.log.
        Maps process events to rules 700000-700006 (700000-tetragon.xml).
        """
        SHELL_BINS = {"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh"}
        WGET_CURL  = {"/usr/bin/wget", "/usr/bin/curl"}
        PKG_MGRS   = {"/usr/bin/apt", "/usr/bin/yum", "/usr/bin/dpkg",
                      "/usr/bin/rpm", "/usr/bin/apk"}

        results = []
        for line in self._tail(TETRAGON_LOG):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule_id = level = desc = None

            if "process_exec" in raw:
                proc   = raw["process_exec"].get("process", {})
                binary = proc.get("binary", "")
                args   = proc.get("arguments", "")
                ns     = proc.get("pod", {}).get("namespace", "host")
                if binary in SHELL_BINS:
                    rule_id, level = "700004", 8
                    desc = f"Shell exec in container [{ns}]: {binary} {args}"
                elif binary in WGET_CURL:
                    rule_id, level = "700005", 7
                    desc = f"Remote fetch [{ns}]: {binary} {args}"
                elif binary in PKG_MGRS:
                    rule_id, level = "700006", 7
                    desc = f"Package manager [{ns}]: {binary} {args}"
                else:
                    rule_id, level = "700000", 3
                    desc = f"Process exec: {binary} {args}"

            elif "process_exit" in raw:
                proc   = raw["process_exit"].get("process", {})
                binary = proc.get("binary", "")
                status = raw["process_exit"].get("status", "")
                if status:
                    rule_id, level = "700003", 5
                    desc = f"Process exit [{status}]: {binary}"
                else:
                    rule_id, level = "700001", 3
                    desc = f"Process exit: {binary}"

            elif "process_kprobe" in raw:
                proc   = raw["process_kprobe"].get("process", {})
                binary = proc.get("binary", "")
                func   = raw["process_kprobe"].get("function_name", "")
                rule_id, level = "700002", 3
                desc = f"Kernel probe: {func} by {binary}"
            else:
                continue

            results.append(self._normalize(
                rule_id=rule_id, level=level, desc=desc,
                source="tetragon",
                groups=["tetragon", "container"],
                agent_name="TSC-Agent", agent_id="001",
                location=TETRAGON_LOG,
                full_log=json.dumps(raw)[:500],
            ))
        return results

    # ── SOURCE 4: Active-response log ───────────────
    def read_active_response_log(self) -> list[dict]:
        """
        Tails /var/ossec/logs/active-responses.log.
        Generates rule 100950 (firewall-drop) or 100951 (account-disabled).
        """
        results = []
        ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
        for line in self._tail(ACTIVE_RESP_LOG):
            if "firewall-drop" in line or "netsh" in line:
                rule_id, level = "100950", 6
                desc = "AR FIREWALL-DROP executed"
            elif "disable-account" in line:
                rule_id, level = "100951", 6
                desc = "AR ACCOUNT-DISABLE executed"
            else:
                continue
            ips = ip_re.findall(line)
            srcip = ips[0] if ips else ""
            results.append(self._normalize(
                rule_id=rule_id, level=level, desc=f"{desc}: {line[:100]}",
                source="active_response",
                groups=["active_response", "firewall"],
                srcip=srcip, location=ACTIVE_RESP_LOG,
                full_log=line,
            ))
        return results

    # ── SOURCE 5: Apache2 / Nginx access logs ───────
    def read_web_logs(self) -> list[dict]:
        """
        Tails Apache2 and Nginx access logs.
        Detects path traversal, SQLi, XSS, web scanner user-agents.
        """
        results = []
        TRAVERSAL_RE = re.compile(r"\.\./|%2e%2e/|\.\.\\", re.IGNORECASE)
        SQLI_RE      = re.compile(r"union\s+select|drop\s+table|' or '1'='1|--\s*$", re.IGNORECASE)
        XSS_RE       = re.compile(r"<script|javascript:|onerror=|onload=", re.IGNORECASE)
        SCANNER_RE   = re.compile(r"nikto|sqlmap|dirb|gobuster|wfuzz|masscan", re.IGNORECASE)

        log_files = [
            (APACHE_ACCESS, "apache"), (NGINX_ACCESS, "nginx"),
            (APACHE_ERROR,  "apache"), (NGINX_ERROR,  "nginx"),
        ]
        for path, srv in log_files:
            for line in self._tail(path):
                rule_id = level = desc = srcip = None

                if SQLI_RE.search(line):
                    rule_id = "100805" if srv == "apache" else "100806"
                    level, desc = 10, f"SQL INJECTION via {srv.upper()}: {line[:80]}"
                elif TRAVERSAL_RE.search(line):
                    rule_id = "100800" if srv == "apache" else "100803"
                    level, desc = 8, f"PATH TRAVERSAL via {srv.upper()}: {line[:80]}"
                elif XSS_RE.search(line):
                    rule_id = "100807"
                    level, desc = 8, f"XSS ATTEMPT via {srv.upper()}: {line[:80]}"
                elif SCANNER_RE.search(line):
                    rule_id = "100808"
                    level, desc = 10, f"WEB SCANNER via {srv.upper()}: {line[:80]}"
                else:
                    continue

                ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                srcip = ip_m.group(1) if ip_m else ""

                results.append(self._normalize(
                    rule_id=rule_id, level=level, desc=desc,
                    source=f"apache" if srv == "apache" else "nginx",
                    groups=["web", srv, "attack"],
                    srcip=srcip, location=path, full_log=line,
                ))
        return results

    # ── AGGREGATE: read all sources in one call ──────
    def read_all(self) -> list[dict]:
        """
        Called by the main poll loop every POLL_INTERVAL seconds.
        Returns a combined list of normalized alerts from all log sources.
        """
        all_alerts = []
        for reader, name in [
            (self.read_wazuh_alerts,      "wazuh_alerts.json"),
            (self.read_zeek_logs,         "zeek"),
            (self.read_tetragon_logs,     "tetragon"),
            (self.read_active_response_log,"active_response"),
            (self.read_web_logs,          "web_logs"),
        ]:
            try:
                batch = reader()
                if batch:
                    logging.info(f"[INTERCEPT] {name}: {len(batch)} new lines")
                all_alerts.extend(batch)
            except Exception as e:
                logging.error(f"[INTERCEPT] {name} error: {e}")
        return all_alerts


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ALERT PROCESSOR (SOAR engine)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class AlertProcessor:
    """
    Receives normalized alert dicts from LogInterceptor,
    applies SOAR actions (block / quarantine / account-disable),
    sends Gmail alerts for CRITICAL/HIGH/MEDIUM,
    and stores everything in SQLite + the in-memory ring buffer.
    """

    def __init__(self, db: MonitorDatabase, ar: ActiveResponseManager,
                 notifier: EmailNotifier, store: deque):
        self.db       = db
        self.ar       = ar
        self.notifier = notifier
        self.store    = store
        self._dedup: dict[str, float] = {}   # rule_id+srcip → timestamp

        self.stats = {
            "alerts_processed": 0, "ips_blocked": 0,
            "accounts_disabled": 0, "files_quarantined": 0,
            "emails_sent": 0, "start_time": datetime.now(),
        }

    def process(self, alert: dict):
        """Full SOAR pipeline for one alert."""
        rule_id = alert.get("rule_id", "")
        level   = alert.get("level", 0)
        sev     = alert.get("severity", "INFO")
        srcip   = alert.get("srcip", "")
        desc    = alert.get("description", "")

        # ── skip zero-level and whitelisted FP rules ─
        if level == 0 or rule_id in ("100209",):
            return

        # ── brute-force escalation ────────────────────
        if rule_id in FAILED_LOGIN_RULES and srcip:
            self.db.record_failed_login(srcip, rule_id)
            count = self.db.failed_login_count(srcip, FAILED_LOGIN_WINDOW_SEC)
            if count >= CRITICAL_THRESHOLD:
                alert["severity"] = sev = "CRITICAL"
                alert["reason"]   = f"CRITICAL BRUTE FORCE: {count} attempts in window"
                alert["level"]    = level = 13
            elif count >= SEVERE_THRESHOLD:
                alert["severity"] = sev = "HIGH"
                alert["reason"]   = f"HIGH BRUTE FORCE: {count} attempts in window"
                alert["level"]    = level = 10
            elif count >= FAILED_LOGIN_THRESHOLD:
                alert["severity"] = sev = "MEDIUM"
                alert["reason"]   = f"MEDIUM BRUTE FORCE: {count} attempts"
                alert["level"]    = level = 7

        # ── deduplication (5-min window) ─────────────
        dup_key = f"{rule_id}_{srcip}"
        now = time.time()
        if dup_key in self._dedup and now - self._dedup[dup_key] < ALERT_DEDUP_WINDOW:
            return
        self._dedup[dup_key] = now

        # ── SOAR: firewall-drop ───────────────────────
        blocked = False
        if rule_id in ACTIVE_RESPONSE_RULES and srcip:
            if self.ar.block_ip(srcip, rule_id, alert.get("reason",""), 3600):
                blocked = True
                alert["blocked"] = True
                self.stats["ips_blocked"] += 1
                self.db.record_ip_block(srcip, rule_id, alert.get("reason",""), 3600)

        # ── SOAR: account-disable ─────────────────────
        acct_disabled = False
        if rule_id in ACCOUNT_DISABLE_RULES:
            username = (alert.get("full_log", "")
                        and re.search(r"dstuser=(\S+)", alert.get("full_log","") or ""))
            username = username.group(1) if username else ""
            if username and self.ar.disable_account(username, rule_id, srcip, 300):
                acct_disabled = True
                alert["account_disabled"] = True
                self.stats["accounts_disabled"] += 1

        # ── SOAR: file quarantine ─────────────────────
        quarantined = False
        if rule_id in QUARANTINE_RULES:
            fp_m = re.search(r'(?:file|path)=(\S+)', alert.get("full_log","") or "")
            file_path = fp_m.group(1) if fp_m else ""
            if file_path and self.ar.quarantine_file(file_path, rule_id):
                quarantined = True
                alert["quarantined"] = True
                self.stats["files_quarantined"] += 1

        # ── ③ Gmail alert for CRITICAL/HIGH/MEDIUM ───
        email_sent = False
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            actions = []
            if blocked:        actions.append(f"FIREWALL-DROP: {srcip} blocked for 3600s")
            if acct_disabled:  actions.append("ACCOUNT-DISABLE: user locked out for 300s")
            if quarantined:    actions.append("FILE-QUARANTINE: suspicious file isolated")

            if self.notifier.send_security_alert(alert, actions):
                email_sent = True
                alert["email_sent"] = True
                self.stats["emails_sent"] += 1

        # ── persist to DB ─────────────────────────────
        alert["id"] = self.db.save_alert(alert)

        # ── push to in-memory ring buffer (REST API) ──
        self.store.append(alert)
        self.stats["alerts_processed"] += 1

        # ── console output ─────────────────────────────
        self._print_alert(alert, blocked, acct_disabled, quarantined, email_sent)

    def _print_alert(self, a, blocked, acct, quar, email):
        badge = {"CRITICAL": C.RED+C.BOLD+"[ CRIT ]",
                 "HIGH":     C.ORANGE+C.BOLD+"[ HIGH ]",
                 "MEDIUM":   C.YELLOW+"[ MED  ]",
                 "LOW":      C.SKY+"[ LOW  ]"}.get(a["severity"], C.WHITE+"[ --- ]")
        ts = datetime.now().strftime("%H:%M:%S")
        src = f"SRC:{a['srcip']}" if a.get("srcip") else "SRC:N/A"
        print(f"\n{C.GRAY}┌─{C.RESET} {C.STEEL}{C.BOLD}{ts}{C.RESET}  "
              f"{badge}{C.RESET}  {C.WHITE}Rule:{C.CYAN}{a['rule_id']}{C.RESET}  "
              f"{C.GRAY}(Lv{a['level']}){C.RESET}  {C.STEEL}{src}{C.RESET}  "
              f"{C.GRAY}[{a['source']}]{C.RESET}")
        print(f"{C.GRAY}│{C.RESET}  {C.WHITE}{a['description'][:100]}{C.RESET}")
        acts = []
        if blocked:  acts.append(f"{C.CYAN}[FIREWALL-DROP]{C.RESET}")
        if quar:     acts.append(f"{C.BLUE}[QUARANTINE]{C.RESET}")
        if acct:     acts.append(f"{C.SKY}[ACCT-LOCK]{C.RESET}")
        if email:    acts.append(f"{C.GREEN}[EMAIL-SENT]{C.RESET}")
        if acts:
            print(f"{C.GRAY}│{C.RESET}  {C.DIM}Response:{C.RESET}  " + "  ".join(acts))
        print(f"{C.GRAY}└{'─'*65}{C.RESET}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WAZUH SERVICE MONITOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ServiceMonitor:
    def check_all(self) -> dict:
        results = {}
        for svc in WAZUH_SERVICES:
            try:
                r = subprocess.run(["systemctl", "is-active", svc],
                                   capture_output=True, text=True, timeout=5)
                ok = r.returncode == 0
                results[svc] = {"status": r.stdout.strip(), "healthy": ok}
            except Exception as e:
                results[svc] = {"status": "error", "healthy": False, "error": str(e)}
        all_ok = all(v["healthy"] for v in results.values())
        return {"services": results, "all_healthy": all_ok}


class AgentMonitor:
    def check_all(self) -> dict:
        try:
            r = subprocess.run(["/var/ossec/bin/agent_control", "-l"],
                               capture_output=True, text=True, timeout=10)
            active = disconnected = 0
            agents = []
            for line in r.stdout.splitlines():
                if "->" not in line:
                    continue
                is_active = "Active" in line
                if is_active:
                    active += 1
                else:
                    disconnected += 1
                parts = line.split()
                agents.append({"id": parts[0] if parts else "",
                                "name": parts[1] if len(parts)>1 else "",
                                "ip": parts[2] if len(parts)>2 else "",
                                "status": "active" if is_active else "disconnected"})
            total = active + disconnected
            return {
                "agents": agents,
                "summary": {
                    "active_count": active,
                    "disconnected_count": disconnected,
                    "healthy_percent": (active/total*100) if total else 0,
                    "pending_count": 0,
                },
                "healthy": disconnected == 0,
            }
        except Exception as e:
            return {"agents": [], "healthy": False,
                    "summary": {"active_count": 0, "disconnected_count": 0, "healthy_percent": 0, "pending_count": 0},
                    "error": str(e)}


class DiskMonitor:
    def check_all(self) -> dict:
        disks = {}
        all_ok = True
        for path in DISK_PATHS:
            if not Path(path).exists():
                disks[path] = {"status": "MISSING", "healthy": False, "percent_used": 0, "free_gb": 0}
                all_ok = False
                continue
            try:
                st = shutil.disk_usage(path)
                pct = st.used / st.total * 100
                status = ("CRITICAL" if pct > DISK_CRITICAL_PERCENT else
                          "WARNING"  if pct > DISK_WARNING_PERCENT  else "HEALTHY")
                if status != "HEALTHY":
                    all_ok = False
                disks[path] = {
                    "status": status, "healthy": status == "HEALTHY",
                    "percent_used": round(pct, 1),
                    "free_gb": round(st.free / 1e9, 2),
                    "total_gb": round(st.total / 1e9, 2),
                    "used_gb":  round(st.used / 1e9, 2),
                }
            except Exception as e:
                disks[path] = {"status": "ERROR", "healthy": False, "error": str(e),
                               "percent_used": 0, "free_gb": 0}
                all_ok = False
        return {"disks": disks, "all_healthy": all_ok}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ④ FLASK REST API
#     Same endpoints as wazuh_collector.py — SOC Dashboard v2 connects here
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Global shared state (populated by engine, read by API)
_alert_store:  deque  = deque(maxlen=MAX_ALERTS)
_store_lock    = threading.Lock()
_metrics_cache: dict  = {}
_engine_ref           = None   # set after CompleteMonitorEngine is created

app = Flask(__name__)
CORS(app)


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/alerts")
def api_alerts():
    limit      = int(request.args.get("limit", 200))
    min_level  = int(request.args.get("min_level", 0))
    sev_filter = request.args.get("severity", "").upper()
    src_filter = request.args.get("source", "")
    search     = request.args.get("search", "").lower()

    with _store_lock:
        alerts = list(_alert_store)

    alerts = sorted(alerts, key=lambda a: a.get("timestamp",""), reverse=True)

    if min_level:  alerts = [a for a in alerts if a.get("level",0) >= min_level]
    if sev_filter: alerts = [a for a in alerts if a.get("severity") == sev_filter]
    if src_filter: alerts = [a for a in alerts if (a.get("source","")).startswith(src_filter)]
    if search:
        alerts = [a for a in alerts if
                  search in a.get("description","").lower() or
                  search in a.get("srcip","").lower() or
                  search in a.get("agent_name","").lower() or
                  search in a.get("rule_id","").lower() or
                  search in a.get("source","").lower()]

    return jsonify({"total": len(alerts), "alerts": alerts[:limit]})


@app.route("/api/metrics")
def api_metrics():
    with _store_lock:
        alerts = list(_alert_store)

    sc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    srcs: dict = {}
    for a in alerts:
        sev = a.get("severity", "INFO")
        sc[sev] = sc.get(sev, 0) + 1
        src = a.get("source", "unknown")
        srcs[src] = srcs.get(src, 0) + 1

    engine_stats = _engine_ref.alert_processor.stats if _engine_ref else {}
    return jsonify({
        "total_alerts":    len(alerts),
        "severity_counts": sc,
        "source_counts":   srcs,
        "emails_sent":     engine_stats.get("emails_sent", 0),
        "api_errors":      0,
        "total_ingested":  engine_stats.get("alerts_processed", 0),
        "ips_blocked":     engine_stats.get("ips_blocked", 0),
        "accounts_disabled": engine_stats.get("accounts_disabled", 0),
        "files_quarantined": engine_stats.get("files_quarantined", 0),
        "last_poll":       datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/agents")
def api_agents():
    if _engine_ref:
        return jsonify({"agents": _engine_ref.agent_monitor.check_all().get("agents", [])})
    return jsonify({"agents": []})


@app.route("/api/config")
def api_config():
    return jsonify({
        "poll_interval":    POLL_INTERVAL,
        "min_level_log":    0,
        "email_level":      EMAIL_MIN_LEVEL,
        "alert_to":         ALERT_EMAIL,
        "max_alerts_buffer": MAX_ALERTS,
        "log_sources": [
            ALERT_FILE, ZEEK_LOG_DIR, TETRAGON_LOG, ACTIVE_RESP_LOG,
            APACHE_ACCESS, NGINX_ACCESS,
        ],
    })


@app.route("/api/send_alert", methods=["POST"])
def api_send_alert():
    """
    Manual alert dispatch from the SOC Dashboard v2 drawer.
    Body: { alert_id, to, note (optional), override_subject (optional) }
    """
    data     = request.get_json() or {}
    alert_id = data.get("alert_id", "")
    to_addr  = data.get("to", "")
    note     = data.get("note", "")

    with _store_lock:
        matches = [a for a in _alert_store if str(a.get("id")) == str(alert_id)]

    if not matches:
        # Allow sending a manual synthetic alert
        alert = {
            "id": alert_id or f"manual_{int(time.time())}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": 7, "severity": "MEDIUM", "color": "#378ADD",
            "rule_id": "MANUAL", "description": data.get("override_subject", "Manual SOC alert"),
            "reason": "Analyst-initiated", "groups": ["manual"],
            "mitre": [], "agent_name": "SOC Dashboard", "agent_id": "000",
            "agent_ip": "", "srcip": "", "dstip": "",
            "location": "dashboard", "source": "manual",
            "full_log": note,
        }
    else:
        alert = dict(matches[0])
        if note:
            alert["_analyst_note"] = note

    # Override recipient if provided
    orig_to = ALERT_EMAIL
    if to_addr:
        import importlib
        globals()["ALERT_EMAIL"] = to_addr

    notifier = _engine_ref.notifier if _engine_ref else EmailNotifier()
    ok = notifier.send_security_alert(alert, [])
    globals()["ALERT_EMAIL"] = orig_to

    return jsonify({"sent": ok})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COMPLETE MONITOR ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CompleteMonitorEngine:
    """
    Orchestrates all sub-systems:
      ① LogInterceptor → reads all log sources
      ② AlertProcessor → SOAR + Gmail
      ③ ServiceMonitor, AgentMonitor, DiskMonitor → health checks
      ④ Flask REST API → serves SOC Dashboard v2
    """

    def __init__(self):
        global _engine_ref
        _engine_ref = self

        # Init directories
        for d in [f"{BACKUP_BASE}/log", f"{BACKUP_BASE}/firewall/blocks",
                  f"{BACKUP_BASE}/accounts/disabled", f"{BACKUP_BASE}/quarantine/files"]:
            os.makedirs(d, exist_ok=True)

        self.db               = MonitorDatabase(DB_FILE)
        self.ar               = ActiveResponseManager()
        self.notifier         = EmailNotifier()
        self.interceptor      = LogInterceptor()
        self.service_monitor  = ServiceMonitor()
        self.agent_monitor    = AgentMonitor()
        self.disk_monitor     = DiskMonitor()
        self.alert_processor  = AlertProcessor(self.db, self.ar, self.notifier, _alert_store)

        self._running = True
        self._timers  = {
            "service": 0, "agent": 0, "disk": 0, "health": 0,
        }
        self.stats = {"start_time": datetime.now(), "health_checks": 0}

    # ── main entry ──────────────────────────────────
    def run(self):
        self._setup_logging()
        self._print_banner()

        if not Path(ALERT_FILE).exists():
            print(f"\n{C.RED}[FAULT]{C.RESET} Alert file not found: {C.CYAN}{ALERT_FILE}{C.RESET}")
            print(f"{C.GRAY}       Ensure wazuh-manager is running and alerts.json logging is enabled.{C.RESET}")
            return

        # Start Flask REST API in background thread
        flask_thread = threading.Thread(
            target=lambda: app.run(host=FLASK_HOST, port=FLASK_PORT,
                                   debug=False, use_reloader=False),
            daemon=True, name="flask-api"
        )
        flask_thread.start()
        print(f"\n{C.GREEN}[API]{C.RESET}  SOC Dashboard REST API live at "
              f"{C.CYAN}http://{FLASK_HOST}:{FLASK_PORT}{C.RESET}")

        # Perform initial health check
        self._health_check()

        print(f"\n{C.GREEN}[LIVE]{C.RESET}  {C.WHITE}Intercepting logs — tailing {len([ALERT_FILE,ZEEK_LOG_DIR,TETRAGON_LOG,ACTIVE_RESP_LOG,APACHE_ACCESS,NGINX_ACCESS])} sources{C.RESET}")
        print(f"{C.GRAY}        Emails → {ALERT_EMAIL}  (threshold: {EMAIL_MIN_LEVEL}+ = MEDIUM/HIGH/CRITICAL){C.RESET}\n")

        # ── MAIN LOOP ────────────────────────────────
        try:
            while self._running:
                now = time.time()

                # ① Intercept and process all new log lines
                new_alerts = self.interceptor.read_all()
                for alert in new_alerts:
                    self.alert_processor.process(alert)

                # ② Periodic sub-checks
                if now - self._timers["service"] > SERVICE_CHECK_INTERVAL:
                    self._check_services()
                    self._timers["service"] = now

                if now - self._timers["agent"] > AGENT_CHECK_INTERVAL:
                    self._check_agents()
                    self._timers["agent"] = now

                if now - self._timers["disk"] > DISK_CHECK_INTERVAL:
                    self._check_disk()
                    self._timers["disk"] = now

                if now - self._timers["health"] > HEALTH_CHECK_INTERVAL:
                    self._health_check()
                    self._timers["health"] = now

                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            self.shutdown()

    # ── sub-checkers ────────────────────────────────
    def _check_services(self) -> dict:
        result = self.service_monitor.check_all()
        if not result["all_healthy"]:
            bad = [s for s, v in result["services"].items() if not v["healthy"]]
            logging.warning(f"Service degradation: {bad}")
        return result

    def _check_agents(self) -> dict:
        result = self.agent_monitor.check_all()
        dc = result.get("summary", {}).get("disconnected_count", 0)
        if dc > 0:
            logging.warning(f"{dc} agent(s) disconnected")
        return result

    def _check_disk(self) -> dict:
        result = self.disk_monitor.check_all()
        if not result["all_healthy"]:
            crit = [p for p, v in result["disks"].items() if v.get("status") == "CRITICAL"]
            if crit:
                logging.error(f"Disk CRITICAL: {crit}")
        return result

    # ── health check + email ─────────────────────────
    def _health_check(self):
        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        print(f"\n{C.BLUE}{C.BOLD}╔══ HEALTH CHECK  ·  {ts} ══╗{C.RESET}")

        services     = self._check_services()
        agents       = self._check_agents()
        disks        = self._check_disk()
        all_ok       = services["all_healthy"] and agents.get("healthy", True) and disks["all_healthy"]
        overall      = "HEALTHY" if all_ok else ("CRITICAL" if not services["all_healthy"] else "DEGRADED")
        status_color = C.GREEN if all_ok else (C.RED if overall == "CRITICAL" else C.YELLOW)

        print(f"{C.BLUE}║{C.RESET}  {status_color}{C.BOLD}{overall}{C.RESET}  "
              f"{C.GRAY}services:{sum(v['healthy'] for v in services['services'].values())}/{len(WAZUH_SERVICES)}"
              f"  agents:{agents.get('summary',{}).get('active_count',0)} online"
              f"  disk:{sum(1 for v in disks['disks'].values() if v.get('healthy',False))}/{len(DISK_PATHS)} OK{C.RESET}")

        # SOAR stats
        ap = self.alert_processor.stats
        print(f"{C.BLUE}║{C.RESET}  {C.STEEL}Processed:{C.CYAN}{ap['alerts_processed']}{C.RESET}  "
              f"{C.STEEL}Blocked:{C.CYAN}{ap['ips_blocked']}{C.RESET}  "
              f"{C.STEEL}Locked:{C.CYAN}{ap['accounts_disabled']}{C.RESET}  "
              f"{C.STEEL}Quar:{C.CYAN}{ap['files_quarantined']}{C.RESET}  "
              f"{C.STEEL}Emails:{C.CYAN}{ap['emails_sent']}{C.RESET}")
        print(f"{C.BLUE}╚{'═'*55}{C.RESET}\n")

        report = {
            "overall_status": overall, "timestamp": datetime.now().isoformat(),
            "services": services, "agents": agents, "disks": disks,
            "issues": [],
            "stats": {
                "alerts_processed":  ap["alerts_processed"],
                "ips_blocked":       ap["ips_blocked"],
                "accounts_disabled": ap["accounts_disabled"],
                "files_quarantined": ap["files_quarantined"],
                "emails_sent":       ap["emails_sent"],
            }
        }

        self.db.save_health(overall, services["all_healthy"],
                            agents.get("healthy", True), disks["all_healthy"], report)
        self.stats["health_checks"] += 1

        if self.notifier.should_send_health_alert(all_ok):
            self.notifier.send_health_alert(report)

    # ── banner ──────────────────────────────────────
    def _print_banner(self):
        B = C.BLUE+C.BOLD; R = C.RESET; T = C.CYAN+C.BOLD; D = C.STEEL; W = C.WHITE
        print(f"\n{B}╔══════════════════════════════════════════════════════════════════════╗{R}")
        print(f"{B}║{R}  {T}WAZUH SOC DEFENSE PLATFORM v3  ·  CBSA PROJECT GROUP 7{R}              {B}║{R}")
        print(f"{B}╠══════════════════════════════════════════════════════════════════════╣{R}")
        for label, val in [
            ("Alert sources",     f"{ALERT_FILE} + Zeek + Tetragon + Apache2/Nginx"),
            ("Email threshold",   f"Level ≥ {EMAIL_MIN_LEVEL} (MEDIUM / HIGH / CRITICAL)"),
            ("Notification →",    ALERT_EMAIL),
            ("REST API",          f"http://0.0.0.0:{FLASK_PORT}  (SOC Dashboard v2)"),
            ("SQLite DB",         DB_FILE),
            ("Detection rules",   f"{len(CRITICAL_RULES)} CRIT  {len(HIGH_RULES)} HIGH  {len(MEDIUM_RULES)} MED  {len(LOW_RULES)} LOW"),
        ]:
            print(f"{B}║{R}  {D}{label:<22}{R}  {C.CYAN}{val}{R}")
        print(f"{B}╚══════════════════════════════════════════════════════════════════════╝{R}")

    # ── logging setup ────────────────────────────────
    @staticmethod
    def _setup_logging():
        os.makedirs(f"{BACKUP_BASE}/log", exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE, level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
        # Also print WARNING+ to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        logging.getLogger("").addHandler(ch)

    # ── graceful shutdown ────────────────────────────
    def shutdown(self):
        self._running = False
        ap = self.alert_processor.stats
        uptime = datetime.now() - self.stats["start_time"]
        print(f"\n{C.BLUE}{C.BOLD}╔══ SHUTDOWN SUMMARY ══╗{C.RESET}")
        for label, val in [
            ("Health checks",    self.stats["health_checks"]),
            ("Alerts processed", ap["alerts_processed"]),
            ("IPs blocked",      ap["ips_blocked"]),
            ("Accounts locked",  ap["accounts_disabled"]),
            ("Files quarantined",ap["files_quarantined"]),
            ("Emails sent",      ap["emails_sent"]),
            ("Uptime",           str(uptime).split(".")[0]),
        ]:
            print(f"{C.BLUE}║{C.RESET}  {C.STEEL}{label:<22}{C.RESET} {C.CYAN}{val}{C.RESET}")
        print(f"{C.BLUE}╚{'═'*30}{C.RESET}")
        sys.exit(0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    """
    Run with:
        # Required
        pip install flask flask-cors requests

        # Optional (for .env support)
        pip install python-dotenv

        # Override credentials via env vars
        export GMAIL_USER=sop98886@gmail.com
        export GMAIL_PASS=kizagpavcmgoodpi
        export ALERT_TO=sopanha.tith@student.cadt.edu.kh

        python monitoring.py
    """
    engine = CompleteMonitorEngine()
    engine.run()


if __name__ == "__main__":
    main()