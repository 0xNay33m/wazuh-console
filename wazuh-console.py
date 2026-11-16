#!/usr/bin/env python3
"""
Wazuh Console  (v3.1): agent + manager, Linux + Windows
=====================================================
Step 1 detects WHAT it runs on (Linux or Windows) and WHETHER it is a Wazuh
agent or a Wazuh manager, then runs the matching workflow:

  Linux agent    audit + safe enable of FIM/Rootcheck/Syscollector/SCA + log sources
  Windows agent  same modules + Windows Event Log channels (Security, Sysmon, ...)
  Linux manager  audit of services/modules/integrations/cloud/fleet, safe enable of
                 modules + Vulnerability Detection, agent-group baseline push, API fleet view

Audit is read-only. Changes are opt-in, previewed as a diff, backed up,
validated, and rolled back automatically on failure.

Interactive:   sudo python3 wazuh-console.py              (Windows: run as Administrator)
Automation:    --detect | --audit [--json] | --enable 2,3,8|all [--dry-run] [--yes]
               --validate | --list-backups | --rollback [FILE|latest]
               manager: --fleet [--deep] | --group-baseline NAME [--sysmon]
Overrides:     --platform {auto,linux,windows}  --role {auto,agent,manager}  --root DIR
"""

import argparse
import datetime
import difflib
import base64
import fnmatch
import functools
import getpass
import glob
import json
import os
import platform as _platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import fcntl
except ImportError:   # Windows
    fcntl = None

# ----------------------------------------------------------------------------
# Paths (all derived from ROOT so the tool can be tested against a copy)
# ----------------------------------------------------------------------------
PLATFORM = "windows" if os.name == "nt" else "linux"
ROLE = "agent"            # "agent" | "manager": set by detect_role() / --role
ROOT = None
CONF = AGENTD = CONTROL = LOG = STATE_FILE = SHARED = BACKUP_DIR = LOCK = None
BIN = SHARED_DIR = AGENT_CONTROL = AGENT_GROUPS = VERIFY_CONF = None
SERVICE_NAME = "wazuh-agent"
WIN_SERVICE = "WazuhSvc"
KEEP_BACKUPS = 20
JOURNALD_MIN_VERSION = (4, 8, 0)   # verify against Wazuh docs for your version
VULN_NEW_MIN_VERSION = (4, 8, 0)   # <vulnerability-detection> block; verify too

AGENT_DAEMONS = ["wazuh-agentd", "wazuh-execd", "wazuh-syscheckd",
                 "wazuh-logcollector", "wazuh-modulesd"]
MANAGER_DAEMONS = ["wazuh-analysisd", "wazuh-remoted", "wazuh-db",
                   "wazuh-modulesd", "wazuh-monitord", "wazuh-execd",
                   "wazuh-syscheckd", "wazuh-logcollector", "wazuh-authd",
                   "wazuh-apid"]
DAEMONS = AGENT_DAEMONS


def default_root(platform_name):
    env = os.environ.get("WAZUH_HOME")
    if env:
        return Path(env)
    if platform_name == "windows":
        for var in ("ProgramFiles(x86)", "ProgramFiles"):
            base = os.environ.get(var)
            if base and (Path(base) / "ossec-agent").is_dir():
                return Path(base) / "ossec-agent"
        return Path(os.environ.get("ProgramFiles(x86)",
                                   r"C:\Program Files (x86)")) / "ossec-agent"
    return Path("/var/ossec")


def configure_paths(root=None, platform_name=None):
    global PLATFORM, ROOT, CONF, AGENTD, CONTROL, LOG, STATE_FILE, SHARED
    global BACKUP_DIR, LOCK, BIN, SHARED_DIR, AGENT_CONTROL, AGENT_GROUPS
    global VERIFY_CONF
    PLATFORM = platform_name or PLATFORM
    ROOT = Path(root) if root else default_root(PLATFORM)
    if PLATFORM == "windows":
        BIN = ROOT
        CONF = ROOT / "ossec.conf"
        SHARED = ROOT / "shared" / "agent.conf"
        AGENTD = ROOT / "wazuh-agent.exe"
        CONTROL = None
        LOG = ROOT / "ossec.log"
        STATE_FILE = ROOT / "wazuh-agent.state"
        BACKUP_DIR = ROOT / "backups"
        LOCK = ROOT / "wazuh-console.lock"
        SHARED_DIR = AGENT_CONTROL = AGENT_GROUPS = VERIFY_CONF = None
    else:
        BIN = ROOT / "bin"
        CONF = ROOT / "etc/ossec.conf"
        SHARED = ROOT / "etc/shared/agent.conf"
        SHARED_DIR = ROOT / "etc/shared"
        AGENTD = BIN / "wazuh-agentd"
        CONTROL = BIN / "wazuh-control"
        AGENT_CONTROL = BIN / "agent_control"
        AGENT_GROUPS = BIN / "agent_groups"
        VERIFY_CONF = BIN / "verify-agent-conf"
        LOG = ROOT / "logs/ossec.log"
        STATE_FILE = ROOT / "var/run/wazuh-agentd.state"
        BACKUP_DIR = ROOT / "etc/backups"
        LOCK = ROOT / "var/run/wazuh-console.lock"
    set_role(ROLE)


def profile_key():
    if PLATFORM == "windows":
        return "windows-agent"
    return "linux-manager" if ROLE == "manager" else "linux-agent"


def set_role(role):
    global ROLE, SERVICE_NAME, DAEMONS
    ROLE = role
    if PLATFORM == "windows":
        SERVICE_NAME = WIN_SERVICE
    else:
        SERVICE_NAME = "wazuh-manager" if role == "manager" else "wazuh-agent"
    DAEMONS = MANAGER_DAEMONS if role == "manager" else AGENT_DAEMONS
    ENABLE_OPTIONS.clear()
    ENABLE_OPTIONS.update(PROFILE_OPTIONS[profile_key()])


# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty()
GREEN, RED, YELLOW, CYAN, BLUE, GREY, BOLD = (
    "92", "91", "93", "96", "94", "90", "1")


def c(value, code):
    return f"\033[{code}m{value}\033[0m" if USE_COLOR else str(value)


def ok(msg): print(c("[OK]    ", GREEN) + msg)
def warn(msg): print(c("[CHECK] ", YELLOW) + msg)
def info(msg): print(c("[INFO]  ", BLUE) + msg)
def error(msg): print(c("[ERROR] ", RED) + msg)


STATUS_COLOR = {
    "ACTIVE": GREEN, "CONFIGURED": YELLOW, "DEGRADED": RED, "DOWN": RED,
    "MISSING": RED, "DISABLED": YELLOW, "CHECK": YELLOW,
    "MANAGER CHECK": CYAN, "N/A": GREY,
}

# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------


def run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def command_exists(name):
    return shutil.which(name) is not None


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def tail_lines(path, max_bytes=2_000_000):
    """Read only the end of a (possibly huge) log file."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > max_bytes else lines


def package_installed(pattern):
    if not command_exists("dpkg-query"):
        return None
    r = run(["dpkg-query", "-W", "-f=${Status}", pattern])
    return bool(r and r.returncode == 0 and "install ok installed" in r.stdout)


def is_admin():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def os_pretty_name():
    if PLATFORM == "windows":
        return _platform.platform()
    for line in read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "Unknown"


def win_service_state(name):
    """Numeric state from `sc query` (4 = RUNNING); locale independent."""
    r = run(["sc", "query", name])
    if r is None:
        return None
    m = re.search(r"STATE\s*:\s*(\d+)", r.stdout)
    return int(m.group(1)) if m else None


def unit_exists(name):
    return any(Path(d, name + ".service").exists() for d in (
        "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/system"))


def safe_exists(path):
    """Like Path.exists() but returns True (not PermissionError) when non-root can't stat."""
    try:
        return Path(path).exists()
    except (PermissionError, OSError):
        return True  # Can't stat => assume present, don't report MISSING


def safe_is_file(path):
    """Like Path.is_file() but returns None (not PermissionError) on permission error."""
    try:
        return Path(path).is_file()
    except (PermissionError, OSError):
        return None  # Unknown; callers that treat None as False will work conservatively


def proc_names():
    names = set()
    for p in Path("/proc").glob("[0-9]*/comm"):
        try:
            names.add(p.read_text().strip())
        except OSError:
            pass
    return names


def proc_cmdlines():
    """Return a dict {pid: cmdline_string} for all /proc/<pid>/cmdline entries."""
    result = {}
    for p in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            raw = p.read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            if raw:
                result[p.parent.name] = raw
        except OSError:
            pass
    return result


def _pid_file_alive(name):
    """
    Check whether a Wazuh daemon PID file exists and its PID is still running.
    Handles versioned filenames like wazuh-apid-12345.pid and wazuh-apid.pid.
    Returns True if the daemon is confirmed alive via its PID file.
    """
    if PLATFORM == "windows" or ROOT is None:
        return False
    run_dir = ROOT / "var" / "run"
    if not run_dir.is_dir():
        return False
    # Match both wazuh-apid.pid and wazuh-apid-<number>.pid
    for pattern in [f"{name}.pid", f"{name}-*.pid"]:
        for pid_file in run_dir.glob(pattern):
            try:
                pid = int(pid_file.read_text().strip())
                proc_dir = Path(f"/proc/{pid}")
                if not proc_dir.is_dir():
                    continue
                try:
                    exe_target = os.readlink(proc_dir / "exe")
                    root_str = str(ROOT.resolve())
                    if exe_target.startswith(root_str):
                        return True
                except (PermissionError, OSError, ValueError):
                    # For unprivileged users, readlink on /proc/<pid>/exe may fail with EACCES.
                    # Since pid file in var/run is verified and /proc/<pid> is alive, count as alive.
                    return True
            except (OSError, ValueError):
                continue
    return False


def _is_wazuh_binary_process(name):
    """
    Verify that an active process matching `name` is genuinely running the binary
    located inside ROOT / 'bin' / name (prevents spoofed process names like 'sleep wazuh-remoted').
    On permission error (unprivileged users), returns None to indicate unverified fallback.
    """
    if PLATFORM == "windows" or ROOT is None:
        return False
    expected_bin = str((ROOT / "bin" / name).resolve())
    saw_permission_error = False
    for proc_exe in Path("/proc").glob("[0-9]*/exe"):
        try:
            target = os.readlink(proc_exe)
            if target == expected_bin:
                return True
        except PermissionError:
            saw_permission_error = True
        except (OSError, ValueError):
            pass
    if saw_permission_error:
        return None  # Unprivileged user: cannot inspect /proc/*/exe
    return False


def proc_running(name, names=None):
    if PLATFORM == "windows":
        names = proc_names() if names is None else names
        return any(n == name[:15] for n in names)
    
    # 1. Native ELF binaries: verify executable link directly under ROOT/bin
    try:
        bin_path = BIN / name if BIN else None
        if bin_path and bin_path.is_file():
            is_bin = _is_wazuh_binary_process(name)
            if is_bin is True:
                return True
            elif is_bin is None:
                # Unprivileged user fallback: fall back to comm name match
                names = proc_names() if names is None else names
                if any(n == name[:15] for n in names):
                    return True
    except (PermissionError, OSError):
        # Unprivileged user cannot stat BIN / name: fallback to comm name match
        names = proc_names() if names is None else names
        if any(n == name[:15] for n in names):
            return True

    # 2. Python-wrapped daemons (e.g., wazuh-apid, wazuh-clusterd): verify via PID file
    try:
        if _pid_file_alive(name):
            return True
    except (PermissionError, OSError):
        pass

    # 3. Direct comm match fallback if unprivileged
    names = proc_names() if names is None else names
    if not is_admin() and any(n == name[:15] for n in names):
        return True

    return False


# ----------------------------------------------------------------------------
# Runtime evidence: daemons, connection, log problems
# ----------------------------------------------------------------------------


def service_active(name):
    if PLATFORM == "windows":
        st = win_service_state(name)
        return None if st is None else st == 4
    if not command_exists("systemctl"):
        return None
    r = run(["systemctl", "is-active", name])
    return None if r is None else r.stdout.strip() == "active"


def running_daemons():
    if PLATFORM == "windows":
        up = bool(service_active(SERVICE_NAME))   # one service hosts all components
        return {d: up for d in DAEMONS}
    names = proc_names()
    return {d: proc_running(d, names) for d in DAEMONS}


@functools.lru_cache(maxsize=1)
def windows_channels():
    """Lower-cased event channel names, or None if they cannot be listed."""
    r = run(["wevtutil", "el"], timeout=30)
    if not r or r.returncode != 0:
        return None
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()} or None


@functools.lru_cache(maxsize=1)
def agent_version():
    texts = []
    if PLATFORM == "windows":
        if AGENTD and Path(AGENTD).exists():
            ps = ("(Get-Item -LiteralPath '%s').VersionInfo.FileVersion"
                  % str(AGENTD).replace("'", "''"))
            r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
            if r:
                texts.append(r.stdout)
    else:
        for cmd in ([CONTROL, "info", "-v"], [AGENTD, "-V"],
                    [BIN / "wazuh-analysisd", "-V"]):
            try:
                if cmd[0] and Path(cmd[0]).exists():
                    r = run([str(x) for x in cmd])
                    if r:
                        texts.append(r.stdout + r.stderr)
            except (PermissionError, OSError):
                pass  # Non-root: cannot stat binaries in root:root 750 bin dir
    for t in texts:
        m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", t)
        if m:
            return tuple(int(x) for x in m.groups())
    return None


def agent_state():
    """Parse wazuh-agentd.state / wazuh-agent.state (status, keepalive, ...)."""
    out = {}
    for line in read_text(STATE_FILE).splitlines():
        m = re.match(r"\s*(\w+)\s*=\s*'?([^']*)'?\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


LOG_RE = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(\S+?):\s+"
    r"(INFO|ERROR|CRITICAL|WARNING|DEBUG\d?):\s*(.*)$")
OPEN_ERR = re.compile(r"Could not open file '([^']+)'")


def recent_problems(hours=24):
    """ERROR/WARNING lines since the agent last started (max `hours` back)."""
    parsed = []
    for line in tail_lines(LOG):
        m = LOG_RE.match(line)
        if not m:
            continue
        try:
            ts = datetime.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        parsed.append((ts, m.group(2), m.group(3), m.group(4)))
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
    started = [p[0] for p in parsed
               if p[1] in ("wazuh-agentd", "wazuh-agent", "wazuh-analysisd")
               and p[3].startswith("Started (pid")]
    if started:
        cutoff = max(cutoff, started[-1] - datetime.timedelta(seconds=60))
    return [p for p in parsed
            if p[0] >= cutoff and p[2] in ("ERROR", "CRITICAL", "WARNING")]


EVT_ERR = re.compile(r"EvtSubscribe\(\) for \(([^)]+)\)")


def collect_context():
    problems = recent_problems()
    unreadable = {}
    for _, _, _, msg in problems:
        m = OPEN_ERR.search(msg) or EVT_ERR.search(msg)
        if m:
            unreadable[m.group(1)] = msg
    return {
        "daemons": running_daemons(),
        "version": agent_version(),
        "state": agent_state(),
        "problems": problems,
        "unreadable": unreadable,
    }


def problems_for(ctx, keys):
    keys = set(keys)
    out = []
    for p in ctx["problems"]:
        if p[2] not in ("ERROR", "CRITICAL"):
            continue
        if keys & set(p[1].lower().split(":")):
            out.append(p)
        elif PLATFORM == "windows" and any(k in p[3].lower() for k in keys):
            out.append(p)   # Windows logs most components under one tag
    return out


def refine(ctx, daemon, keys, paths=()):
    """Turn 'configured' into ACTIVE / CONFIGURED / DEGRADED using evidence."""
    if not ctx["daemons"].get(daemon):
        return "CONFIGURED", f"configured, but {daemon} is not running"
    bad = [p for p in paths if p in ctx["unreadable"]]
    if bad:
        return "DEGRADED", "agent cannot open: " + ", ".join(bad)
    probs = problems_for(ctx, keys)
    if probs:
        return "DEGRADED", (f"{len(probs)} error(s) since last start; "
                            f"latest: {probs[-1][3][:80]}")
    return "ACTIVE", None


# ----------------------------------------------------------------------------
# Configuration model (ossec.conf + manager-pushed shared agent.conf)
# ----------------------------------------------------------------------------


def parse_blocks(path, wrapper_tag):
    """ossec.conf can hold several top-level blocks: wrap them to parse."""
    content = Path(path).read_text(encoding="utf-8-sig")
    content = re.sub(r"<\?xml[^>]*\?>", "", content, flags=re.I)
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring("<_wazuh_root>" + content + "</_wazuh_root>", parser)
    blocks = [x for x in root if isinstance(x.tag, str) and x.tag == wrapper_tag]
    return root, blocks


def load_config():
    root, blocks = parse_blocks(CONF, "ossec_config")
    if not blocks:
        raise ValueError("No <ossec_config> blocks found in ossec.conf")
    return root, blocks


def serialize_config(root):
    try:
        ET.indent(root, space="  ")
    except AttributeError:
        pass
    xml = ET.tostring(root, encoding="unicode")
    inner = xml[len("<_wazuh_root>"):-len("</_wazuh_root>")].strip("\n")
    return textwrap.dedent(inner).rstrip() + "\n"


def shared_blocks(local_blocks):
    """Blocks pushed by the manager that apply to this agent."""
    if ROLE == "manager" or not SHARED or not SHARED.is_file():
        return []
    try:
        _, blocks = parse_blocks(SHARED, "agent_config")
    except (ET.ParseError, OSError):
        return []
    host = socket.gethostname()
    platform_text = os_pretty_name() + (" windows" if PLATFORM == "windows" else " linux")
    profiles = set()
    for n in iter_nodes(local_blocks, "client"):
        for cp in n.findall("config-profile"):
            profiles.update(x.strip() for x in (cp.text or "").split(","))

    def rx(pattern, text):
        try:
            return re.search(pattern, text, re.I) is not None
        except re.error:
            return True

    out = []
    for b in blocks:
        if b.get("os") and not rx(b.get("os"), platform_text):
            continue
        if b.get("name") and not rx("^(?:" + b.get("name") + ")$", host):
            continue
        if b.get("profile") and b.get("profile") not in profiles:
            continue
        out.append(b)
    return out


def effective_blocks(local_blocks):
    return list(local_blocks) + shared_blocks(local_blocks)


def iter_nodes(blocks, tag, attr_name=None, attr_value=None):
    for block in blocks:
        for node in block:
            if (isinstance(node.tag, str) and node.tag == tag and
                    (attr_name is None or node.get(attr_name) == attr_value)):
                yield node


def child_text(node, name, raw=False):
    child = node.find(name) if node is not None else None
    if child is None:
        return None
    text = (child.text or "").strip()
    return text if raw else text.lower()


def module_enabled(blocks, tag, attr_name=None, attr_value=None,
                   enable_tag="disabled"):
    """Last block that sets the flag wins. Section present without flag:
    <disabled>-style defaults to on; <enabled>-style stays conservative (off)."""
    nodes = list(iter_nodes(blocks, tag, attr_name, attr_value))
    if not nodes:
        return False
    state = None
    for n in nodes:
        v = child_text(n, enable_tag)
        if v is not None:
            state = (v == "yes") if enable_tag == "enabled" else (v != "yes")
    return state if state is not None else enable_tag == "disabled"


def localfile_entries(blocks):
    """[(log_format, location)] with the location's case preserved."""
    out = []
    for n in iter_nodes(blocks, "localfile"):
        out.append((child_text(n, "log_format") or "",
                    child_text(n, "location", raw=True) or ""))
    return out


def existing(candidate):
    return sorted(glob.glob(candidate)) if any(
        ch in candidate for ch in "*?[") else (
        [candidate] if Path(candidate).is_file() else [])


def covered(candidate, locs):
    """Is every existing file behind `candidate` matched by a localfile?"""
    files = existing(candidate)
    if not files:
        return False
    return all(any(loc == f or loc == candidate or fnmatch.fnmatchcase(f, loc)
                   for loc in locs) for f in files)


def journald_configured(blocks):
    return any(fmt == "journald" for fmt, _ in localfile_entries(blocks))


# ----------------------------------------------------------------------------
# Capability tables
# ----------------------------------------------------------------------------
LOG_SOURCES = {
    8:  ("System Syslog", [("/var/log/syslog", "syslog")]),
    9:  ("PAM / authentication", [("/var/log/auth.log", "syslog"),
                                  ("/var/log/secure", "syslog")]),
    12: ("Linux Audit / auditd", [("/var/log/audit/audit.log", "audit")]),
    14: ("Cron", [("/var/log/cron", "syslog"), ("/var/log/cron.log", "syslog")]),
    15: ("Kernel logs", [("/var/log/kern.log", "syslog")]),
    16: ("Apache / Nginx", [
        ("/var/log/apache2/access.log", "apache"),
        ("/var/log/apache2/error.log", "apache"),
        ("/var/log/nginx/access.log", "apache"),
        ("/var/log/nginx/error.log", "apache")]),
    17: ("MySQL / PostgreSQL", [
        ("/var/log/mysql/error.log", "mysql_log"),
        ("/var/log/postgresql/postgresql-*.log", "postgresql_log")]),
    20: ("Firewall logs (UFW)", [("/var/log/ufw.log", "syslog")]),
}
# Sources the systemd journal also carries: enabling both duplicates events.
JOURNAL_OVERLAP = {8, 9, 14, 15, 20}

WIN_CHANNELS = {
    8:  ("Security event log", "Security"),
    9:  ("System event log", "System"),
    10: ("Application event log", "Application"),
    11: ("Sysmon", "Microsoft-Windows-Sysmon/Operational"),
    12: ("PowerShell logging", "Microsoft-Windows-PowerShell/Operational"),
    13: ("Windows Defender", "Microsoft-Windows-Windows Defender/Operational"),
    14: ("Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational"),
    15: ("Windows Firewall",
         "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"),
    16: ("RDP sessions",
         "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
    17: ("WinRM", "Microsoft-Windows-WinRM/Operational"),
}

PROFILE_OPTIONS = {
    "linux-agent": {
        2: ("FIM", "module", "syscheck"),
        3: ("Rootcheck", "module", "rootcheck"),
        4: ("Syscollector", "module", "syscollector"),
        5: ("SCA", "module", "sca"),
        8: ("System Syslog", "log", 8),
        9: ("Authentication / PAM / SSH / sudo logs", "log", 9),
        12: ("Linux Audit log collection", "log", 12),
        13: ("Journald collection", "journal", None),
        14: ("Cron log collection", "log", 14),
        15: ("Kernel log collection", "log", 15),
        16: ("Apache / Nginx logs", "log", 16),
        17: ("MySQL / PostgreSQL logs", "log", 17),
        20: ("UFW firewall log collection", "log", 20),
    },
    "windows-agent": {
        2: ("FIM", "module", "syscheck"),
        3: ("Rootcheck", "module", "rootcheck"),
        4: ("Syscollector", "module", "syscollector"),
        5: ("SCA", "module", "sca"),
        **{n: (name + " collection", "channel", ch)
           for n, (name, ch) in WIN_CHANNELS.items()},
    },
    "linux-manager": {
        11: ("FIM (manager host)", "module", "syscheck"),
        12: ("Rootcheck (manager host)", "module", "rootcheck"),
        13: ("Syscollector (manager host)", "module", "syscollector"),
        14: ("SCA (manager host)", "module", "sca"),
        15: ("Vulnerability Detection", "vuln", None),
    },
}
ENABLE_OPTIONS = {}      # filled by set_role() for the active profile


def option_currently_active(n, blocks):
    _, kind, target = ENABLE_OPTIONS[n]
    if kind == "module":
        if target == "syscollector":
            return module_enabled(blocks, "wodle", "name", "syscollector")
        if target == "sca":
            return module_enabled(blocks, "sca", enable_tag="enabled")
        return module_enabled(blocks, target)
    if kind == "vuln":
        return module_enabled(blocks, "vulnerability-detection", enable_tag="enabled")
    if kind == "journal":
        return journald_configured(blocks)
    if kind == "channel":
        return any(fmt == "eventchannel" and loc.lower() == target.lower()
                   for fmt, loc in localfile_entries(blocks))
    locs = [loc for _, loc in localfile_entries(blocks)]
    present = [p for p, _ in LOG_SOURCES[target][1] if existing(p)]
    return bool(present) and all(covered(p, locs) for p in present)


def indexer_configured(blocks):
    if not module_enabled(blocks, "indexer", enable_tag="enabled"):
        return False
    return any((h.text or "").strip() for n in iter_nodes(blocks, "indexer")
               for h in n.iter("host"))


def option_blocker(n):
    """None if the option can be enabled, otherwise the reason it cannot."""
    _, kind, target = ENABLE_OPTIONS[n]
    if kind == "log":
        if not any(existing(p) for p, _ in LOG_SOURCES[target][1]):
            return "no matching log file exists on this host"
    if kind == "journal":
        if not command_exists("journalctl"):
            return "journalctl not found"
        v = agent_version()
        if v is not None and v < JOURNALD_MIN_VERSION:
            return ("agent %s is older than %s (journald format)" % (
                ".".join(map(str, v)), ".".join(map(str, JOURNALD_MIN_VERSION))))
    if kind == "channel":
        chans = windows_channels()
        if chans is not None and target.lower() not in chans:
            return f"event channel '{target}' not present on this host"
    if kind == "vuln":
        v = agent_version()
        if v is None:
            return "manager version unknown"
        if v < VULN_NEW_MIN_VERSION:
            return "pre-4.8 uses the legacy vulnerability-detector (configure manually)"
        try:
            _, blocks = load_config()
        except Exception:
            return "cannot read ossec.conf"
        if not indexer_configured(blocks):
            return "<indexer> connector is not configured/enabled in ossec.conf"
    return None


configure_paths()


# ----------------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------------


def agent_core_rows(add, module_row, blocks, ctx):
    """Rows 2-7, identical for Linux and Windows agents."""
    d = ctx["daemons"]
    module_row(2, "File Integrity Monitoring (FIM)",
               module_enabled(blocks, "syscheck"), "wazuh-syscheckd",
               ["wazuh-syscheckd", "syscheck"],
               "syscheck enabled and daemon running.",
               "syscheck section absent or disabled.")
    module_row(3, "Rootcheck", module_enabled(blocks, "rootcheck"),
               "wazuh-syscheckd", ["rootcheck"],
               "rootcheck enabled and daemon running.",
               "rootcheck section absent or disabled.")
    module_row(4, "Syscollector",
               module_enabled(blocks, "wodle", "name", "syscollector"),
               "wazuh-modulesd", ["syscollector"],
               "syscollector wodle enabled and modulesd running.",
               "syscollector wodle absent or disabled.")
    module_row(5, "Security Configuration Assessment (SCA)",
               module_enabled(blocks, "sca", enable_tag="enabled"),
               "wazuh-modulesd", ["sca"],
               "sca enabled and modulesd running.",
               "SCA absent or not enabled.")

    # 6 Command monitoring: real command entries only
    cmds = sum(1 for fmt, _ in localfile_entries(blocks)
               if fmt in ("command", "full_command"))
    cmds += sum(1 for _ in iter_nodes(blocks, "wodle", "name", "command"))
    add(6, "Command monitoring", "ACTIVE" if cmds else "DISABLED",
        f"{cmds} command entr(ies) configured." if cmds
        else "No command / full_command localfile or command wodle found.")

    # 7 Active response (agent side)
    ar_nodes = list(iter_nodes(blocks, "active-response"))
    ar_off = any(child_text(n, "disabled") == "yes" for n in ar_nodes)
    if ar_off:
        add(7, "Active Response", "DISABLED",
            "active-response explicitly disabled on this agent.", "Manager + endpoint")
    elif not d["wazuh-execd"]:
        add(7, "Active Response", "DOWN", "wazuh-execd is not running.",
            "Manager + endpoint")
    else:
        add(7, "Active Response", "ACTIVE",
            "Agent side ready (execd running). Responses are defined on the manager.",
            "Manager + endpoint")



def audit_linux_agent(blocks, ctx):
    rows = []

    def add(n, name, status, detail, cat="Endpoint"):
        rows.append({"number": n, "name": name, "status": status,
                     "detail": detail, "category": cat})

    d = ctx["daemons"]
    locs = [loc for _, loc in localfile_entries(blocks)]

    def module_row(n, name, on, daemon, keys, on_msg, off_msg):
        if not on:
            add(n, name, "DISABLED", off_msg)
            return
        st, extra = refine(ctx, daemon, keys)
        add(n, name, st, extra or on_msg)

    # 1 Logcollector daemon
    try:
        _agentd_found = AGENTD.exists()
    except (PermissionError, OSError):
        _agentd_found = True  # Assume present if we can't stat (non-root)
    if not _agentd_found:
        add(1, "Logcollector", "MISSING", "Agent binaries not found.")
    elif d["wazuh-logcollector"]:
        add(1, "Logcollector", "ACTIVE",
            f"Daemon running; {len(locs)} localfile entr(ies) configured.")
    else:
        add(1, "Logcollector", "DOWN", "wazuh-logcollector is not running.")

    agent_core_rows(add, module_row, blocks, ctx)

    # 8-20 log sources
    journal = journald_configured(blocks)
    results = {}
    for n, name, cands in [(n, v[0], v[1]) for n, v in sorted(LOG_SOURCES.items())]:
        present = [p for p, _ in cands if existing(p)]
        cov = [p for p in present if covered(p, locs)]
        files = [f for p in cov for f in existing(p)]
        via_journal = journal and n in JOURNAL_OVERLAP
        if n == 12:
            pkg = package_installed("auditd")
            if present and len(cov) == len(present):
                st, detail = refine(ctx, "wazuh-logcollector",
                                    ["wazuh-logcollector", "logcollector"], files)
                detail = detail or "Audit log exists and is collected."
            elif present or pkg:
                st, detail = "CHECK", ("auditd present, but its log is not "
                                       "collected (or not created yet).")
            else:
                st, detail = "MISSING", "auditd package/log not detected."
        elif present and len(cov) == len(present):
            st, detail = refine(ctx, "wazuh-logcollector",
                                ["wazuh-logcollector", "logcollector"], files)
            detail = detail or "Collected: " + ", ".join(cov)
        elif cov:
            st, detail = "CHECK", ("Partially collected. Not configured: " +
                                   ", ".join(p for p in present if p not in cov))
        elif via_journal:
            st, detail = refine(ctx, "wazuh-logcollector",
                                ["wazuh-logcollector", "logcollector"])
            detail = detail or "Collected through the journald input."
        elif present:
            st, detail = "CHECK", "Log exists but is not collected: " + ", ".join(present)
        elif n in (14, 15, 20) and "/var/log/syslog" in locs:
            st, detail = "CHECK", ("Dedicated log not found; general syslog is "
                                   "collected, which may or may not carry this.")
        else:
            st, detail = "MISSING", "Expected log not found: " + ", ".join(p for p, _ in cands)
        results[n] = (st, detail)
        add(n, name, st, detail)

    # 9 is reused for 10 (SSH) and 11 (sudo) with their own prerequisites
    def derived(n, name, prereq_ok, prereq_msg):
        rows[:] = [r for r in rows if r["number"] != n]
        if not prereq_ok:
            add(n, name, "N/A", prereq_msg)
        else:
            st, detail = results[9]
            add(n, name, st, detail)

    derived(10, "SSH authentication",
            command_exists("sshd") or Path("/usr/sbin/sshd").exists(),
            "sshd not installed: no SSH events to collect.")
    derived(11, "sudo events", command_exists("sudo"), "sudo not installed.")

    # 13 journald
    if not command_exists("journalctl"):
        add(13, "Journald", "MISSING", "journalctl not found.")
    elif option_blocker(13):
        add(13, "Journald", "N/A", option_blocker(13))
    elif journal:
        st, extra = refine(ctx, "wazuh-logcollector",
                           ["wazuh-logcollector", "logcollector"])
        add(13, "Journald", st, extra or "journald localfile configured.")
    else:
        add(13, "Journald", "CHECK", "Available but not collected.")

    add(18, "Windows Event Logs", "N/A", "Windows-only capability.")
    add(19, "Sysmon", "N/A", "Windows-only capability.")

    # 21-28
    syscol_on = module_enabled(blocks, "wodle", "name", "syscollector")
    add(21, "Vulnerability Detection", "MANAGER CHECK",
        "Runs on the manager. Agent prerequisite (Syscollector inventory): " +
        ("on." if syscol_on else "OFF, enable it (option 4)."), "Manager-side")
    add(22, "Malware / IOC detection", "MANAGER CHECK",
        "Rules on the manager; endpoint inputs are FIM + Rootcheck.", "Manager-side")
    add(23, "YARA integration", "MANAGER CHECK",
        "Needs manager active-response + yara on the endpoint (yara %s)." %
        ("found" if command_exists("yara") else "not installed"), "Manager-side")
    add(24, "VirusTotal integration", "MANAGER CHECK",
        "Manager-side integration; the agent only supplies FIM events.", "Manager-side")

    for n, name, wodle, binary in (
            (25, "Docker Listener", "docker-listener", "docker"),
            (26, "Osquery integration", "osquery", "osqueryd")):
        installed = command_exists(binary)
        on = module_enabled(blocks, "wodle", "name", wodle)
        if on:
            st, extra = refine(ctx, "wazuh-modulesd", [wodle])
            if not installed:
                st, extra = "DEGRADED", f"enabled, but {binary} is not installed"
            add(n, name, st, extra or f"{wodle} wodle enabled.")
        elif not installed:
            add(n, name, "MISSING", f"{binary} not installed; wodle not configured.")
        else:
            add(n, name, "DISABLED",
                f"{binary} installed but the {wodle} wodle is not enabled "
                "(not auto-enabled: needs extra setup).")
    add(27, "Cloud integrations", "MANAGER CHECK",
        "Manager / dedicated-node feature.", "Manager-side")
    add(28, "Agentless monitoring", "MANAGER CHECK",
        "Manager-side feature.", "Manager-side")

    rows.sort(key=lambda r: r["number"])
    return rows


def make_helpers(ctx):
    rows = []

    def add(n, name, status, detail, cat="Endpoint"):
        rows.append({"number": n, "name": name, "status": status,
                     "detail": detail, "category": cat})

    def module_row(n, name, on, daemon, keys, on_msg, off_msg, cat="Endpoint"):
        if not on:
            add(n, name, "DISABLED", off_msg, cat)
            return
        st, extra = refine(ctx, daemon, keys)
        add(n, name, st, extra or on_msg, cat)

    return rows, add, module_row


def wodle_row(add, ctx, blocks, n, name, wodle, binary=None, toplevel=None,
              cat="Endpoint"):
    on = module_enabled(blocks, "wodle", "name", wodle)
    if toplevel and not on:
        on = module_enabled(blocks, toplevel, enable_tag="enabled")
    installed = None if binary is None else command_exists(binary)
    if on:
        st, extra = refine(ctx, "wazuh-modulesd", [wodle, toplevel or wodle])
        if installed is False:
            st, extra = "DEGRADED", f"enabled, but {binary} is not installed"
        add(n, name, st, extra or f"{wodle} enabled.", cat)
    elif installed is False:
        add(n, name, "MISSING", f"{binary} not installed; not configured.", cat)
    else:
        add(n, name, "DISABLED",
            "Not configured/enabled (needs credentials or extra setup; "
            "never auto-enabled).", cat)


def audit_windows_agent(blocks, ctx):
    rows, add, module_row = make_helpers(ctx)
    d = ctx["daemons"]
    if not Path(AGENTD).exists():
        add(1, "Wazuh agent service", "MISSING", "wazuh-agent.exe not found.")
    elif d["wazuh-agentd"]:
        add(1, "Wazuh agent service", "ACTIVE", f"Service {WIN_SERVICE} is running.")
    else:
        add(1, "Wazuh agent service", "DOWN", f"Service {WIN_SERVICE} is not running.")
    agent_core_rows(add, module_row, blocks, ctx)

    chans = windows_channels()
    collected = {loc.lower() for fmt, loc in localfile_entries(blocks)
                 if fmt == "eventchannel"}
    for n, (name, ch) in WIN_CHANNELS.items():
        want = ch.lower() in collected
        exists = None if chans is None else ch.lower() in chans
        if want and exists is False:
            st, detail = "DEGRADED", "collected, but the channel does not exist on this host"
        elif want:
            st, extra = refine(ctx, "wazuh-logcollector",
                               ["wazuh-logcollector", "logcollector", "eventchannel"], [ch])
            detail = extra or f"Collecting '{ch}'."
        elif exists:
            st, detail = "CHECK", "Channel exists but is not collected."
        elif exists is None:
            st, detail = "CHECK", "Cannot list event channels (run as Administrator)."
        else:
            st, detail = "MISSING", ("Sysmon not installed (channel absent)."
                                     if n == 11 else "Channel not present on this host.")
        add(n, name, st, detail)

    regs = sum(1 for sc in iter_nodes(blocks, "syscheck") for _ in sc.findall("windows_registry"))
    fim_on = module_enabled(blocks, "syscheck")
    add(18, "FIM registry monitoring",
        "ACTIVE" if (fim_on and regs) else "CHECK" if fim_on else "DISABLED",
        f"{regs} registry key(s) monitored." if regs else
        "FIM has no <windows_registry> entries." if fim_on else "FIM is disabled.")
    wodle_row(add, ctx, blocks, 19, "Osquery integration", "osquery", "osqueryd")
    pk = module_enabled(blocks, "wodle", "name", "syscollector")
    add(20, "Vulnerability Detection", "MANAGER CHECK",
        "Runs on the manager. Agent prerequisite (Syscollector packages/hotfixes): " +
        ("on." if pk else "OFF, enable it (option 4)."), "Manager-side")
    add(21, "Malware / IOC detection", "MANAGER CHECK",
        "Rules on the manager; endpoint inputs are FIM, Rootcheck, Sysmon.", "Manager-side")
    add(22, "VirusTotal / cloud / agentless", "MANAGER CHECK",
        "Manager-side integrations; the agent only supplies the events.", "Manager-side")
    rows.sort(key=lambda r: r["number"])
    return rows


def global_value(blocks, tag):
    val = None
    for n in iter_nodes(blocks, "global"):
        v = child_text(n, tag)
        if v is not None:
            val = v
    return val


def svc_row(add, n, name, unit, note):
    if not unit_exists(unit):
        add(n, name, "N/A", f"{unit} is not installed on this host ({note}).", "Manager")
        return
    act = service_active(unit)
    add(n, name, "ACTIVE" if act else "DOWN",
        f"{unit} service {'active' if act else 'not active'}.", "Manager")


def audit_manager(blocks, ctx):
    rows, add, module_row = make_helpers(ctx)
    d, v = ctx["daemons"], ctx["version"]

    def core(n, name, daemon, keys, ok_msg):
        if not d.get(daemon):
            add(n, name, "DOWN", f"{daemon} is not running.", "Manager")
            return
        st, extra = refine(ctx, daemon, keys)
        add(n, name, st, extra or ok_msg, "Manager")

    core(1, "Analysis engine (analysisd)", "wazuh-analysisd", ["wazuh-analysisd"],
         "Decoder/rules engine running.")

    remotes = [(child_text(n, "connection"), child_text(n, "port"),
                child_text(n, "protocol")) for n in iter_nodes(blocks, "remote")]
    if not remotes:
        add(2, "Agent communication (remoted)", "MISSING",
            "No <remote> block: agents cannot connect.", "Manager")
    else:
        desc = ", ".join(f"{c_ or 'secure'}:{p_ or '1514'}/{pr or 'tcp'}"
                         for c_, p_, pr in remotes)
        core(2, "Agent communication (remoted)", "wazuh-remoted", ["wazuh-remoted"],
             "Listening: " + desc)

    auth = list(iter_nodes(blocks, "auth"))
    if any(child_text(n, "disabled") == "yes" for n in auth):
        add(3, "Agent enrollment (authd)", "DISABLED",
            "Disabled: agents must be added with manage_agents.", "Manager")
    elif not d.get("wazuh-authd"):
        add(3, "Agent enrollment (authd)", "DOWN", "wazuh-authd is not running.", "Manager")
    elif not any(child_text(n, "use_password") == "yes" for n in auth):
        add(3, "Agent enrollment (authd)", "CHECK",
            "OPEN enrollment: any host that reaches the port can register. "
            "Set <use_password>yes</use_password> or restrict the network.", "Manager")
    else:
        add(3, "Agent enrollment (authd)", "ACTIVE", "Password-protected enrollment.", "Manager")

    core(4, "Wazuh API (apid)", "wazuh-apid", ["wazuh-apid"], "API daemon running.")
    core(5, "Wazuh DB (wazuh-db)", "wazuh-db", ["wazuh-db"], "Agent database daemon running.")

    cl = list(iter_nodes(blocks, "cluster"))
    if not any(child_text(n, "disabled") == "no" for n in cl):
        add(6, "Cluster", "N/A", "Single-node (cluster disabled).", "Manager")
    else:
        up = proc_running("wazuh-clusterd")
        add(6, "Cluster", "ACTIVE" if up else "CONFIGURED",
            f"{child_text(cl[-1], 'node_type') or '?'} node; clusterd "
            f"{'running' if up else 'process not detected'}.", "Manager")

    ix_ok = indexer_configured(blocks)
    if ix_ok:
        missing = []
        for n in iter_nodes(blocks, "indexer"):
            for tag in ("certificate", "key"):
                for e in n.iter(tag):
                    path = (e.text or "").strip()
                    if path and not Path(path).exists():
                        missing.append(path)
        add(7, "Indexer connector", "CHECK" if missing else "ACTIVE",
            ("TLS file(s) missing: " + ", ".join(missing)) if missing
            else "Enabled with host(s) configured.", "Manager")
    elif v is not None and v < VULN_NEW_MIN_VERSION:
        add(7, "Indexer connector", "N/A", "Not used before 4.8.", "Manager")
    else:
        add(7, "Indexer connector", "MISSING",
            "<indexer> not enabled/configured (needed by Vulnerability Detection).", "Manager")
    svc_row(add, 8, "Wazuh indexer service", "wazuh-indexer", "distributed deployment?")
    svc_row(add, 9, "Filebeat service", "filebeat", "alerts shipping")
    svc_row(add, 10, "Wazuh dashboard service", "wazuh-dashboard", "distributed deployment?")

    module_row(11, "File Integrity Monitoring (FIM)", module_enabled(blocks, "syscheck"),
               "wazuh-syscheckd", ["wazuh-syscheckd", "syscheck"],
               "syscheck enabled and daemon running.", "syscheck absent or disabled.", "Manager")
    module_row(12, "Rootcheck", module_enabled(blocks, "rootcheck"),
               "wazuh-syscheckd", ["rootcheck"],
               "rootcheck enabled and daemon running.", "rootcheck absent or disabled.", "Manager")
    module_row(13, "Syscollector", module_enabled(blocks, "wodle", "name", "syscollector"),
               "wazuh-modulesd", ["syscollector"],
               "syscollector enabled and modulesd running.", "syscollector absent or disabled.",
               "Manager")
    module_row(14, "Security Configuration Assessment (SCA)",
               module_enabled(blocks, "sca", enable_tag="enabled"),
               "wazuh-modulesd", ["sca"], "sca enabled and modulesd running.",
               "SCA absent or not enabled.", "Manager")

    new_node = last_match(blocks, "vulnerability-detection")
    legacy = module_enabled(blocks, "wodle", "name", "vulnerability-detector", enable_tag="enabled")
    vkeys = ["vulnerability-scanner", "vulnerability-detector", "indexer-connector"]
    if new_node is not None or (v is not None and v >= VULN_NEW_MIN_VERSION):
        if module_enabled(blocks, "vulnerability-detection", enable_tag="enabled"):
            st, extra = refine(ctx, "wazuh-modulesd", vkeys)
            if st == "ACTIVE" and not ix_ok:
                st, extra = "DEGRADED", "enabled, but the <indexer> connector is not configured"
            add(15, "Vulnerability Detection", st, extra or "Enabled; indexer configured.", "Manager")
        else:
            add(15, "Vulnerability Detection", "DISABLED",
                "Disabled" + (" (can be enabled with option 15)." if ix_ok else
                              "; configure <indexer> first."), "Manager")
    elif legacy:
        st, extra = refine(ctx, "wazuh-modulesd", vkeys)
        add(15, "Vulnerability Detection", st, extra or "Legacy vulnerability-detector enabled.", "Manager")
    else:
        add(15, "Vulnerability Detection", "DISABLED",
            "Legacy (pre-4.8) detector not enabled; configure manually.", "Manager")

    ar = [n for n in iter_nodes(blocks, "active-response") if child_text(n, "disabled") != "yes"]
    cmds = sum(1 for _ in iter_nodes(blocks, "command"))
    if not d.get("wazuh-execd"):
        add(16, "Active Response", "DOWN", "wazuh-execd is not running.", "Manager")
    elif ar:
        add(16, "Active Response", "ACTIVE",
            f"{len(ar)} active-response rule(s), {cmds} command(s) defined.", "Manager")
    elif cmds:
        add(16, "Active Response", "CHECK",
            f"{cmds} command(s) defined but no <active-response> block uses them.", "Manager")
    else:
        add(16, "Active Response", "MISSING", "No commands or active-response blocks.", "Manager")

    ints = [(child_text(n, "name", raw=True) or "", bool(child_text(n, "api_key")))
            for n in iter_nodes(blocks, "integration")]
    integratord = proc_running("wazuh-integratord")
    vt = [i for i in ints if i[0].lower() == "virustotal"]
    if not vt:
        add(17, "VirusTotal integration", "DISABLED",
            "Not configured (needs an API key; never auto-enabled).", "Manager")
    elif not vt[-1][1]:
        add(17, "VirusTotal integration", "DEGRADED", "Block present but api_key is empty.", "Manager")
    elif not integratord:
        add(17, "VirusTotal integration", "CONFIGURED", "Configured, but wazuh-integratord is not running.", "Manager")
    else:
        add(17, "VirusTotal integration", "ACTIVE", "Configured (API key present).", "Manager")
    others = sorted({i[0] for i in ints if i[0].lower() != "virustotal"})
    if not others:
        add(18, "Other integrations (Slack, PagerDuty, ...)", "DISABLED", "None configured.", "Manager")
    else:
        add(18, "Other integrations (Slack, PagerDuty, ...)",
            "ACTIVE" if integratord else "CONFIGURED", ", ".join(others), "Manager")

    wodle_row(add, ctx, blocks, 19, "OpenSCAP", "open-scap", "oscap", cat="Manager")
    wodle_row(add, ctx, blocks, 20, "CIS-CAT", "cis-cat", cat="Manager")
    wodle_row(add, ctx, blocks, 21, "Osquery", "osquery", "osqueryd", cat="Manager")
    wodle_row(add, ctx, blocks, 22, "Docker listener", "docker-listener", "docker", cat="Manager")
    wodle_row(add, ctx, blocks, 23, "Cloud: AWS S3", "aws-s3", cat="Manager")
    wodle_row(add, ctx, blocks, 24, "Cloud: Azure logs", "azure-logs", cat="Manager")
    wodle_row(add, ctx, blocks, 25, "Cloud: GCP Pub/Sub", "gcp-pubsub", toplevel="gcp-pubsub", cat="Manager")
    wodle_row(add, ctx, blocks, 26, "Office 365 / GitHub", "office365", toplevel="office365", cat="Manager")
    ag = sum(1 for _ in iter_nodes(blocks, "agentless"))
    add(27, "Agentless monitoring", "ACTIVE" if ag else "DISABLED",
        f"{ag} agentless block(s)." if ag else "No <agentless> blocks.", "Manager")

    if global_value(blocks, "email_notification") == "yes":
        miss = [t for t in ("smtp_server", "email_from", "email_to") if not global_value(blocks, t)]
        if miss:
            add(28, "Email alerts", "DEGRADED", "Enabled but missing: " + ", ".join(miss), "Manager")
        else:
            add(28, "Email alerts", "ACTIVE" if proc_running("wazuh-maild") else "CONFIGURED",
                "email_notification on; SMTP/from/to set.", "Manager")
    else:
        add(28, "Email alerts", "DISABLED", "email_notification is off.", "Manager")
    arch = [t for t in ("logall", "logall_json") if global_value(blocks, t) == "yes"]
    add(29, "Archive logging (logall)", "ACTIVE" if arch else "DISABLED",
        ("Storing ALL events (" + ", ".join(arch) + "): heavy disk use.") if arch
        else "Off (only alerts are stored).", "Manager")
    nloc = len(localfile_entries(blocks))
    add(30, "Local log collection", "ACTIVE" if (nloc and d.get("wazuh-logcollector")) else
        "DISABLED" if not nloc else "CONFIGURED", f"{nloc} localfile entr(ies) on the manager host.", "Manager")

    agents = agent_list()
    if agents is None:
        add(31, "Enrolled agents", "CHECK", "agent_control not available.", "Fleet")
    else:
        cnt = {"active": 0, "disconnected": 0, "never": 0, "pending": 0}
        for a in agents:
            k = a["status"].lower()
            key = ("active" if k.startswith("active") else "disconnected" if k.startswith("disc")
                   else "never" if k.startswith("never") else "pending")
            cnt[key] += 1
        text = (f"{cnt['active']} active, {cnt['disconnected']} disconnected, "
                f"{cnt['never']} never connected, {cnt['pending']} pending")
        if not agents:
            add(31, "Enrolled agents", "CHECK", "No agents enrolled yet.", "Fleet")
        elif not cnt["active"]:
            add(31, "Enrolled agents", "DEGRADED", text, "Fleet")
        elif cnt["disconnected"] or cnt["never"]:
            add(31, "Enrolled agents", "CHECK", text, "Fleet")
        else:
            add(31, "Enrolled agents", "ACTIVE", text, "Fleet")

    groups = list_groups()
    ok_, msg = verify_agent_conf()
    if not groups:
        add(32, "Agent groups / centralized config", "CHECK", "No group directories found.", "Fleet")
    elif ok_ is False:
        add(32, "Agent groups / centralized config", "DEGRADED", msg.replace("\n", " ")[:100], "Fleet")
    else:
        add(32, "Agent groups / centralized config", "ACTIVE" if ok_ else "CHECK",
            f"{len(groups)} group(s): {', '.join(groups[:6])}" +
            (" (verify-agent-conf ok)" if ok_ else " (verify inconclusive)"), "Fleet")
    rows.sort(key=lambda r: r["number"])
    return rows


def run_audit(blocks, ctx):
    if ROLE == "manager":
        return audit_manager(blocks, ctx)
    if PLATFORM == "windows":
        return audit_windows_agent(blocks, ctx)
    return audit_linux_agent(blocks, ctx)


def print_audit(rows):
    width = max(100, min(shutil.get_terminal_size((120, 20)).columns, 150))
    dwidth = width - 4 - 1 - 36 - 1 - 14 - 1
    print(c(f"WAZUH {ROLE.upper()} CAPABILITY AUDIT  ({PLATFORM})", BOLD + CYAN))
    print("=" * width)
    print(f"{'#':<4} {'CAPABILITY':<36} {'STATUS':<14} DETAILS")
    print("-" * width)
    for r in rows:
        detail = r["detail"]
        if len(detail) > dwidth:
            detail = detail[:dwidth - 1] + "…"
        st = r["status"]
        print(f"{r['number']:<4} {r['name'][:35]:<36} "
              f"{c(f'{st:<14}', STATUS_COLOR.get(st, GREY))} {detail}")
    print("=" * width)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("Summary: " + " | ".join(f"{k}: {v}" for k, v in counts.items()))
    print(c("ACTIVE", GREEN) + " = configured + daemon running + no errors since start.  " +
          c("CONFIGURED", YELLOW) + " = configured but daemon down.  " +
          c("DEGRADED", RED) + " = errors in ossec.log.")


def _overview_agent(blocks, ctx):
    st = ctx["state"]
    print(c("SYSTEM OVERVIEW", BOLD + CYAN))
    print("-" * 70)
    print("Hostname:        ", socket.gethostname())
    print("Role / platform: ", f"Wazuh {ROLE} / {PLATFORM}")
    print("Operating system:", os_pretty_name())
    v = ctx["version"]
    print("Agent version:   ", ".".join(map(str, v)) if v else "Unknown")
    svc = service_active(SERVICE_NAME)
    print("Agent service:   ", {True: "Active", False: "Inactive", None: "Unknown"}[svc])
    if PLATFORM == "windows":
        print("Daemons:         ", "service running (hosts all components)"
              if any(ctx["daemons"].values()) else "service NOT running")
    else:
        print("Daemons:         ", ", ".join(
            f"{k.replace('wazuh-', '')}={'up' if up else 'DOWN'}"
            for k, up in ctx["daemons"].items()))
    
    # Manager link and reachability details
    curr_mgr, port, proto, is_place, reachable = get_current_configured_manager()
    if curr_mgr and not is_place:
        reach_txt = c(f"{proto.upper()}:{port} reachable", GREEN) if reachable else c(f"{proto.upper()}:{port} unreachable", RED)
        print("Configured manager:", f"{curr_mgr} ({reach_txt})")
    elif curr_mgr:
        print("Configured manager:", f"{curr_mgr} " + c("(placeholder - run --set-manager-ip to auto-configure)", YELLOW))
    else:
        print("Configured manager:", c("not set", RED))

    if st:
        print("Manager link:    ", st.get("status", "unknown"),
              f"(last keepalive {st.get('last_keepalive', '?')}, "
              f"last ack {st.get('last_ack', '?')})")
        print("Events:          ",
              f"generated={st.get('msg_count', '?')} sent={st.get('msg_sent', '?')} "
              f"buffered={st.get('msg_buffer', '?')}")
    else:
        print("Manager link:    ", "no state file (agent never started or no access)")
    extra = len(shared_blocks(blocks))
    print("Config sources:  ", f"ossec.conf ({len(blocks)} block(s)) + "
          f"{extra} manager-pushed shared block(s) applying to this agent")
    print("-" * 70)


def _overview_manager(blocks, ctx):
    print(c("SYSTEM OVERVIEW", BOLD + CYAN))
    print("-" * 70)
    print("Hostname:        ", socket.gethostname())
    print("Role / platform: ", f"Wazuh {ROLE} / {PLATFORM}")
    print("Operating system:", os_pretty_name())
    v = ctx["version"]
    print("Manager version: ", ".".join(map(str, v)) if v else "Unknown")
    svc = service_active(SERVICE_NAME)
    print("Manager service: ", {True: "Active", False: "Inactive", None: "Unknown"}[svc])
    print("Daemons:         ", ", ".join(
        f"{k.replace('wazuh-', '')}={'up' if up else 'DOWN'}"
        for k, up in ctx["daemons"].items()))
    ag = agent_list()
    if ag is not None:
        act = sum(1 for a in ag if a["status"].lower().startswith("active"))
        print("Agents:          ", f"{len(ag)} enrolled, {act} active")
    print("Config:          ", f"ossec.conf ({len(blocks)} block(s))")
    print("-" * 70)


def system_overview(blocks, ctx):
    (_overview_manager if ROLE == "manager" else _overview_agent)(blocks, ctx)


def audit_json(blocks, ctx, rows):
    return json.dumps({
        "host": socket.gethostname(),
        "role": ROLE,
        "platform": PLATFORM,
        "os": os_pretty_name(),
        "agent_version": ".".join(map(str, ctx["version"])) if ctx["version"] else None,
        "daemons": ctx["daemons"],
        "connection": ctx["state"],
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "capabilities": rows,
    }, indent=2)


# ----------------------------------------------------------------------------
# Safe change engine
# ----------------------------------------------------------------------------


class Lock:
    def __enter__(self):
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(LOCK, "a+")
        try:
            if fcntl:
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
        except (BlockingIOError, OSError):
            raise RuntimeError("Another instance is already applying changes.")
        return self

    def __exit__(self, *a):
        self.f.close()


def atomic_write(path, text, like=None):
    """Write via temp file + rename, keeping the original mode and owner."""
    path = Path(path)
    ref = os.stat(like or path)
    tmp = path.with_name(path.name + ".wazuh-console.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, stat.S_IMODE(ref.st_mode))
    try:
        os.chown(tmp, ref.st_uid, ref.st_gid)
    except (PermissionError, AttributeError):
        pass
    os.replace(tmp, path)


def backup_config():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    target = BACKUP_DIR / f"ossec.conf.backup_{stamp}"
    shutil.copy2(CONF, target)
    st = os.stat(CONF)
    try:
        os.chown(target, st.st_uid, st.st_gid)
    except (PermissionError, AttributeError):
        pass
    for old in list_backups()[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)
    return target


def list_backups():
    return sorted(BACKUP_DIR.glob("ossec.conf.backup_*")) if BACKUP_DIR.is_dir() else []


def validate_config():
    """XML check everywhere; daemon -t checks on Linux."""
    msgs = []
    try:
        _, blocks = parse_blocks(CONF, "ossec_config")
        if not blocks:
            return False, "No <ossec_config> block found."
        msgs.append("XML well-formed: ok")
    except (ET.ParseError, OSError) as exc:
        return False, f"ossec.conf is not valid XML: {exc}"
    if PLATFORM == "windows":
        msgs.append("Windows: only XML structure is verified here (no daemon config-test "
                    "is used). The service start is checked after a restart.")
        return True, "\n".join(msgs)
    if ROLE == "manager":
        names = ("wazuh-analysisd", "wazuh-modulesd", "wazuh-syscheckd", "wazuh-logcollector")
    else:
        names = ("wazuh-agentd", "wazuh-logcollector", "wazuh-syscheckd", "wazuh-modulesd")
    if not any(safe_exists(BIN / n) for n in names):
        return False, "Wazuh binaries not found."
    all_ok = True
    for name in names:
        binary = BIN / name
        if not safe_exists(binary):
            continue
        r = run([str(binary), "-t"], timeout=60)
        if r is None:
            all_ok = False
            msgs.append(f"{name} -t: could not run")
            continue
        out = (r.stdout + "\n" + r.stderr).strip()
        if r.returncode != 0:
            all_ok = False
            msgs.append(f"{name} -t FAILED: {out}")
        else:
            msgs.append(f"{name} -t: ok")
    return all_ok, "\n".join(msgs)


def restart_agent():
    """Restart the Wazuh service for the active profile."""
    if PLATFORM == "windows":
        run(["net", "stop", SERVICE_NAME], timeout=120)   # may fail if already stopped
        r = run(["net", "start", SERVICE_NAME], timeout=120)
        if r and r.returncode == 0 and service_active(SERVICE_NAME):
            return True, f"{SERVICE_NAME} service is running."
        return False, f"Could not restart {SERVICE_NAME} (run as Administrator)."
    timeout = 180 if ROLE == "manager" else 60
    if command_exists("systemctl"):
        r = run(["systemctl", "restart", SERVICE_NAME], timeout=timeout)
        if r and r.returncode == 0:
            chk = run(["systemctl", "is-active", SERVICE_NAME])
            if chk and chk.stdout.strip() == "active":
                return True, f"{SERVICE_NAME} service is active."
            return False, "Restart ran, but service is not confirmed active."
    if CONTROL and safe_exists(CONTROL):
        r = run([str(CONTROL), "restart"], timeout=timeout)
        if r and r.returncode == 0:
            return True, "wazuh-control restart completed."
    return False, f"Could not restart/confirm the {SERVICE_NAME} service."


def wait_ready(timeout=45):
    """Manager: analysisd + remoted up. Agent: connected (or service up)."""
    deadline = time.time() + (90 if ROLE == "manager" else timeout)
    while time.time() < deadline:
        if ROLE == "manager":
            d = running_daemons()
            if d.get("wazuh-analysisd") and d.get("wazuh-remoted"):
                return True
        else:
            st = agent_state().get("status")
            if st:
                if st == "connected":
                    return True
            elif service_active(SERVICE_NAME):
                return True
        time.sleep(2)
    return False


def last_match(blocks, tag, attr_name=None, attr_value=None):
    nodes = list(iter_nodes(blocks, tag, attr_name, attr_value))
    return nodes[-1] if nodes else None


def set_child(node, tag, value):
    child = node.find(tag)
    if child is None:
        child = ET.SubElement(node, tag)
    child.text = value


def ensure_module(blocks, kind):
    win = PLATFORM == "windows"
    if kind == "vuln":
        node = last_match(blocks, "vulnerability-detection")
        if node is None:
            node = ET.SubElement(blocks[0], "vulnerability-detection")
        set_child(node, "enabled", "yes")
        if node.find("index-status") is None:
            set_child(node, "index-status", "yes")
        if node.find("feed-update-interval") is None:
            set_child(node, "feed-update-interval", "60m")
        return
    if kind == "syscollector":
        node = last_match(blocks, "wodle", "name", "syscollector")
        if node is None:
            node = ET.SubElement(blocks[0], "wodle", {"name": "syscollector"})
        set_child(node, "disabled", "no")
        if node.find("scan_on_start") is None:
            set_child(node, "scan_on_start", "yes")
        return
    node = last_match(blocks, kind)
    created = node is None
    if created:
        node = ET.SubElement(blocks[0], kind)
    if kind == "sca":
        set_child(node, "enabled", "yes")
        if node.find("scan_on_start") is None:
            set_child(node, "scan_on_start", "yes")
        return
    set_child(node, "disabled", "no")
    if kind == "syscheck":
        if node.find("scan_on_start") is None:
            set_child(node, "scan_on_start", "yes")
        if not any(sc.find("directories") is not None for sc in iter_nodes(blocks, "syscheck")):
            if win:
                d = ET.SubElement(node, "directories", {"check_all": "yes"})
                d.text = "%WINDIR%/System32"
            else:
                d = ET.SubElement(node, "directories", {"check_all": "yes"})
                d.text = "/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot"
        if win and not any(sc.find("windows_registry") is not None
                           for sc in iter_nodes(blocks, "syscheck")):
            ET.SubElement(node, "windows_registry").text = (
                r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run")
    if kind == "rootcheck" and win and created:
        for tag, fname in (("windows_apps", "win_applications_rcl.txt"),
                           ("windows_malware", "win_malware_rcl.txt")):
            if (ROOT / "shared" / fname).exists():
                ET.SubElement(node, tag).text = "./shared/" + fname


def add_localfile(blocks, location, fmt):
    node = ET.SubElement(blocks[0], "localfile")
    ET.SubElement(node, "log_format").text = fmt
    ET.SubElement(node, "location").text = location


def build_changes(numbers, blocks):
    """blocks = EFFECTIVE config. Returns (changes, skipped)."""
    changes, skipped = [], []
    locs = [loc for _, loc in localfile_entries(blocks)]
    journald_on = 13 in ENABLE_OPTIONS and ENABLE_OPTIONS[13][1] == "journal" \
        and option_currently_active(13, blocks)
    nums = sorted(set(numbers), key=lambda x: (ENABLE_OPTIONS.get(x, ("", ""))[1] == "journal", x))
    planned_overlap = False
    for n in nums:
        if n not in ENABLE_OPTIONS:
            skipped.append((n, "Not auto-enabled here (needs credentials/extra setup, "
                               "or belongs to the manager / another platform)."))
            continue
        label, kind, target = ENABLE_OPTIONS[n]
        if option_currently_active(n, blocks):
            skipped.append((n, "Already configured; no change needed."))
            continue
        blocker = option_blocker(n)
        if blocker:
            skipped.append((n, "Cannot enable: " + blocker + "."))
            continue
        if kind == "journal":
            overlap = planned_overlap or any(
                option_currently_active(x, blocks) for x in JOURNAL_OVERLAP
                if x in ENABLE_OPTIONS and ENABLE_OPTIONS[x][1] == "log")
            if overlap:
                skipped.append((n, "Would duplicate events: file-based syslog/auth/kern "
                                   "collection is already on. Choose one approach."))
                continue
            changes.append({"n": n, "label": label, "kind": kind})
        elif kind == "log":
            if n in JOURNAL_OVERLAP and journald_on:
                skipped.append((n, "journald already collects this; adding the file "
                                   "would duplicate events."))
                continue
            items = [(p, fmt) for p, fmt in LOG_SOURCES[target][1]
                     if existing(p) and not covered(p, locs)]
            if n in JOURNAL_OVERLAP:
                planned_overlap = True
            changes.append({"n": n, "label": label, "kind": kind, "items": items})
        else:   # module / vuln / channel
            changes.append({"n": n, "label": label, "kind": kind, "target": target})
    return changes, skipped


def apply_change(blocks, ch):
    if ch["kind"] in ("module", "vuln"):
        ensure_module(blocks, ch["target"] if ch["kind"] == "module" else "vuln")
    elif ch["kind"] == "log":
        for path, fmt in ch["items"]:
            add_localfile(blocks, path, fmt)
    elif ch["kind"] == "channel":
        add_localfile(blocks, ch["target"], "eventchannel")
    elif ch["kind"] == "journal":
        add_localfile(blocks, "journald", "journald")


def apply_selection(numbers, dry_run=False, assume_yes=False, restart=True):
    """Returns a process exit code."""
    if not dry_run and not is_admin():
        error("Applying changes needs root (sudo) / Administrator.")
        return 1
    try:
        with Lock() if not dry_run else _NullCtx():
            return _apply(numbers, dry_run, assume_yes, restart)
    except KeyboardInterrupt:
        warn("Interrupted. Check backups and service status before retrying.")
        return 130
    except Exception as exc:
        error(str(exc))
        return 1


class _NullCtx:
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _apply(numbers, dry_run, assume_yes, restart):
    root, blocks = load_config()
    changes, skipped = build_changes(numbers, effective_blocks(blocks))

    if not changes:
        info("No eligible configuration changes are required.")
        for n, reason in skipped:
            print(f"  {n}. {reason}")
        return 0

    print("\nPlanned changes:")
    for ch in changes:
        extra = ""
        if ch["kind"] == "log":
            extra = " -> " + ", ".join(p for p, _ in ch["items"]) if ch["items"] else " (nothing new)"
        print(f"  {ch['n']:>2}. {ch['label']}{extra}")
    if skipped:
        print("\nNot changing:")
        for n, reason in skipped:
            print(f"  {n:>2}. {reason}")

    before = serialize_config(root)
    for ch in changes:
        apply_change(blocks, ch)
    after = serialize_config(root)
    diff = list(difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        "ossec.conf (current)", "ossec.conf (proposed)", lineterm=""))
    print("\nDiff preview:")
    for line in diff:
        col = GREEN if line.startswith("+") and not line.startswith("+++") else \
            RED if line.startswith("-") and not line.startswith("---") else GREY
        print(c(line, col))

    if dry_run:
        info("Dry run: nothing was written.")
        return 0
    if ROLE == "manager" and restart:
        warn("Restarting the manager briefly pauses analysis for ALL agents "
             "(they buffer events meanwhile).")
    if not assume_yes:
        if input("\nProceed with these changes? [y/N]: ").strip().lower() != "y":
            info("Cancelled. No changes were made.")
            return 0

    backup = backup_config()
    info(f"Backup created: {backup}")
    try:
        atomic_write(CONF, after)
        valid, message = validate_config()
        if not valid:
            raise RuntimeError("Configuration validation failed:\n" + message)
        ok("Configuration validation passed.")
        if restart:
            good, msg = restart_agent()
            if not good:
                raise RuntimeError("Agent restart failed: " + msg)
            ok(msg)
            if wait_ready():
                ok("Manager services are up again." if ROLE == "manager"
                   else "Agent is up and connected to the manager.")
            else:
                warn("Not confirmed ready yet; check again shortly.")
        else:
            info("Restart skipped (--no-restart). Changes take effect on next restart.")
    except Exception:
        atomic_write(CONF, backup.read_text(encoding="utf-8"), like=CONF)
        warn("Restored the original ossec.conf from backup.")
        if restart:
            restart_agent()
        raise

    print("\nPost-change check:")
    _, new_blocks = load_config()
    eff = effective_blocks(new_blocks)
    for ch in changes:
        good = option_currently_active(ch["n"], eff)
        print((c("[CONFIGURED] ", GREEN) if good else c("[RECHECK] ", YELLOW)) +
              ch["label"] + ("" if good else " (not confirmed)"))
    print("\nConfigured does not guarantee ingestion. Run the audit again in a few "
          "minutes (it reads ossec.log) and check the dashboard.")
    return 0


def do_rollback(target="latest", assume_yes=False):
    if not is_admin():
        error("Rollback needs root (sudo) / Administrator.")
        return 1
    backups = list_backups()
    if not backups:
        error("No backups found in " + str(BACKUP_DIR))
        return 1
    chosen = backups[-1] if target == "latest" else Path(target)
    if not chosen.is_file():
        error(f"Backup not found: {chosen}")
        return 1
    print(f"Restoring: {chosen}")
    if not assume_yes and input("Proceed? [y/N]: ").strip().lower() != "y":
        info("Cancelled.")
        return 0
    with Lock():
        safety = backup_config()
        info(f"Current config saved as {safety}")
        atomic_write(CONF, chosen.read_text(encoding="utf-8"), like=CONF)
        valid, message = validate_config()
        if not valid:
            atomic_write(CONF, safety.read_text(encoding="utf-8"), like=CONF)
            error("Backup failed validation; kept the current config.\n" + message)
            return 1
        good, msg = restart_agent()
        (ok if good else error)(msg)
        return 0 if good else 1


# ----------------------------------------------------------------------------
# Interactive UI
# ----------------------------------------------------------------------------


def clear():
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def pause():
    try:
        input("\nPress ENTER to return to the menu...")
    except (KeyboardInterrupt, EOFError):
        print("\nReturning...")


def parse_numbers(value, allowed):
    value = value.strip().lower()
    if value in ("b", "back", "q", "quit", "exit"):
        return None
    if value == "all":
        return sorted(allowed)
    try:
        values = [int(x.strip()) for x in value.split(",") if x.strip()]
        if len(values) != len(set(values)):
            raise ValueError("Duplicate numbers are not allowed.")
        invalid = [x for x in values if x not in allowed]
        if invalid:
            raise ValueError("Invalid option(s): " + ", ".join(map(str, invalid)))
        return values
    except ValueError as exc:
        error(str(exc))
        return []


def audit_screen():
    clear()
    try:
        _, blocks = load_config()
        eff = effective_blocks(blocks)
        ctx = collect_context()
        system_overview(blocks, ctx)
        print_audit(run_audit(eff, ctx))
    except Exception as exc:
        error(f"Could not audit ossec.conf: {exc}")
    pause()


def activation_screen():
    while True:
        clear()
        try:
            _, blocks = load_config()
            eff = effective_blocks(blocks)
            print(c("SELECTIVE FEATURE ACTIVATION", BOLD + CYAN))
            print("-" * 78)
            for n, (label, *_rest) in ENABLE_OPTIONS.items():
                if option_currently_active(n, eff):
                    state = c("ALREADY CONFIGURED", GREEN)
                elif option_blocker(n):
                    state = c("BLOCKED: " + option_blocker(n)[:34], RED)
                else:
                    state = c("AVAILABLE TO ENABLE", YELLOW)
                print(f"{n:>2}. {label:<42} {state}")
            print("-" * 78)
            print("Numbers separated by commas, 'all', 'b' = back, 'q' = quit.")
            value = input("\nSelect features > ")
            if value.strip().lower() in ("q", "quit", "exit"):
                raise SystemExit(0)
            selected = parse_numbers(value, set(ENABLE_OPTIONS))
            if selected is None:
                return
            if not selected:
                pause()
                continue
            apply_selection(selected)
            pause()
        except KeyboardInterrupt:
            warn("Returning to main menu.")
            return


# ----------------------------------------------------------------------------
# Role detection
# ----------------------------------------------------------------------------


def detect_role():
    """Returns (role, reason); role is None when it cannot be determined."""
    if PLATFORM == "windows":
        try:
            if CONF.is_file() or (AGENTD and AGENTD.exists()):
                return "agent", "Windows install found (the Wazuh manager does not run on Windows)"
        except (PermissionError, OSError):
            pass
        return None, "no ossec-agent install found"
    
    # Check packages first (dpkg/rpm works for non-root users)
    for pkg, role in (("wazuh-manager", "manager"), ("wazuh-agent", "agent")):
        try:
            if package_installed(pkg):
                return role, f"package {pkg} installed"
        except Exception:
            pass

    # Check binaries with permission error handling
    try:
        if (BIN / "wazuh-analysisd").is_file():
            return "manager", "wazuh-analysisd binary present"
    except (PermissionError, OSError):
        pass
    try:
        if AGENTD.is_file():
            return "agent", "wazuh-agentd present, no wazuh-analysisd"
    except (PermissionError, OSError):
        pass

    # Check config with permission error handling
    try:
        if CONF.is_file():
            try:
                _, blocks = parse_blocks(CONF, "ossec_config")
            except Exception:
                blocks = []
            if any(True for _ in iter_nodes(blocks, "remote")):
                return "manager", "ossec.conf has a <remote> listener"
            if any(True for _ in iter_nodes(blocks, "client")):
                return "agent", "ossec.conf has a <client> section"
    except (PermissionError, OSError):
        pass

    return None, "no Wazuh binaries, config or packages found"


# ----------------------------------------------------------------------------
# Manager features: fleet, groups, centralized-config baseline
# ----------------------------------------------------------------------------


def agent_list():
    if not AGENT_CONTROL or not safe_exists(AGENT_CONTROL):
        return None
    r = run([str(AGENT_CONTROL), "-l"], timeout=30)
    if not r or r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        m = re.search(r"ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP:\s*([^,]+),\s*(.+?)\s*$", line)
        if m and m.group(1) != "000":
            out.append({"id": m.group(1), "name": m.group(2).strip(),
                        "ip": m.group(3).strip(), "status": m.group(4).strip()})
    return out


def list_groups():
    if not SHARED_DIR or not SHARED_DIR.is_dir():
        return []
    return sorted(p.name for p in SHARED_DIR.iterdir() if p.is_dir())


def verify_agent_conf():
    """(True|False|None, message); None = inconclusive."""
    if not VERIFY_CONF or not safe_exists(VERIFY_CONF):
        return None, "verify-agent-conf not found"
    r = run([str(VERIFY_CONF)], timeout=30)
    if r is None:
        return None, "could not run verify-agent-conf"
    out = (r.stdout + "\n" + r.stderr).strip()
    if r.returncode == 0:
        return True, out or "ok"
    if "usage" in out.lower():
        return None, "verify-agent-conf needs arguments on this version"
    return False, out


BASELINE_BEGIN = "<!-- BEGIN wazuh-console baseline -->"
BASELINE_END = "<!-- END wazuh-console baseline -->"
BASELINE_TEMPLATE = BASELINE_BEGIN + r"""
<!-- Managed block: re-running the tool replaces everything between BEGIN and END. -->
<agent_config os="Linux">
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>
  </syscheck>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>
</agent_config>
<agent_config os="Windows">
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes">%WINDIR%/System32</directories>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  </syscheck>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <hotfixes>yes</hotfixes>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>@@SYSMON@@
</agent_config>
""" + BASELINE_END


def baseline_text(sysmon=False):
    extra = r"""
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>""" if sysmon else ""
    return BASELINE_TEMPLATE.replace("@@SYSMON@@", extra)


def apply_group_baseline(group, sysmon=False, dry_run=False, assume_yes=False, remote_url=None):
    """Write/refresh the managed baseline block in etc/shared/<group>/agent.conf (local or via remote API)."""
    if remote_url:
        # Remote API mode: check auth and push group baseline configuration
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", group or ""):
            error("Invalid group name (letters, digits, _ . - only).")
            return 1
        base, user, pw = api_credentials(interactive_ok=sys.stdin.isatty(), remote_url=remote_url)
        if not (user and pw):
            error("Set WAZUH_API_USER and WAZUH_API_PASSWORD (and optionally --remote).")
            return 1
        try:
            tok = api_request(base, "/security/user/authenticate?raw=true", method="POST",
                              basic=(user, pw), insecure=True).strip()
            # Verify group exists or create it
            groups_resp = json.loads(api_request(base, f"/groups?groups_list={group}", token=tok, insecure=True))
            if not groups_resp.get("data", {}).get("affected_items"):
                if dry_run:
                    info(f"Group '{group}' would be created remotely via Wazuh API.")
                else:
                    api_request(base, f"/groups", token=tok, method="POST", insecure=True)
                    ok(f"Created remote group '{group}'.")
            block = baseline_text(sysmon)
            print(f"\nRemote baseline to upload for group '{group}'" + (" (+Sysmon)" if sysmon else "") + ":")
            print(block)
            if dry_run:
                info("Dry run: nothing was uploaded.")
                return 0
            if not assume_yes and input(f"\nUpload this baseline to remote manager group '{group}'? [y/N]: ").strip().lower() != "y":
                info("Cancelled.")
                return 0
            # Upload configuration via API
            upload_url = f"/groups/{group}/configuration"
            req = urllib.request.Request(base.rstrip("/") + upload_url, method="PUT",
                                        data=block.encode("utf-8"),
                                        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/xml"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                ok(f"Successfully uploaded baseline to remote group '{group}' via Wazuh API.")
            return 0
        except Exception as exc:
            error(f"Remote group baseline failed: {exc}")
            return 1

    if ROLE != "manager":
        error("Group baselines are pushed from the manager (or use --remote <URL>).")
        return 1
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", group or ""):
        error("Invalid group name (letters, digits, _ . - only).")
        return 1
    if not dry_run and not is_admin():
        error("Applying changes needs root (sudo).")
        return 1
    gdir = SHARED_DIR / group
    if not gdir.is_dir():
        if dry_run:
            info(f"Group '{group}' does not exist yet; it would be created with agent_groups.")
        else:
            if not AGENT_GROUPS or not safe_exists(AGENT_GROUPS):
                error(f"Group '{group}' does not exist and agent_groups was not found.")
                return 1
            r = run([str(AGENT_GROUPS), "-a", "-g", group, "-q"], timeout=60)
            if not r or r.returncode != 0 or not gdir.is_dir():
                error("Could not create the group: " + ((r.stdout + r.stderr).strip() if r else "?"))
                return 1
            ok(f"Created group '{group}'.")
    target = gdir / "agent.conf"
    current = read_text(target) if target.exists() else ""
    block = baseline_text(sysmon)
    if BASELINE_BEGIN in current and BASELINE_END in current:
        new = re.sub(re.escape(BASELINE_BEGIN) + r".*?" + re.escape(BASELINE_END),
                     lambda m: block, current, flags=re.S)
    else:
        new = (current.rstrip() + "\n\n" if current.strip() else "") + block + "\n"
    if new == current:
        info("Baseline already up to date; nothing to do.")
        return 0

    try:
        probe = Path(os.environ.get("TMPDIR", "/tmp")) / "wazuh-console-agentconf.check"
        probe.write_text(new, encoding="utf-8")
        _, blocks = parse_blocks(probe, "agent_config")
        probe.unlink(missing_ok=True)
        if not blocks:
            raise ValueError("no <agent_config> blocks")
    except Exception as exc:
        error(f"Generated agent.conf is not valid XML: {exc}")
        return 1

    print(f"\nBaseline for group '{group}'" + (" (+Sysmon)" if sysmon else "") + ":")
    for line in difflib.unified_diff(current.splitlines(), new.splitlines(),
                                     "agent.conf (current)", "agent.conf (proposed)", lineterm=""):
        col = GREEN if line.startswith("+") and not line.startswith("+++") else \
            RED if line.startswith("-") and not line.startswith("---") else GREY
        print(c(line, col))
    warn(f"This applies to EVERY agent in group '{group}'. Try a small canary group first.")
    if dry_run:
        info("Dry run: nothing was written.")
        return 0
    if not assume_yes and input("\nWrite this baseline? [y/N]: ").strip().lower() != "y":
        info("Cancelled. No changes were made.")
        return 0

    backup = None
    if target.exists():
        bdir = BACKUP_DIR / "groups" / group
        bdir.mkdir(parents=True, exist_ok=True)
        backup = bdir / ("agent.conf.backup_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
        shutil.copy2(target, backup)
        info(f"Backup created: {backup}")
    else:
        target.touch()
        st = os.stat(gdir)
        try:
            os.chown(target, st.st_uid, st.st_gid)
            os.chmod(target, 0o660)
        except (PermissionError, AttributeError):
            pass
    try:
        atomic_write(target, new, like=target)
        result, msg = verify_agent_conf()
        if result is False:
            raise RuntimeError("verify-agent-conf failed:\n" + msg)
        if result is None:
            warn("verify-agent-conf was inconclusive (" + msg + "); XML structure was checked.")
        else:
            ok("verify-agent-conf passed.")
    except Exception as exc:
        if backup:
            atomic_write(target, backup.read_text(encoding="utf-8"), like=target)
        else:
            target.unlink(missing_ok=True)
        warn("Restored the previous agent.conf.")
        error(str(exc))
        return 1
    ok("Baseline written. Agents in the group typically fetch it on their next sync and "
       "restart themselves to apply it.")
    info("Assign agents with:  agent_groups -a -i <AGENT_ID> -g " + group + " -q")
    return 0


class ApiError(Exception):
    pass


def api_request(base, path, token=None, method="GET", basic=None,
                insecure=False, timeout=20):
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if basic:
        req.add_header("Authorization", "Basic " +
                       base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode())
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode()
    except urllib.error.HTTPError as exc:
        raise ApiError(f"HTTP {exc.code} for {path.split('?')[0]}")
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise ApiError(f"{path.split('?')[0]}: {getattr(exc, 'reason', exc)}")


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def section_on(section):
    if not isinstance(section, dict):
        return None
    if "disabled" in section:
        return str(section["disabled"]).lower() != "yes"
    if "enabled" in section:
        return str(section["enabled"]).lower() == "yes"
    return None


def fleet_overview(base, user, password, insecure=False, deep=False, deep_limit=200):
    tok = api_request(base, "/security/user/authenticate?raw=true", method="POST",
                      basic=(user, password), insecure=insecure).strip()

    def get(path):
        return json.loads(api_request(base, path, token=tok, insecure=insecure))

    out = {"summary": get("/agents/summary/status").get("data", {}), "agents": []}
    offset = 0
    while True:
        r = get("/agents?select=id,name,version,status,group,os.platform"
                f"&limit=500&offset={offset}").get("data", {})
        items = r.get("affected_items", [])
        out["agents"] += [a for a in items if str(a.get("id")) != "000"]
        offset += 500
        if not items or offset >= r.get("total_affected_items", 0):
            break
    if deep:
        out["deep"] = {}
        active = [a for a in out["agents"] if a.get("status") == "active"][:deep_limit]
        for a in active:
            aid, res = a["id"], {}
            try:
                fim = get(f"/agents/{aid}/config/syscheck/syscheck")
                res["FIM"] = section_on(find_key(fim, "syscheck"))
                rc = get(f"/agents/{aid}/config/syscheck/rootcheck")
                res["Rootcheck"] = section_on(find_key(rc, "rootcheck"))
                wm = get(f"/agents/{aid}/config/wmodules/wmodules")
                res["Syscollector"] = section_on(find_key(wm, "syscollector"))
                res["SCA"] = section_on(find_key(wm, "sca"))
            except (ApiError, ValueError):
                res = {"error": True}
            out["deep"][aid] = res
    return out


def _vt(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def print_fleet(out, manager_version):
    conn = out["summary"].get("connection", out["summary"])
    print(c("FLEET OVERVIEW (Wazuh API)", BOLD + CYAN))
    print("-" * 70)
    print("Agents: " + " | ".join(f"{k}: {conn.get(k, 0)}" for k in
                                  ("total", "active", "disconnected", "never_connected", "pending")))
    agents = out["agents"]
    vers, plats, default_only = {}, {}, 0
    older, newer = [], []
    for a in agents:
        vers[a.get("version", "?")] = vers.get(a.get("version", "?"), 0) + 1
        plat = (a.get("os") or {}).get("platform", "?")
        plats[plat] = plats.get(plat, 0) + 1
        if (a.get("group") or ["default"]) == ["default"]:
            default_only += 1
        av = _vt(a.get("version"))
        if av and manager_version:
            if av < manager_version:
                older.append(a)
            elif av > manager_version:
                newer.append(a)
    print("Versions:  " + ", ".join(f"{k} x{n}" for k, n in sorted(vers.items())))
    print("Platforms: " + ", ".join(f"{k} x{n}" for k, n in sorted(plats.items())))
    print(f"In the 'default' group only: {default_only}")
    if manager_version:
        mv = ".".join(map(str, manager_version))
        print(f"Older than manager ({mv}): {len(older)}  |  NEWER than manager (unsupported): {len(newer)}")
        for a in (older + newer)[:15]:
            print(f"   {a['id']} {a.get('name', '?')} {a.get('version', '?')}")
    if "deep" in out:
        print("\nDeep module check (EXPERIMENTAL; parsed from the API's config output):")
        gaps = 0
        for aid, res in out["deep"].items():
            name = next((a.get("name") for a in agents if a["id"] == aid), "?")
            if res.get("error"):
                print(f"   {aid} {name}: config query failed")
                continue
            off = [k for k, v in res.items() if v is False]
            unk = [k for k, v in res.items() if v is None]
            if off or unk:
                gaps += 1
                print(f"   {aid} {name}: " + (("OFF: " + ", ".join(off)) if off else "") +
                      ((" unknown: " + ", ".join(unk)) if unk else ""))
        if not gaps:
            print("   every checked agent reports FIM/Rootcheck/Syscollector/SCA on.")
    print("-" * 70)


def api_credentials(interactive_ok=True, remote_url=None):
    base = remote_url or os.environ.get("WAZUH_API_URL") or (
        input("API URL [https://localhost:55000] > ").strip() if interactive_ok else "") \
        or "https://localhost:55000"
    user = os.environ.get("WAZUH_API_USER") or (input("API user > ").strip() if interactive_ok else "")
    pw = os.environ.get("WAZUH_API_PASSWORD") or (getpass.getpass("API password > ") if interactive_ok else "")
    return base, user, pw


# ----------------------------------------------------------------------------
# Dynamic IP discovery
# ----------------------------------------------------------------------------


def is_valid_host(value):
    """Check whether value is a valid IPv4, IPv6 address or valid RFC hostname."""
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    # Check if IPv4
    try:
        socket.inet_aton(val)
        parts = val.split(".")
        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
            return True
    except (OSError, ValueError):
        pass
    # Check if IPv6
    try:
        socket.inet_pton(socket.AF_INET6, val)
        return True
    except (OSError, ValueError):
        pass
    # Reject strings that look like numeric IPs but have out-of-range octets (e.g. 999.1.1.1)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
        return False
    # Check if valid Hostname / FQDN (RFC 1123)
    if len(val) > 253 or "<" in val or ">" in val or " " in val or '"' in val or "'" in val:
        return False
    # Hostname labels cannot be entirely numeric if top-level, and must follow RFC rules
    allowed = re.compile(r"^(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\.[A-Za-z0-9-_]{1,63})*$")
    if not allowed.match(val):
        return False
    # Labels should not be all-numeric for the TLD in a dot-separated domain
    labels = val.split(".")
    if len(labels) > 1 and labels[-1].isdigit():
        return False
    return True


def _check_reachability(host, port=None, proto=None, timeout=0.5):
    """
    Check if Wazuh manager port is reachable on host using specified or detected proto/port.
    For TCP: socket connect.
    For UDP: sends an empty ossec keepalive/ping packet or probes UDP socket.
    """
    port = int(port or 1514)
    proto = (proto or "tcp").lower()
    if proto == "udp":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # UDP is connectionless; sending probe packet
            s.sendto(b"", (host, port))
            s.close()
            return True
        except (OSError, socket.timeout):
            return False
    else:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False


def _resolve_dns_fast(name, timeout=0.8):
    """Resolve DNS with a strict timeout to avoid blocking."""
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(socket.gethostbyname, name)
        try:
            return future.result(timeout=timeout)
        except (concurrent.futures.TimeoutError, Exception):
            return None


def get_current_configured_manager():
    """Return (address, port, protocol, is_placeholder, is_reachable)."""
    if not CONF or not Path(CONF).is_file():
        return None, 1514, "tcp", True, False
    try:
        _, blocks = load_config()
        for client_node in iter_nodes(blocks, "client"):
            for srv in client_node.findall("server"):
                addr_el = srv.find("address")
                port_el = srv.find("port")
                proto_el = srv.find("protocol")
                port = int(port_el.text.strip()) if port_el is not None and (port_el.text or "").strip().isdigit() else 1514
                proto = (proto_el.text or "tcp").strip().lower() if proto_el is not None else "tcp"
                if addr_el is not None:
                    raw = (addr_el.text or "").strip()
                    if not raw:
                        return None, port, proto, True, False
                    is_placeholder = raw.lower() in ("0.0.0.0", "127.0.0.1", "manager_ip", "localhost", "none")
                    reachable = _check_reachability(raw, port=port, proto=proto, timeout=1.0) if not is_placeholder else False
                    return raw, port, proto, is_placeholder, reachable
    except Exception:
        pass
    return None, 1514, "tcp", True, False


def _get_local_ips():
    """Return a set of local IP addresses for this machine, to exclude from manager candidates."""
    local = set()
    try:
        import socket
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr and not addr.startswith("::") and addr != "127.0.0.1":
                local.add(addr)
    except Exception:
        pass
    # Also parse /proc/net/fib_trie or ip addr on Linux for more coverage
    if PLATFORM != "windows":
        try:
            r = run(["ip", "-4", "addr", "show"], timeout=5)
            if r and r.stdout:
                for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout):
                    local.add(m.group(1))
        except Exception:
            pass
    local.add("127.0.0.1")
    return local


def discover_manager_ip():
    """
    Auto-discover candidates for the Wazuh Manager without manual input.
    Includes the currently configured manager if set.
    Returns (selected_ip_or_none, candidates_list).
    Each candidate is a tuple: (ip, source_description, is_reachable).
    """
    candidates = []
    seen = set()
    local_ips = _get_local_ips()

    # Get current config port/proto to use consistent probe
    curr_addr, curr_port, curr_proto, curr_placeholder, curr_reachable = get_current_configured_manager()

    def add_candidate(val, desc, timeout=0.5):
        if not val or val in seen or val in local_ips:
            return
        if not is_valid_host(val):
            return
        seen.add(val)
        reachable = _check_reachability(val, port=curr_port, proto=curr_proto, timeout=timeout)
        candidates.append((val, desc, reachable))

    # 1. Current configured manager (if not a placeholder)
    if curr_addr and not curr_placeholder:
        add_candidate(curr_addr, f"current config ({curr_addr})", timeout=1.0)

    # 2. Environment variables
    for env_var in ("WAZUH_MANAGER_IP", "WAZUH_MANAGER", "WAZUH_SERVER"):
        val = os.environ.get(env_var)
        if val:
            add_candidate(val.strip(), f"environment variable ${env_var}", timeout=1.0)

    # 3. DNS Hostname Resolution with timeout
    for name in ("wazuh", "wazuh-manager", "manager"):
        resolved = _resolve_dns_fast(name, timeout=0.8)
        if resolved:
            add_candidate(resolved, f"DNS '{name}' -> {resolved}", timeout=0.8)

    # 4. ARP cache scan (Linux: /proc/net/arp, Windows: arp -a)
    arp_entries = []
    if PLATFORM == "windows":
        r = run(["arp", "-a"], timeout=5)
        if r and r.stdout:
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", r.stdout):
                ip = m.group(1)
                if not ip.startswith("127.") and not ip.endswith(".255") and ip != "255.255.255.255":
                    arp_entries.append(ip)
    else:
        try:
            arp_text = Path("/proc/net/arp").read_text()
            for line in arp_text.splitlines()[1:]:
                parts = line.split()
                if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]) and parts[0] != "0.0.0.0":
                    if len(parts) >= 3 and parts[2] != "0x0":
                        arp_entries.append(parts[0])
        except OSError:
            pass

    for ip in arp_entries:
        add_candidate(ip, f"ARP cache ({ip})", timeout=0.4)

    # 5. Default Gateway
    gateway = None
    if PLATFORM != "windows":
        try:
            route_text = Path("/proc/net/route").read_text()
            for line in route_text.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    b = bytes.fromhex(parts[2])
                    gateway = ".".join(str(b[i]) for i in [3, 2, 1, 0])
                    break
        except Exception:
            pass
    if gateway:
        add_candidate(gateway, f"Default gateway ({gateway})", timeout=0.5)

    # 6. Local subnet sweep (quick sweep on likely manager IPs)
    subnet_base = None
    if gateway:
        subnet_base = gateway.rsplit(".", 1)[0]
    elif local_ips:
        for lip in local_ips:
            if not lip.startswith("127.") and "." in lip:
                subnet_base = lip.rsplit(".", 1)[0]
                break

    if subnet_base:
        for host_num in (5, 10, 2, 3, 4, 1, 50, 100):
            probe_ip = f"{subnet_base}.{host_num}"
            add_candidate(probe_ip, f"Local subnet sweep ({probe_ip})", timeout=0.25)

    # Sort: reachable candidates first
    reachable_candidates = [c for c in candidates if c[2]]
    # Prioritize currently configured manager if it is reachable
    if curr_addr and curr_reachable and any(c[0] == curr_addr for c in reachable_candidates):
        return curr_addr, candidates
    if reachable_candidates:
        return reachable_candidates[0][0], candidates
    # If no candidate is reachable, return None (do NOT pick unreachable candidate in auto mode)
    return None, candidates


def set_manager_ip(target_address, dry_run=False, assume_yes=False, restart=True):
    """
    Safely update <client><server><address> in ossec.conf with:
    - Input validation (valid IP or hostname)
    - Structured XML node manipulation (ET)
    - Full diff preview
    - Automated backup
    - Pre-commit daemon validation (-t)
    - Service restart and reconnection wait
    - Automatic rollback if agent fails to connect
    """
    if ROLE != "agent":
        error("Setting manager IP is an agent capability.")
        return 1

    if not is_valid_host(target_address):
        error(f"Invalid IP address or hostname: '{target_address}'")
        return 1

    if not dry_run and not is_admin():
        error("Updating manager IP requires root (sudo) / Administrator.")
        return 1

    root, blocks = load_config()
    client_nodes = list(iter_nodes(blocks, "client"))
    if not client_nodes:
        error("No <client> block found in ossec.conf.")
        return 1

    client_node = client_nodes[0]
    server_node = client_node.find("server")
    if server_node is None:
        server_node = ET.SubElement(client_node, "server")

    addr_node = server_node.find("address")
    old_address = (addr_node.text or "").strip() if addr_node is not None else "(none)"
    if old_address == target_address:
        info(f"Manager address is already set to {target_address}. No changes needed.")
        return 0

    before = serialize_config(root)

    # Update address node safely via DOM (do NOT inject unsolicited port or protocol tags)
    if addr_node is None:
        addr_node = ET.SubElement(server_node, "address")
    addr_node.text = target_address

    after = serialize_config(root)

    diff = list(difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        "ossec.conf (current)", "ossec.conf (proposed)", lineterm=""))

    print(f"\nManager address change: {old_address} -> {target_address}")
    print("=" * 60)
    for line in diff:
        col = GREEN if line.startswith("+") and not line.startswith("+++") else \
            RED if line.startswith("-") and not line.startswith("---") else GREY
        print(c(line, col))
    print("=" * 60)

    if dry_run:
        info("Dry run: nothing was written.")
        return 0

    if not assume_yes:
        ans = input(f"\nProceed with setting manager IP to '{target_address}'? [y/N] > ").strip().lower()
        if ans != "y":
            info("Cancelled. No changes made.")
            return 0

    with Lock():
        backup = backup_config()
        info(f"Backup created: {backup}")
        try:
            atomic_write(CONF, after)
            valid, message = validate_config()
            if not valid:
                raise RuntimeError("Configuration validation failed:\n" + message)
            ok("Configuration validation passed.")

            if restart:
                good, msg = restart_agent()
                if not good:
                    raise RuntimeError("Agent restart failed: " + msg)
                ok(msg)
                if wait_ready(timeout=35):
                    ok(f"Agent successfully connected to manager at {target_address}!")
                else:
                    # Connection failed: ROLL BACK automatically and exit with failure
                    raise RuntimeError(f"Agent failed to establish connection to manager at {target_address} after restart.")
            else:
                info("Restart skipped (--no-restart). Changes take effect on next restart.")
        except Exception as exc:
            atomic_write(CONF, backup.read_text(encoding="utf-8"), like=CONF)
            warn("Restored previous ossec.conf from backup.")
            if restart:
                restart_agent()
            error(str(exc))
            return 1

    return 0


def auto_set_manager_ip(force=False, assume_yes=False, dry_run=False, restart=True):
    """
    Auto-detect manager candidates across network, show candidates, and configure.
    Only auto-applies a candidate if it is confirmed reachable.
    Keeps the current manager if it is already reachable (even with stale env vars).
    """
    curr_addr, curr_port, curr_proto, is_placeholder, is_reachable = get_current_configured_manager()
    if curr_addr and not is_placeholder and is_reachable and not force:
        info(f"Manager is already configured at '{curr_addr}' and reachable ({curr_proto.upper()}:{curr_port}). No update needed.")
        return 0, curr_addr

    info("Scanning for Wazuh Manager candidates (current config, env vars, DNS, ARP, gateway, subnet)...")
    chosen, candidates = discover_manager_ip()

    if not candidates:
        error("No manager candidates found. Set WAZUH_MANAGER_IP or configure manually.")
        return 1, None

    print("\nDiscovered Manager Candidates:")
    print("-" * 65)
    for idx, (ip, desc, reachable) in enumerate(candidates, 1):
        status_txt = c(f"[{curr_proto.upper()}:{curr_port} OPEN]", GREEN) if reachable else c("[UNREACHABLE]", GREY)
        print(f"  {idx}. {ip:<18} {status_txt}  ({desc})")
    print("-" * 65)

    if not chosen:
        error("No reachable manager candidates detected. Auto-mode will not apply an unreachable address.")
        return 1, None

    target = chosen
    if not assume_yes and not dry_run:
        prompt_val = input(f"\nSelect candidate [1-{len(candidates)}] or enter custom IP/hostname (default: {target}) > ").strip()
        if prompt_val:
            if prompt_val.isdigit() and 1 <= int(prompt_val) <= len(candidates):
                target = candidates[int(prompt_val) - 1][0]
            elif is_valid_host(prompt_val):
                target = prompt_val
            else:
                error(f"Invalid input: {prompt_val}")
                return 1, None

    rc = set_manager_ip(target, dry_run=dry_run, assume_yes=assume_yes, restart=restart)
    return rc, target




# ----------------------------------------------------------------------------
# Interactive screens
# ----------------------------------------------------------------------------


def limitations_screen():
    clear()
    print(c("IMPORTANT LIMITATIONS", BOLD + CYAN))
    print("-" * 72)
    notes = [
        "The tool detects Linux/Windows and agent/manager first and only offers what applies.",
        "ACTIVE = configured + service/daemon running + no errors since last start. It still does "
        "not prove alerts reach the dashboard; error detection is a heuristic read of ossec.log.",
        "Every change shows a diff, is backed up first (last %d kept), validated, and rolled back "
        "automatically on failure. Rewriting ossec.conf normalizes formatting (comments are kept)." % KEEP_BACKUPS,
        "Manager-pushed shared config (agent.conf) is READ by agents' audits but never edited by the "
        "agent workflow. The effective setting may differ from ossec.conf.",
        "Missing logs/services are never created or installed (auditd, ufw, rsyslog, Sysmon, Docker...).",
        "Test in a lab first. This is a helper, not a substitute for the Wazuh documentation.",
    ]
    if PLATFORM == "windows":
        notes += [
            "Windows: run as Administrator. Paths are assumed under Program Files (x86)\\ossec-agent "
            "(override with --root).",
            "Windows: no daemon config-test is used; validation is XML structure only, plus a "
            "service-start check after restart. Restore from backup if the service fails.",
            "Windows: a channel being collected does not mean it has events. Security needs audit "
            "policies, PowerShell needs script-block logging, Sysmon must be installed.",
            "Windows: the Wazuh manager cannot run on Windows; manager features are Linux-only.",
        ]
    elif ROLE == "manager":
        notes += [
            "Manager: restarting pauses analysis for ALL agents (they buffer events). Use a window.",
            "Manager: never auto-enabled (need keys/credentials/risk decisions): open enrollment (authd), "
            "VirusTotal/other integrations, cloud modules, email, logall, agentless.",
            "Manager: Vulnerability Detection is only enabled when the <indexer> connector is configured; "
            "version <4.8 uses the legacy detector and is left to you (threshold: %s, verify)." %
            ".".join(map(str, VULN_NEW_MIN_VERSION)),
            "Manager: a group baseline applies to EVERY agent in that group on its next sync. Use a "
            "canary group first. Agent group membership is not changed by this tool.",
            "Manager: fleet view needs API credentials (env WAZUH_API_USER / WAZUH_API_PASSWORD). "
            "The deep per-agent check is experimental and untested against all API versions.",
        ]
    else:
        notes += [
            "Linux agent: journald and file-based syslog/auth/kern collection overlap; the tool refuses "
            "to enable both (duplicate events). Journald needs agent >= %s (verify for your version)." %
            ".".join(map(str, JOURNALD_MIN_VERSION)),
            "Linux agent: auditd collection only reads the log; you must supply audit rules.",
            "Linux agent: FIM uses a conservative starter directory list. Review paths and performance.",
        ]
    for i, note in enumerate(notes, 1):
        print(textwrap.fill(f"{i:>2}. {note}", 78, subsequent_indent="    "))
    pause()


def validate_screen():
    clear()
    valid, message = validate_config()
    print(c("PASS" if valid else "FAIL", GREEN if valid else RED))
    print(message)
    pause()


def restart_screen():
    clear()
    extra = " (pauses analysis for ALL agents)" if ROLE == "manager" else ""
    if input(f"Restart {SERVICE_NAME} now?{extra} [y/N] > ").strip().lower() == "y":
        good, message = restart_agent()
        print(c("SUCCESS" if good else "FAILED", GREEN if good else RED))
        print(message)
    else:
        info("Restart cancelled.")
    pause()


def rollback_screen():
    clear()
    backups = list_backups()
    if not backups:
        info("No backups yet.")
    else:
        print("Most recent backups:")
        for b in backups[-10:]:
            print("  " + b.name)
        do_rollback("latest")
    pause()


def fleet_screen():
    clear()
    try:
        base, user, pw = api_credentials()
        insecure = input("Skip TLS verification (self-signed certificate)? [y/N] > ").strip().lower() == "y"
        deep = input("Deep per-agent module check (slower, experimental)? [y/N] > ").strip().lower() == "y"
        print_fleet(fleet_overview(base, user, pw, insecure, deep), agent_version())
    except ApiError as exc:
        error(str(exc))
    pause()


def baseline_screen():
    clear()
    groups = list_groups()
    print("Existing groups: " + (", ".join(groups) if groups else "(none)"))
    group = input("Group to apply the baseline to (new names are created) > ").strip()
    if group:
        sysmon = input("Also collect Sysmon on Windows agents in this group? [y/N] > ").strip().lower() == "y"
        apply_group_baseline(group, sysmon)
    pause()


def manager_ip_screen():
    """Interactive: auto-detect and optionally update the manager IP in ossec.conf."""
    clear()
    auto_set_manager_ip(force=False, assume_yes=False)
    pause()


def interactive():
    if not CONF.is_file():
        error(f"Wazuh config not found: {CONF}")
        return 1
    items = [
        ("System overview + capability audit", audit_screen),
        ("Selectively enable features (status-aware, with diff preview)", activation_screen),
        ("Validate current configuration", validate_screen),
        (f"Restart {SERVICE_NAME}", restart_screen),
        ("Roll back to a previous ossec.conf backup", rollback_screen),
    ]
    if ROLE == "manager":
        items += [("Fleet overview via Wazuh API (agents, versions, optional deep check)", fleet_screen),
                  ("Push a baseline to an agent group (Linux + Windows)", baseline_screen)]
    elif ROLE == "agent" and PLATFORM == "linux":
        items.append(("Auto-detect and set manager IP (dynamic discovery)", manager_ip_screen))
    items.append(("Read limitations and safety notes", limitations_screen))
    title = f"WAZUH {ROLE.upper()} CONSOLE  ({PLATFORM})"
    while True:
        clear()
        print(c("=" * 66, CYAN))
        print(c(title.center(66), CYAN))
        print(c("=" * 66, CYAN))
        print()
        for i, (label, _) in enumerate(items, 1):
            print(f" {i}. {label}")
        print(f" {len(items) + 1}. Exit\n")
        try:
            choice = input(f"Choose an option [1-{len(items) + 1}] > ").strip()
            if choice == str(len(items) + 1):
                return 0
            if choice.isdigit() and 1 <= int(choice) <= len(items):
                items[int(choice) - 1][1]()
            else:
                warn("Invalid choice.")
                pause()
        except KeyboardInterrupt:
            print("\nCtrl+C received. Returning to main menu. Choose Exit to leave.")
        except EOFError:
            print("\nInput closed. Exiting.")
            return 0


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Wazuh audit + safe enable tool for agents and managers, Linux and Windows.")
    ap.add_argument("--root", help="Wazuh home (default: auto / $WAZUH_HOME)")
    ap.add_argument("--platform", choices=["auto", "linux", "windows"], default="auto")
    ap.add_argument("--role", choices=["auto", "agent", "manager"], default="auto")
    ap.add_argument("--detect", action="store_true", help="show detected platform/role and exit")
    ap.add_argument("--audit", action="store_true", help="print the capability audit and exit")
    ap.add_argument("--json", action="store_true", help="with --audit: machine-readable output")
    ap.add_argument("--enable", metavar="LIST|all",
                    help="comma-separated option numbers (see --audit / menu) or 'all' eligible")
    ap.add_argument("--dry-run", action="store_true", help="show the diff, change nothing")
    ap.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompts")
    ap.add_argument("--no-restart", action="store_true", help="write config but do not restart")
    ap.add_argument("--validate", action="store_true", help="test the current configuration")
    ap.add_argument("--list-backups", action="store_true")
    ap.add_argument("--rollback", nargs="?", const="latest", metavar="FILE|latest")
    ap.add_argument("--fleet", action="store_true", help="manager: fleet overview via the Wazuh API")
    ap.add_argument("--deep", action="store_true", help="with --fleet: per-agent module check (experimental)")
    ap.add_argument("--insecure", action="store_true", help="with --fleet: skip TLS verification")
    ap.add_argument("--group-baseline", metavar="GROUP",
                    help="manager: write the Linux+Windows baseline into an agent group")
    ap.add_argument("--sysmon", action="store_true", help="with --group-baseline: collect Sysmon on Windows")
    ap.add_argument("--set-manager-ip", nargs="?", const="auto", metavar="IP|auto",
                    help="agent: auto-detect (or set specific) manager IP in ossec.conf (validates, diffs, restarts)")
    ap.add_argument("--remote", metavar="URL",
                    help="connect to a remote Wazuh manager API (e.g. https://manager-ip:55000)")
    args = ap.parse_args(argv)

    configure_paths(args.root, None if args.platform == "auto" else args.platform)
    agent_version.cache_clear()
    windows_channels.cache_clear()

    # Step 1: what are we running on, and is it an agent or a manager?
    # If using remote mode for fleet or group-baseline, bypass local role detection requirement
    remote_mode = bool(args.remote and (args.fleet or args.group_baseline))

    if args.role == "auto":
        role, reason = detect_role()
    else:
        role, reason = args.role, "forced with --role"
    action = any([args.audit, args.enable, args.validate, args.list_backups, args.rollback,
                  args.fleet, args.group_baseline, args.set_manager_ip])
    if role is None and not args.detect and not action and not remote_mode and sys.stdin.isatty():
        warn(f"Could not detect the Wazuh role ({reason}).")
        ans = input("Is this an (a)gent or a (m)anager? > ").strip().lower()
        role = {"a": "agent", "m": "manager"}.get(ans[:1])
        reason = "chosen manually"
    if args.detect:
        print(f"Platform: {PLATFORM}\nRole:     {role or 'unknown'}  ({reason})\n"
              f"Root:     {ROOT}\nConfig:   {CONF}  [{'found' if CONF.is_file() else 'MISSING'}]")
        return 0 if role else 1
    if role is None and not remote_mode:
        error(f"Could not detect whether this is an agent or a manager ({reason}). "
              "Use --role agent|manager (and --root if installed elsewhere) or --remote <URL>.")
        return 1
    if role == "manager" and PLATFORM == "windows":
        error("The Wazuh manager does not run on Windows.")
        return 1
    if role:
        set_role(role)

    try:
        if args.list_backups:
            for b in list_backups():
                print(b)
            return 0
        if args.rollback:
            return do_rollback(args.rollback, args.yes)
        if args.validate:
            valid, message = validate_config()
            print(("PASS\n" if valid else "FAIL\n") + message)
            return 0 if valid else 1
        if args.group_baseline:
            return apply_group_baseline(args.group_baseline, args.sysmon, args.dry_run, args.yes, remote_url=args.remote)
        if args.set_manager_ip:
            if ROLE != "agent":
                error("--set-manager-ip is an agent feature.")
                return 1
            if args.set_manager_ip == "auto":
                rc, ip = auto_set_manager_ip(force=True, assume_yes=args.yes, dry_run=args.dry_run, restart=not args.no_restart)
            else:
                rc = set_manager_ip(args.set_manager_ip, dry_run=args.dry_run, assume_yes=args.yes, restart=not args.no_restart)
                ip = args.set_manager_ip
            return rc
        if args.fleet:
            if ROLE != "manager" and not args.remote:
                error("--fleet requires running on a manager or using --remote <URL>.")
                return 1
            base, user, pw = api_credentials(interactive_ok=sys.stdin.isatty(), remote_url=args.remote)
            if not (user and pw):
                error("Set WAZUH_API_USER and WAZUH_API_PASSWORD (and optionally WAZUH_API_URL or --remote).")
                return 1
            try:
                out = fleet_overview(base, user, pw, args.insecure, args.deep)
            except ApiError as exc:
                error(str(exc))
                return 1
            if args.json:
                print(json.dumps(out, indent=2))
            else:
                print_fleet(out, agent_version())
            return 0
        if args.enable:
            nums = (sorted(ENABLE_OPTIONS) if args.enable.strip().lower() == "all"
                    else parse_numbers(args.enable, set(ENABLE_OPTIONS)))
            if not nums:
                return 2
            return apply_selection(nums, args.dry_run, args.yes, not args.no_restart)
        if args.audit:
            _, blocks = load_config()
            ctx = collect_context()
            rows = run_audit(effective_blocks(blocks), ctx)
            if args.json:
                print(audit_json(blocks, ctx, rows))
            else:
                system_overview(blocks, ctx)
                print_audit(rows)
            return 0
    except (OSError, ET.ParseError, ValueError) as exc:
        error(f"{exc} (try running with sudo / as Administrator?)"
              if isinstance(exc, PermissionError) else str(exc))
        return 1

    if not is_admin():
        warn("Not running as root/Administrator: audit may be incomplete and changes cannot be applied.")
    return interactive()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nConsole closed safely.")
        sys.exit(130)
    except BrokenPipeError:   # e.g. `... --list-backups | head`
        sys.exit(0)
