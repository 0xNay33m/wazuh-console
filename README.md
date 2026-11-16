<div align="center">

# 🛡️ Wazuh Console

**One script to audit, understand, and safely harden your Wazuh agents and managers, on Linux and Windows.**

![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![Roles](https://img.shields.io/badge/role-agent%20%7C%20manager-blue)
![Version](https://img.shields.io/badge/version-3.1-orange)

</div>

---

## Table of Contents

- [Why Wazuh Console?](#why-wazuh-console)
- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [The audit](#the-audit)
- [Enabling features safely](#enabling-features-safely)
- [Manager features](#manager-features)
- [Agent features](#agent-features)
- [Command-line reference](#command-line-reference)
- [Environment variables](#environment-variables)
- [Backups and rollback](#backups-and-rollback)
- [Automation and exit codes](#automation-and-exit-codes)
- [Safety model](#safety-model)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Why Wazuh Console?

A Wazuh deployment can look healthy while quietly missing half of what you thought it was collecting: a module that is *configured* but whose daemon is down, a log source that exists but is never read, a channel that errors on every start, or a manager with wide-open agent enrollment.

Wazuh Console answers one question quickly: **"What is this host actually doing, and what is it missing?"** It then lets you fix the gaps without hand-editing XML and hoping for the best.

- 🔍 **Read-only audit first.** Nothing changes unless you ask it to.
- 🧠 **Evidence-based status.** It cross-checks config, running daemons, and `ossec.log` errors, not just whether a tag exists.
- 🧰 **Safe changes.** Every edit is previewed as a diff, backed up, validated, and rolled back automatically if something breaks.
- 🪶 **Zero dependencies.** A single Python file using only the standard library.

---

## Features

| Area | What you get |
|------|--------------|
| **Auto-detection** | Detects Linux vs Windows and agent vs manager, then shows only the options that apply |
| **Capability audit** | Colorised table (or JSON) covering FIM, Rootcheck, Syscollector, SCA, log sources, integrations, cloud modules, fleet health, and more |
| **Runtime evidence** | Daemon liveness, agent connection state, and recent `ossec.log` errors feed into each status |
| **Selective enable** | Turn on FIM, Rootcheck, Syscollector, SCA, log sources, Windows event channels, and Vulnerability Detection |
| **Diff preview** | Unified diff of `ossec.conf` before anything is written |
| **Backups and rollback** | Timestamped backups (last 20 kept) with one-command rollback |
| **Validation** | XML check everywhere, plus daemon `-t` config tests on Linux |
| **Auto-rollback** | Restores the previous config if validation fails, the service will not restart, or the agent cannot reconnect |
| **Duplicate protection** | Refuses to enable journald and file-based syslog/auth/kern together (duplicate events) |
| **Shared config awareness** | Reads manager-pushed `agent.conf` so the audit reflects the *effective* config |
| **Fleet view** | Agent counts, versions, platforms, group coverage, and version drift via the Wazuh API |
| **Group baselines** | Push a managed Linux + Windows baseline to an agent group |
| **Manager discovery** | Agents can auto-detect and set the manager address (validated, diffed, reconnect-checked) |
| **Automation friendly** | Non-interactive flags, `--json` output, and sensible exit codes |

---

## How it works

```
                 ┌─────────────────────────────┐
                 │  Step 1: detect environment │
                 │   Linux | Windows           │
                 │   agent | manager           │
                 └──────────────┬──────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        ▼                       ▼                        ▼
  Linux agent             Windows agent             Linux manager
  FIM / Rootcheck /       FIM / Rootcheck /         Services, modules,
  Syscollector / SCA      Syscollector / SCA        integrations, cloud,
  + log sources           + Event Log channels      fleet, Vuln Detection
                                │
                                ▼
                 ┌─────────────────────────────┐
                 │ Audit (read-only)           │
                 └──────────────┬──────────────┘
                                ▼
          Opt-in change:  diff → backup → write → validate
                          → restart → verify → (auto-rollback on failure)
```

---

## Requirements

- **Python 3.8+** (3.9+ recommended for nicer XML formatting). No third-party packages.
- An existing **Wazuh agent or manager** installation.
- **Root / Administrator** to apply changes. The audit also runs unprivileged, but may be incomplete.
- Wazuh API credentials, only for `--fleet` and remote group baselines.

> **Windows note:** the Wazuh manager does not run on Windows, so manager features are Linux-only. Windows hosts are treated as agents.

---

## Quick start

```bash
# Get the script
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>

# Linux: interactive menu
sudo python3 wazuh-console.py

# Windows (PowerShell as Administrator)
python wazuh-console.py
```

Not sure what it will detect? Ask first:

```bash
sudo python3 wazuh-console.py --detect
```

```
Platform: linux
Role:     agent  (package wazuh-agent installed)
Root:     /var/ossec
Config:   /var/ossec/etc/ossec.conf  [found]
```

Run a one-shot audit and exit:

```bash
sudo python3 wazuh-console.py --audit
```

### The interactive menu

```
==================================================================
                  WAZUH AGENT CONSOLE  (linux)
==================================================================

 1. System overview + capability audit
 2. Selectively enable features (status-aware, with diff preview)
 3. Validate current configuration
 4. Restart wazuh-agent
 5. Roll back to a previous ossec.conf backup
 6. Auto-detect and set manager IP (dynamic discovery)
 7. Read limitations and safety notes
 8. Exit
```

Managers get extra entries for the **fleet overview** and **group baselines**. The menu adapts to what it detects.

---

## The audit

`--audit` (or menu option 1) prints a system overview followed by a capability table. Each row gets a status derived from **configuration + daemon state + log evidence**:

| Status | Meaning |
|--------|---------|
| 🟢 `ACTIVE` | Configured, daemon running, no errors since the last start |
| 🟡 `CONFIGURED` | Configured, but the responsible daemon or service is not running |
| 🔴 `DEGRADED` | Configured and running, but `ossec.log` shows errors (for example, a file the agent cannot open) |
| 🔴 `DOWN` | A required daemon is not running |
| 🔴 `MISSING` | The thing it needs (binary, log file, package, channel) is not present |
| 🟡 `DISABLED` | Present on the host but not enabled in the config |
| 🟡 `CHECK` | Needs a human look (partial coverage, open enrollment, and so on) |
| 🔵 `MANAGER CHECK` | Lives on the manager; the agent can only verify its own prerequisites |
| ⚪ `N/A` | Does not apply to this host |

### What gets audited

<details>
<summary><b>Linux agent</b></summary>

Logcollector, FIM, Rootcheck, Syscollector, SCA, command monitoring, Active Response, system syslog, PAM/auth, SSH, sudo, Linux Audit (auditd), journald, cron, kernel logs, Apache/Nginx, MySQL/PostgreSQL, UFW, Docker listener, Osquery, plus manager-side items (Vulnerability Detection, malware/IOC, YARA, VirusTotal, cloud, agentless) with their agent-side prerequisites.

</details>

<details>
<summary><b>Windows agent</b></summary>

Agent service, FIM (including registry monitoring), Rootcheck, Syscollector, SCA, command monitoring, Active Response, and Event Log channels: Security, System, Application, Sysmon, PowerShell, Windows Defender, Task Scheduler, Windows Firewall, RDP, and WinRM. Also Osquery and manager-side prerequisites.

</details>

<details>
<summary><b>Linux manager</b></summary>

analysisd, remoted (listeners), authd (flags **open enrollment**), API, wazuh-db, cluster, indexer connector (including missing TLS files), indexer / Filebeat / dashboard services, FIM/Rootcheck/Syscollector/SCA on the manager host, Vulnerability Detection, Active Response, VirusTotal and other integrations, OpenSCAP, CIS-CAT, Osquery, Docker, AWS S3, Azure, GCP, Office 365, agentless, email alerts, `logall` archiving, local log collection, enrolled-agent health, and agent groups with `verify-agent-conf`.

</details>

### JSON output

```bash
sudo python3 wazuh-console.py --audit --json > audit.json
```

The JSON includes host, role, platform, OS, version, daemon states, connection state, a timestamp, and every capability row, which is handy for dashboards and compliance evidence.

---

## Enabling features safely

List what is available from the menu (**option 2**) or go straight to the CLI. Option numbers depend on the detected profile.

### Linux agent

| # | Feature | # | Feature |
|---|---------|---|---------|
| 2 | FIM | 14 | Cron log collection |
| 3 | Rootcheck | 15 | Kernel log collection |
| 4 | Syscollector | 16 | Apache / Nginx logs |
| 5 | SCA | 17 | MySQL / PostgreSQL logs |
| 8 | System syslog | 20 | UFW firewall log |
| 9 | Authentication / PAM / SSH / sudo | 12 | Linux Audit (auditd) log |
| 13 | Journald collection | | |

### Windows agent

| # | Feature | # | Feature |
|---|---------|---|---------|
| 2 | FIM | 11 | Sysmon |
| 3 | Rootcheck | 12 | PowerShell |
| 4 | Syscollector | 13 | Windows Defender |
| 5 | SCA | 14 | Task Scheduler |
| 8 | Security log | 15 | Windows Firewall |
| 9 | System log | 16 | RDP sessions |
| 10 | Application log | 17 | WinRM |

### Linux manager

| # | Feature |
|---|---------|
| 11 | FIM (manager host) |
| 12 | Rootcheck (manager host) |
| 13 | Syscollector (manager host) |
| 14 | SCA (manager host) |
| 15 | Vulnerability Detection |

### Examples

```bash
# Preview only: show the diff, change nothing
sudo python3 wazuh-console.py --enable 2,3,4,5 --dry-run

# Enable FIM + SCA, confirm interactively
sudo python3 wazuh-console.py --enable 2,5

# Enable everything eligible, unattended
sudo python3 wazuh-console.py --enable all --yes

# Write the config but do not restart yet
sudo python3 wazuh-console.py --enable 8,9 --no-restart
```

### What a change looks like

```
Planned changes:
   2. FIM
   5. SCA

Diff preview:
--- ossec.conf (current)
+++ ossec.conf (proposed)
+  <sca>
+    <enabled>yes</enabled>
+    <scan_on_start>yes</scan_on_start>
+  </sca>

Proceed with these changes? [y/N]:
Backup created: /var/ossec/etc/backups/ossec.conf.backup_20260101_120000_123456
[OK]    Configuration validation passed.
[OK]    wazuh-agent service is active.
[OK]    Agent is up and connected to the manager.
```

### Smart refusals

Wazuh Console says **no** when enabling something would be wrong, and tells you why:

- The log file does not exist on this host
- The event channel is not present (for example, Sysmon not installed)
- Journald would duplicate events already collected from files (and vice versa)
- The agent version is too old for journald
- Vulnerability Detection is requested but the `<indexer>` connector is not configured, or the manager is on the legacy (pre-4.8) detector

It also **never installs or creates** missing software or logs (auditd, ufw, rsyslog, Sysmon, Docker, and so on).

---

## Manager features

### Fleet overview

Pulls agent data from the Wazuh API and summarises it:

```bash
export WAZUH_API_USER=wazuh-wui
export WAZUH_API_PASSWORD='********'

sudo -E python3 wazuh-console.py --fleet --insecure          # self-signed cert
sudo -E python3 wazuh-console.py --fleet --deep --insecure   # + per-agent module check (experimental)
sudo -E python3 wazuh-console.py --fleet --json              # machine-readable
```

You get totals by connection state, version and platform distribution, agents only in the `default` group, and agents **older or newer than the manager** (newer agents are unsupported). `--deep` queries each active agent's config for FIM, Rootcheck, Syscollector, and SCA.

You can also point it at a remote manager from any machine:

```bash
python3 wazuh-console.py --fleet --remote https://manager.example.com:55000
```

### Group baselines

Write a managed Linux + Windows baseline (FIM, Rootcheck, Syscollector, SCA, and core Windows event channels) into an agent group's centralized `agent.conf`:

```bash
# Preview
sudo python3 wazuh-console.py --group-baseline canary --dry-run

# Apply, and also collect Sysmon on Windows agents in the group
sudo python3 wazuh-console.py --group-baseline canary --sysmon
```

- The tool only manages the block between `BEGIN wazuh-console baseline` and `END wazuh-console baseline`. Re-running it **replaces just that block** and leaves the rest of your `agent.conf` alone.
- The group is created with `agent_groups` if it does not exist.
- The result is validated (XML plus `verify-agent-conf`) and the previous file is restored on failure.
- ⚠️ A baseline applies to **every agent in the group** on its next sync. **Try a small canary group first.**
- Assign agents with: `agent_groups -a -i <AGENT_ID> -g <GROUP> -q`

---

## Agent features

### Dynamic manager discovery

Agents can find and configure their manager address. The tool probes, in order: the currently configured manager, environment variables, DNS names (`wazuh`, `wazuh-manager`, `manager`), the ARP cache, the default gateway, and a short list of likely addresses on the local subnet. It only auto-applies a candidate that is **confirmed reachable** on the configured manager port.

```bash
# Auto-detect (interactive selection)
sudo python3 wazuh-console.py --set-manager-ip

# Set a specific address (IPv4, IPv6, or hostname; validated)
sudo python3 wazuh-console.py --set-manager-ip 10.0.0.5

# Preview only
sudo python3 wazuh-console.py --set-manager-ip 10.0.0.5 --dry-run
```

If the agent **fails to reconnect** after the change, the previous `ossec.conf` is restored automatically.

---

## Command-line reference

```
usage: wazuh-console.py [options]
```

| Flag | Description |
|------|-------------|
| *(no flags)* | Start the interactive console |
| `--detect` | Show detected platform / role / paths and exit |
| `--audit` | Print the capability audit and exit |
| `--json` | With `--audit` or `--fleet`: machine-readable output |
| `--enable LIST\|all` | Enable options by number (comma-separated) or every eligible option |
| `--dry-run` | Show the diff and change nothing |
| `-y`, `--yes` | Skip confirmation prompts |
| `--no-restart` | Write the config but do not restart the service |
| `--validate` | Test the current configuration |
| `--list-backups` | List available `ossec.conf` backups |
| `--rollback [FILE\|latest]` | Restore a backup (default: latest) |
| `--fleet` | Manager (or `--remote`): fleet overview via the Wazuh API |
| `--deep` | With `--fleet`: per-agent module check (experimental) |
| `--insecure` | With `--fleet`: skip TLS verification (self-signed certs) |
| `--group-baseline GROUP` | Write the managed baseline into an agent group |
| `--sysmon` | With `--group-baseline`: also collect Sysmon on Windows agents |
| `--set-manager-ip [IP\|auto]` | Agent: set or auto-detect the manager address |
| `--remote URL` | Use a remote Wazuh manager API, e.g. `https://manager-ip:55000` |
| `--platform {auto,linux,windows}` | Override platform detection |
| `--role {auto,agent,manager}` | Override role detection |
| `--root DIR` | Wazuh home directory (default: auto / `$WAZUH_HOME`) |

---

## Environment variables

| Variable | Purpose |
|----------|---------|
| `WAZUH_HOME` | Override the Wazuh install directory (same as `--root`) |
| `WAZUH_API_URL` | API base URL (default `https://localhost:55000`) |
| `WAZUH_API_USER` | API username for `--fleet` and remote baselines |
| `WAZUH_API_PASSWORD` | API password for `--fleet` and remote baselines |
| `WAZUH_MANAGER_IP` / `WAZUH_MANAGER` / `WAZUH_SERVER` | Hints for manager discovery |

Default install paths:

| Platform | Root | Config |
|----------|------|--------|
| Linux | `/var/ossec` | `/var/ossec/etc/ossec.conf` |
| Windows | `C:\Program Files (x86)\ossec-agent` | `...\ossec-agent\ossec.conf` |

---

## Backups and rollback

Every change creates a timestamped backup **before** anything is written. The 20 most recent are kept.

| Platform | Backup location |
|----------|-----------------|
| Linux | `/var/ossec/etc/backups/` |
| Windows | `...\ossec-agent\backups\` |
| Group baselines | `<backups>/groups/<group>/` |

```bash
sudo python3 wazuh-console.py --list-backups
sudo python3 wazuh-console.py --rollback            # latest
sudo python3 wazuh-console.py --rollback /var/ossec/etc/backups/ossec.conf.backup_20260101_120000_123456
```

A rollback first saves your *current* config as a fresh backup, validates the restored file, and puts the current config back if the backup fails validation.

---

## Automation and exit codes

Everything interactive has a flag, so it slots into configuration management, cron, or CI:

```bash
# Nightly audit to JSON
sudo python3 wazuh-console.py --audit --json > /var/log/wazuh-audit-$(date +%F).json

# Fail a pipeline if the config is invalid
sudo python3 wazuh-console.py --validate || exit 1
```

| Code | Meaning |
|------|---------|
| `0` | Success (or nothing to do) |
| `1` | Error: permissions, validation or restart failure, role not detected, API failure |
| `2` | Invalid `--enable` selection |
| `130` | Interrupted (Ctrl+C) |

Only one instance can apply changes at a time (file lock).

---

## Safety model

Wazuh Console is designed so that a bad day does not become a worse one.

1. **Audit is strictly read-only.**
2. **Changes are opt-in** and show a unified diff first (`--dry-run` stops there).
3. **Backup before write**, with original file mode and ownership preserved (atomic write via temp file and rename).
4. **Validate before restart.** XML is checked everywhere; Linux additionally runs `-t` config tests on the relevant daemons.
5. **Verify after restart.** The service must come back, and agents must reconnect.
6. **Automatic rollback** if any of the above fails.
7. **Never auto-enabled** because they need credentials, keys, or a risk decision: open enrollment, VirusTotal and other integrations, cloud modules, email alerts, `logall`, agentless, Docker, and Osquery.
8. **Manager restarts warn you** that analysis pauses for all agents while it happens.
9. **Shared `agent.conf` is read, never edited** by the agent workflow. Only the group baseline feature writes to it, and only inside its own marked block.

---

## Limitations

Please read these before using it in production:

- **Test in a lab first.** This is a helper, not a substitute for the [Wazuh documentation](https://documentation.wazuh.com/).
- `ACTIVE` means *configured + running + no errors since last start*. It does **not** prove alerts reach the dashboard. Error detection is a heuristic read of `ossec.log`.
- Rewriting `ossec.conf` **normalizes formatting** (comments are preserved).
- **Windows:** no daemon config-test exists, so validation is XML structure plus a service-start check. A collected channel is not necessarily producing events (Security needs audit policies, PowerShell needs script-block logging, Sysmon must be installed).
- **Linux agent:** auditd collection only *reads* the log; you supply the audit rules. The FIM starter directory list is deliberately conservative; review it for your environment.
- **Manager:** Vulnerability Detection is only enabled when the `<indexer>` connector is configured. Version thresholds (4.8) for journald and the new detector are best-effort; verify against the docs for your version.
- `--fleet --deep` is **experimental** and parses the API's config output, which can vary between versions.
- API calls made with `--insecure`, and remote group baseline uploads, skip TLS certificate verification. Only use them on networks you trust, or put a proper certificate on the API.
- Remote group baselines (`--remote` with `--group-baseline`) are newer than the local path; use `--dry-run` and verify the result on the manager.

---

## Troubleshooting

<details>
<summary><b>"Could not detect whether this is an agent or a manager"</b></summary>

Wazuh was not found in the default location. Point the tool at it:

```bash
sudo python3 wazuh-console.py --root /opt/wazuh --role agent --audit
```

</details>

<details>
<summary><b>Audit shows odd results or "run as Administrator" hints</b></summary>

Run with `sudo` (Linux) or an elevated prompt (Windows). Unprivileged users cannot read most Wazuh paths or inspect other processes, so the audit falls back to weaker checks.

</details>

<details>
<summary><b>"Another instance is already applying changes"</b></summary>

A previous run holds the lock, or another admin is running the tool. Wait for it to finish, then retry.

</details>

<details>
<summary><b>A feature says BLOCKED or is skipped</b></summary>

The reason is printed next to it, for example a missing log file, absent event channel, journald/file overlap, or missing `<indexer>` block. Fix the prerequisite on the host, then run the audit again.

</details>

<details>
<summary><b>Fleet view fails with a TLS error</b></summary>

The API likely uses a self-signed certificate. Use `--insecure` on a trusted network, or install a certificate your host trusts.

</details>

<details>
<summary><b>The change was applied but the audit still shows CHECK or DEGRADED</b></summary>

Give the agent a few minutes to restart its modules, then re-run the audit; it reads recent `ossec.log` entries. A `DEGRADED` row includes the latest error line to guide you.

</details>

---

## Contributing

Issues and pull requests are welcome. If you add a new capability:

1. Add an audit row in the relevant `audit_*` function.
2. If it can be enabled safely, register it in `PROFILE_OPTIONS` (and `LOG_SOURCES` / `WIN_CHANNELS` where relevant).
3. Make sure it follows the existing contract: **preview → backup → validate → rollback**.
4. Test against a copy using `--root` rather than a production install.

Please include your OS, Wazuh version, and the (redacted) output of `--detect` and `--audit` when reporting bugs.

---

## License

Add your license here (for example, MIT or Apache-2.0) and include a `LICENSE` file in the repository.

---

<div align="center">

*Wazuh is a trademark of Wazuh, Inc. This project is an independent community tool and is not affiliated with or endorsed by Wazuh.*

</div>
