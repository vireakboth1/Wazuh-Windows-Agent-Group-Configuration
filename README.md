# Wazuh Windows Agent Group Configuration

**Balanced Monitoring Profile for General Windows Endpoints**

| Field | Value |
|---|---|
| Document Version | 1.0 |
| Date | March 2026 |
| Wazuh Compatibility | 4.8+ (tested on 4.12–4.14) |
| Target Group Name | `windows-general` / `windows-workstations-balanced` |

**Purpose:** Centralized configuration for Wazuh agents on typical Windows 10/11 workstations and non-domain-critical servers.

**Author Notes:** This profile prioritises high-signal / low-noise collection: focused Sysmon + key Security events, limited realtime FIM on risky paths, and Defender/PowerShell/Task Scheduler coverage for persistence & execution threats.

---

## 1. Overview & Design Goals

This configuration is applied via centralised agent groups to avoid per-agent edits.

### Key Objectives

- Detect common attack chains: initial access → execution → persistence → defence evasion → C2
- Balance detection vs. performance (EPS throttling, selective XPath queries)
- Minimise alert fatigue (filter out low-value events)
- Enable `whodata` + realtime FIM only where it adds attribution value
- Support MITRE ATT&CK coverage:
  - T1059 – Command and Scripting Interpreter
  - T1547 – Boot or Logon Autostart Execution
  - T1562 – Impair Defenses
  - T1071 – Application Layer Protocol (C2)

### Intentionally Excluded

- Full Sysmon (EventID 8/10/23 are omitted unless ransomware focus is required)
- Broad Application/System logs (only errors/critical + selected IDs)
- Heavy registry scanning beyond persistence-relevant keys

---

## 2. Deployment Instructions

### 2.1 Create the Group (on Wazuh Manager)

```bash
/var/ossec/bin/agent_groups -a -g windows-general
```

### 2.2 Assign Agents

```bash
# Single agent (example: agent ID 005)
/var/ossec/bin/agent_groups -a -i 005 -g windows-general
```

Bulk-assign via dashboard: **Management → Groups → windows-general → Manage Agents**

### 2.3 Deploy the Configuration File

Copy `agent.conf` to the group shared directory on the manager:

```
/var/ossec/etc/shared/windows-general/agent.conf
```

The manager auto-syncs changes to agents (poll interval ~10–60 s). No agent restart is usually needed.

### 2.4 Verify Deployment

**Manager side:**

```bash
/var/ossec/bin/agent_groups -s -g windows-general
```

**Agent side (Windows):**

Check the merged config at:
```
C:\Program Files (x86)\ossec-agent\shared\agent.conf
```

**Agent log confirmation:**

Look for the following line in the agent `ossec.log`:
```
Configuration received and merged
```

**Dashboard:**

Navigate to **Agents → [agent] → Syscheck / Rootcheck / Events** tabs.

---

## 3. Configuration Breakdown & Rationale

### 3.1 Client Buffer

```xml
<client_buffer>
  <queue_size>5000</queue_size>
  <events_per_second>250</events_per_second>
</client_buffer>
```

- Prevents buffer overflow during bursts (patching, logon storms).
- 250 EPS is conservative — safe for mid-range endpoints (4–16 GB RAM).

### 3.2 Event Log Monitoring (`<localfile>`)

All channels use `<log_format>eventchannel</log_format>` with XPath queries for precision.

| Channel | Key Event IDs / Filters | Purpose / Coverage | Notes |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | 1, 3, 7, 11, 12, 13, 22 | Process create, network, image load, file/reg, DNS | High-value only; avoids noisy IDs like 23 unless ransomware focus |
| `Application` | Level ≤ 3 (Critical/Error/Warning) | App crashes, failures | Broader than default for better visibility |
| `Security` | 4624, 4625, 4648, 4672, 4697–4698, 4720–4726, 4732–4733, 4740, 4756, 1102, 5140, 4719, 6416, 4663, 4768, 4769, 4776 | Logon/logoff, privilege use, account mgmt, policy changes, share access, Kerberos/NTLM | Strong auth + privilege + persistence coverage |
| `System` | Level 1–2 + 7022–7024, 7031, 7034, 1074, 6005–6008, 104 | Service failures, shutdowns, BSOD hints | Critical system health + unexpected reboots |
| `Microsoft-Windows-Windows Defender/Operational` | 1116–1119, 1121–1124, 5000–5001 | Detections, quarantines, AV status | Malware/defender tampering focus |
| `Microsoft-Windows-PowerShell/Operational` | 4103, 4105, 4106 | Module logging, script execution | Enhanced coverage: script block + pipeline tracking |
| `Microsoft-Windows-TaskScheduler/Operational` | 100, 102, 106, 140, 141, 200, 201 | Task creation/registration/update | Persistence via scheduled tasks |
| `Microsoft-Windows-Windows Firewall.../Firewall` | 2003–2006, 2009 | Rule/profile changes | Firewall tampering detection |
| `Microsoft-Windows-WMI-Activity/Operational` | 5859–5861 | WMI activity (filtering) | Malicious WMI persistence/execution |
| `Microsoft-Windows-DNS-Client/Operational` | 3006–3008 | DNS query resolution failures/success | C2 / suspicious resolution |
| `Microsoft-Windows-DriverFrameworks-UserMode/Operational` | 2003, 2100, 2102, 2105 | USB device connect/disconnect | Removable media threats |
| `active-responses.log` | syslog | Local AR actions | Visibility into agent-triggered responses |

### 3.3 Rootcheck & SCA

- **rootcheck:** Uses shared Windows malware/apps lists for basic policy/malware scanning.
- **sca:** 24-hour interval + `scan_on_start` — detects CIS benchmark drift with reduced overhead.

### 3.4 Syscheck (FIM)

| Setting | Value | Rationale |
|---|---|---|
| `frequency` | 86400 s (daily) | Full scan once per day |
| `scan_on_start` | yes | Catches changes made while agent was offline |
| Realtime + whodata | Downloads, Documents, Temp, Startup | Restricted to paths with high malicious-write risk |
| Ignores | Browser caches, Windows Update, logs, thumbs.db, Prefetch, Recycle.Bin | Eliminates false positives from high-churn paths |
| Registry keys | User/HKLM Run, RunOnce, Shell Folders, Active Setup, Winlogon, AppInit_DLLs, IFEO | Persistence-focused; ignores noisy service keys + USB history |

> **Best Practice:** `whodata="yes"` automatically enables realtime monitoring and records *who* made each change via Windows Audit/SACLs. Avoid applying `whodata` to very large directories (e.g., `C:\`) to prevent a performance impact.

---

## 4. Potential Enhancements (Test Before Applying)

| Enhancement | Details |
|---|---|
| Additional Sysmon IDs | Add 6 (driver load), 8 (remote thread), 10 (process access), 23 (file delete) for ransomware focus |
| Additional Security IDs | Add 4688 (process create – noisy), 5145 (network share access) |
| Additional FIM paths | `%PROGRAMFILES%\Windows Defender`, `C:\ProgramData` (executables only) |
| Larger buffer | Increase `queue_size` to 8000–15000 if event bursts are observed |
| Future-events filter | `<only_future_events>yes</only_future_events>` already applied to Security, Sysmon, PowerShell, DNS to skip historical floods after restarts |

---

## 5. Monitoring & Tuning Tips

1. **Dashboard:** Go to **Modules → Events** and filter by `rule.groups: sysmon`, `windows`, or `attacker`.
2. **Buffer health:** Watch agent logs for `buffer full` or high CPU usage.
3. **Config sync status:** Check via **Agents → [agent] → Configuration sync status** in the dashboard.
4. **False-positive tuning:** Override rules on the manager (set `level` to `0`) for noisy event IDs rather than broadening the XPath filters.
5. **Subgroup customisation:** Create child groups such as `windows-laptops` or `windows-servers-critical` for stricter or more permissive tuning.

---

## File Reference

| File | Description |
|---|---|
| `agent.conf` | Full Wazuh agent group configuration for Windows endpoints |

---

This profile provides strong visibility with manageable load — ideal as a baseline for most Windows fleets. Customise subgroups for environments that require stricter or more permissive monitoring.