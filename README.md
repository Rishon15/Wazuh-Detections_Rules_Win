# Wazuh Detection Lab

**Project Status:** - Active.<br>
**Focus:** - Windows Security, Log Analysis and Custom Rule Engineering.<br>
**Tools:** - Wazuh, Sysmon, Atomic Red Team and Powershell.<br>

<br>
<br>

## Project Overview

This repository documents my journey in **Detection Engineering**. The goal is to go past the default Wazuh rules, to create an alert for an actionable threat based on real-world attack scenarios.<br>
In this lab I simulate attacks using Atomic Red Team, analyze raw telemetry/logs generated, and develop custom rules according to their criticality to reduce false positives.

<br>
<br>

## Methodology

For each MITRE ATT&CK scenario, strict engineering lifecycles are followed.
1. **Simulation** - Done by executing scripts via Atomic Red Team.
2. **Analysis** - Review raw logs to identify unique patterns.
3. **Engineering** - Develop specific REGEX or XML rules to filter noise and target intent.
4. **Validation** - Re-running the attack to validate the created rules and its effects.

<br>
<br>

## Detection Portfolio

| Tactic | Technique | Description |
|---|---|---|
| Discovery | T1016 | Network & System Configuration Discovery |
| Lateral Movement | T1021 | Remote Service Login |
| Credential Access | T1003 | Credential Dumping using pypykatz |
| Command & Control | T1071 | C2 via web Protocols |
| Persistence | T1053 | Persistence via Scheduled Task |
| Defense Evasion | T1070 | Clearing Windows Event Logs |
| Privilege Escalation | T1548 | User Access Control Bypass |
| Impact | T1490 | Clearing Backups using Windows Binaries |

<br>
<br>

## Tech Stack

- **SIEM:** Wazuh 4.x
- **Endpoint:** Windows 10 (Sysmon Configured), Windows 11 (Enterprise)
- **Simulation:** Atomic Red Team (PowerShell)
- **Log Source:** Sysmon configuration using [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
