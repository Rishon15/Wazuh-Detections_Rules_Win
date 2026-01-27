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

| Phase | Technique | Description | Log Source |
|---|---|---|---|
| Discovery | T1016 | Network & System Configuration Discovery | Process Creation (EventID = 1) |
| Lateral Movement | T1021 | Remote Service Login | Authentication (EventID = 4624) |
<br>
<br>

## Tech Stack

- **SIEM:** Wazuh 4.x
- **Endpoint:** Windows 10 (Sysmon Configured)
- **Simulation:** Atomic Red Team (PowerShell)
- **Log Source:** Sysmon Event ID 1 (Process Creation), Event ID 3 (Network), Windows Security (4624)
