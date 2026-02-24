# [T1053](https://attack.mitre.org/techniques/T1053/)

This technique is used by adversaries to achieve persistence over a system remotely, this is done by abusing "Task Scheduling" functionality. Task scheduling is a method of executing a specific task or script at a specific date and time.
 Requires initial foothold on a system as a member of an admin or otherwise privileged group on the remote system.

## [T1053.005](https://attack.mitre.org/techniques/T1053/005/): Persistence via Scheduled Tasks

### 1. Scenario

This test simulates how adversaries can abuse the "Windows Task Scheduler" to perform task scheduling for initial or recurring execution of malicious code. 
In this case [schtasks.exe](https://attack.mitre.org/software/S0111) utility is run directly on the command from "temp" directory.

### 2. Problem

![T1053.005 BEfore_Rule picture](../Evidences/T1053.005%20Before_Rule.png)

- **Tuning**: Default Wazuh rules only classified the event as suspicious process creation which is a low severity alert, thus requiring tuning to meet situation expectations.
- **Use Case**: `schtask.exe` is a legitimate Windows binary used daily by administrators and the `NT AUTHORITY\SYSTEM` account for updates and maintenance.
- **Noise**: Creating a rule that alerts on `schtasks /create` generates massive false positives in a production environment.
- **Privilege Gap**: Common fix would be to whitelist the `SYSTEM` account. However, attackers often escalate privileges to `SYSTEM` before establishing persistence, whitelisting this could create a blindspot.

### 3. Solution

1. **Log Analysis**: During the simulation, I analyzed the Sysmon EventID 1 logs and noticed that `schtasks.exe` command was executed from `C:\Users\....\AppData\Local\Temp\`.
2. **Contextual Rule**: Legitimate administrative tasks are almost always executed from `C:\Windows\System32` or valid Program file directories, however malware typically execute these commands from writable temporary directories. (`Temp`, `AppData`, `Public`).
3. **Fix**: I engineered a rule that targets the **behavior** of executing malicious commands from suspicious directories like `Temp` in this case instead of targeting who executed the script.

### 4. Custom Rules

#### Before Audit

```xml
<group name="sysmon, persistence,">

  <rule id="100300" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)schtasks\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <field name="win.eventdata.currentDirectory" type="pcre2">(?i)Temp|AppData|Public</field>
    <description>CRITICAL: Persistence Mechanism Created from Suspicious Directory (T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

</group>
```

#### After Audit

```xml
<group name="sysmon, persistence,">

  <rule id="100300" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)schtasks\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/tr\s+.*?(cmd\.exe|powershell\.exe|pwsh\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|\\Temp\\|\\AppData\\|\\Public\\|\\ProgramData\\)</field>
    <description>HIGH: Suspicious Scheduled Task Creation via LOLBin or Writable Directory (T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1053.005 After_Rule image](../Evidences/T1053.005%20After_Rule.png)

#### Before Audit

- **Precision**: The rule successfully triggered a **Level 12 Critical Alert** when the Atomic Red Team test executed and `schtask.exe` ran from the `Temp` directory.
- **False Positive Reduction**: Legitimate background tasks created by Windows Update (running from System32) are ignored.
- **Resilience**: The detection  holds true even if the attacker has escalated to `SYSTEM`, closing the gap left if it was just whitelisting users.

#### After Audit

- **Behavioral focus** - Shifted detection logic from the execution directory to inspecting the actual scheduled payload via the /TR flag.
- **Eliminates lab overfitting** - Ignores legitimate admin tasks by strictly targeting the scheduling of LOLBins (e.g., cmd.exe) or payloads in user-writable paths (e.g., \Temp\).
- **Severity validation** - Confirmed Level 12 (High Importance) to accurately prioritize critical post-compromise persistence without triggering top-tier exfiltration alarms.
