# [T1548](https://attack.mitre.org/techniques/T1548/)

This technique is used by adversaries to elevate their privileges in compromised machines/systems by abusing elevation control mechanisms. Modern system use these mechanisms to ensure only authorized users perform risky tasks, however adversaries exploit flaws or misconfiguration in mechanisms in this case "User Account Control (UAC)" to gain administrative access without credentials.

## [T1548.002](https://attack.mitre.org/techniques/T1548/002/): Bypass User Access Control

### 1. Scenario

This test simulates bypassing "User Access Control" by using `reg.exe` to modify the registry key `HKCU\Software\Classes\mscfile\shell\open\command`. The attacker sets this key to execute a malicious payload (in this case `cmd.exe`). When `eventvwr.msc` which runs with auto-elevated privileges is launched, it checks this specific registry key for instructions and executes the payload, effectively bypassing the UAC prompt.

### 2. Problem

![T1548.002 Before Rule image](../Evidences/T1548.002%20Before_Rule.png)

- **Misinterpretation** - Default Wazuh rules depict this incident as "Suspicious Base64 Pattern" (Rule 92041, Level 10), due to it having mixed characters. It caught the format but not the intent.
- **Misclassification** - When the registry `HKCU\Software\Classes\mscfile\shell\open\command` was modified Rule 92004 fired which flagged it as a suspicous Process relationship of low severity which is misclassification.

### 3. Solution

- **UAC Signature** - Engineered a rule that detects any changes made to the `HKCU\Software\Classes\mscfile\shell\open\command` registry as it is common clue of UAC bypass being performed. It is not edited in a normal use case scenario.
- **Process Relationship** - Devised another rule that fires when `eventvwr.msc` is started by `cmd.exe` as that is also a suspicious event but may be benign so not given that high of a severity.

### 4. Custom Rule

#### Before Audit

```xml
<group name="sysmon, privilege_escalation">

 <rule id="100600" level="15">
 <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)mscfile.*shell.*open.*command</field>

    <description>CRITICAL: UAC Bypass Attempt via Registry Key Modification</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
 </rule>

 <rule id="100601" level="10">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)cmd\.exe|powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\/c\seventvwr.msc</field>
    <description>MEDIUM: Suspicious Launch of UAC-Bypass Binary via Terminal</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
 </rule>
</group>
```

#### After Audit

```xml
<group name="sysmon, privilege_escalation">

  <rule id="100600" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)reg\.exe|powershell\.exe|pwsh\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)mscfile.*shell.*open.*command</field>
    <description>HIGH: UAC Bypass Registry Key Modification Setup (T1548.002)</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
  </rule>

  <rule id="100601" level="8">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)cmd\.exe|powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\/c\seventvwr\.msc</field>
    <description>WARNING: Suspicious Launch of eventvwr.msc via Terminal</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
  </rule>

  <rule id="100602" level="15" timeframe="120">
    <if_sid>100601</if_sid>
    <if_matched_sid>100600</if_matched_sid>
    <description>CRITICAL: Successful UAC Bypass Execution Confirmed (Registry + EventVwr Chained)</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

#### Before Audit

![T1548.002 After_Rule image](../Evidences/T1548.002%20After_Rule.png)

- Upon executing the attack, **Level 15** alerts are generated that highlight not only the severity of the event but also the intent.
- Adding these rules helped classify the alerts with their actual severity but also targets the "behavior" reducing the amount of "False Positives".

#### After Audit

![T1548.002 After Rule Audit Image](../Evidences/T1548.002%20After_Rule_AA.png)

- **Cross-binary scoping** - Added reg.exe, powershell.exe, and pwsh.exe to the registry modification rule to reduce noise while preventing blind spots from terminal-based evasion.
- **Attack chain correlation** - Restructured detection into a 3-tier composite logic, requiring the registry setup to immediately precede the eventvwr.msc execution within a 120-second timeframe.
- **Severity calibration** - Calibrated isolated setup and execution events to Level 12 and Level 8 to maintain visibility without alert fatigue, reserving the Level 15 (Critical) alert strictly for the confirmed UAC bypass chain.
