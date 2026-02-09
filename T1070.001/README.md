# [T1071](https://attack.mitre.org/techniques/T1070/)

This technique is used by adversaries to delete or modify artifacts generated within system to remove evidences, hide presence or hinder defense. 
Involves removal of indicators like strings in downloaded files, logs generated from various actions and other actions that can be used as analytics by defenders

## [T1070.001](https://attack.mitre.org/techniques/T1070/001/): Defense evasion via clearing Windows Event Logs

### 1. Scenario

This test simulates an adversary clearing previously generated logs or any other Indicator of Compromise (IoC), mostly used as an **anti-forensic** measure. In this case `wevtutil.exe` is used to wipe the "system" event logs, `wevtutil.exe` is a legitimate Windows binary to query event logs.

### 2. Problem 

![T1070.001 Before_Rule image](../Evidences/T1070.001%20Before_Rule.png)

- **Severity Mismatch**: The default Wazuh rule (ID 63104) detects the log clearing event (Event ID 104) but classifies it as Level 5 (Medium Severity). In a real incident, wiping logs is an event that requires immediate critical attention.
- **Context Gap**: Default Rule ID 63104 alert only informs about the logs being wiped out, but it often lacks crucial context like the User who did it or the Command Line arguments used.
- **Reactive vs Proactive**: Waiting for Event ID 104 means alerting only after the evidence is destroyed.

### 3. Solution

1. **Log Analysis**: Analysis of process creation logs (Event ID 1) during the attack as it clearly showed `wevtutil.exe` being run with the cl (Clear Log) argument.
2. **Targeting the Argument**: Instead of relying on the Event ID 104, I wrote a rule to detect the specific execution of the wevtutil binary combined with the cl argument.
3. **Benefit**: This provides full forensic context (Parent Process, User, Terminal Session) and allows for a higher severity classification than the default Wazuh alert.

### 4. Custom Rule

```xml
<group name="sysmon, defense_evasion,">

  <rule id="100400" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)wevtutil\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\scl\s</field>
    
    <description>CRITICAL: Windows Log Clearing Command Executed (wevtutil cl)</description>
    <mitre>
      <id>T1070.001</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1070.001 After_Rule image](../Evidences/T1070.001%20After_Rule.png)

- **High Fidelity**: The rule successfully triggered a Level 12 Critical Alert specifically on the wevtutil cl command.
- **Context**: Unlike the default alert (Rule 63104) that indicates that logs were cleared, this new alert captures the full command line, confirming exactly which log was targeted ("System") and how it was executed.
