# [T1490](https://attack.mitre.org/techniques/T1490/)

This technique is used by adversaries to delete or remove built-in data and services that help in recovery of corrupted systems. Common targets include backup files or recovery options.

### 1. Scenario

This test simulates an adversary running a command that deletes any shadow copy created by windows or a user thus inhibiting any recovery methods in case of ransomware attacks. When data is encrypted, any forms of backup of that file is destroyed requiring the victim to pay the ransom to have any possibility to retrieve the encrypted data. Adversaries use the windows binary `vssadmin.exe` that can create or delete shadow copies for files, in this case the adversary uses the delete function along with the `/quiet` argument, displaying no sign of deletion/prompt.

### 2. Problem

![T1490 Before_Rule image](../Evidences/T1490%20Before_Rule.png)

- **Severity Underestimation** - Default Wazuh rules classify this incident as "Suspicious Windows cmd Shell execution" which is a severity level 3 alert. This underestimates the damage which is caused by the command that deletes all backups in `C:`.
- **Execution Constraints** - During simulation `-GetPrereqs` was not able to meet the requirements of the test due to `vssadmin.exe` not having a `create` command available for windows 10 or 11 as it is there only in windows server versions.

### 3. Solution

- **Detection** - Custom rule that fires when `vssadmin.exe` runs with multiple suspicious indicators like `delete shadows` and the flag `/quiet`, making it a clear indication of a ransomware attack.
- **Zero-Trust** - Commands like this should be run from whitelisted directories to eliminate the possibility of the alert triggering when an admin runs the command, as they are aware of the whitelisted directories.
- **Prerequisites** - Investigation confirmed that, to create a shadow copy in windows 10/11 `wmic.exe` must be used, the whole command looks like this `wmic shadowcopy call create Volume='C:\'`.

### 4. Custom Rule

#### Before Audit

```xml
<group name="sysmon, impact">

  <rule id="101400" level="15">
    <if_group>sysmon_eid1_detections</if_group>
    
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)vssadmin\.exe</field>
    
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Delete.*Shadows</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/quiet|/qn</field>
    
    <field name="win.eventdata.currentDirectory" negate="yes" type="pcre2">(?i)C:\\Windows\\System32</field>
    
    <description>CRITICAL: Silent Shadow Copy Deletion from Non-Standard Directory</description>
    <mitre>
      <id>T1490</id>
    </mitre>
  </rule>

</group>
```

#### After Audit

```xml
<rule id="101400" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)vssadmin\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Delete.*Shadows</field>
    <description>HIGH: Volume Shadow Copy Deletion Detected (T1490)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
  </rule>

  <rule id="101401" level="15">
    <if_sid>101400</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/quiet|/qn</field>
    <description>CRITICAL: Silent Volume Shadow Copy Deletion - Ransomware Behavior Detected (T1490)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
  </rule>
```

### 5. Result

#### Before Audit

![T1490 After Rule image](../Evidences/T1490%20After_Rule.png)

- **Critical Alerting** - Upon execution of the attack from a non-standard directory, the system generated a Level 15 (Critical) alert, correctly identifying the behavior as "Ransomware Behavior" rather than generic command execution.
- **Noise Reduction** - The implementation of the Negation Logic successfully filtered out standard administrative noise. By allowing execution strictly from System32, we ensured that the SOC is only alerted when the behavior deviates from the established baseline, significantly reducing False Positives.

#### After Audit

![T1490 After Rule Audit](../Evidences/T1490%20After_Rule_AA.png)

- **Logic decoupling** - Separated the standard deletion command and the /quiet evasion flags into a parent-child rule structure to prevent noisy ransomware from bypassing the AND condition logic.
- **Evasion robustness** - Removed the directory restriction (negate="yes" for System32), recognizing that advanced malware and injected processes frequently execute from standard system paths.

- **Severity calibration** - Assigned Level 12 (High Importance) to the base deletion to account for potential administrative maintenance, while reserving Level 15 (Critical) exclusively for evasive, silent executions highly indicative of active ransomware.
