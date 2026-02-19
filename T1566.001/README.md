# [T1566](https://attack.mitre.org/techniques/T1566/)

This technique involves adversaries sending phishing messages to gain access to victim systems. Phishing messages can include malicious attachments or links that execute malicious code, this helps the attacker gain the intial foothold on the victim systems.

# [T1566.001](https://attack.mitre.org/techniques/T1566/001/): Initial Access via Phishing

### 1. Scenario

This test simulates a user opening a malicious attachment (e.g., a Word document with a macro) that triggers a PowerShell "Download Cradle." The script attempts to download a second-stage payload (art.jse) from an external server and execute it in memory.

### 2. Problem

![T1566 Before Rule Image](../Evidences/T1566%20Before_Rule.png)

- **Low Severity Alert** - The default Wazuh rule triggered a generic 'Low Severity' alert, significantly underestimating the critical nature of a download cradle.
- **Context Failure** - Here the rule fired only due to `.ps1` file and the directory path which misses the context of payloads being downloaded from malicious external sources.

### 3. Solution

- **Targeting Behavior** - In this case payloads are being downloaded using `Invoke-WebRequest` and executed using `Invoke-Expression`, which is abnormal behavior that should raise alarms.
- **Critical Severity** - New alerts severity has been elevated to level 15 which is categorized as CRITICAL alert as this event is highly suspicious.
- **Multiple Rules** - We retained the default rule "92207" that successfully detected the payload artifact `art.jse` in the `public` folder, together with the newly created rule shows the whole context - *execution method* and *payload artifact*.

### 4. Custom Rule

```xml
<group name="sysmon, initial_access">

  <rule id="100300" level="15">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)PowerShell.EXE</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(iex|Invoke-Expression).*(iwr|curl|wget|Invoke-WebRequest|WebClient)</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(http://|https://)</field>
    <description>CRITICAL: PowerShell Downloading and Executing Remote Payload (Phishing/Dropper)</description>
    <mitre>
      <id>T1566.001</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1566.001 After Rule image](../Evidences/T1566.001%20After_rule.png)

- **Critical Detection**: The new rule successfully identified the malicious download cradle and triggered a Level 15 alert, prioritizing the incident for immediate response.
- **Comprehensive Coverage**: The attack generated two high-fidelity alerts: one for the download (Rule 101900) and one for the file drop (Rule 92207), providing a complete picture of the intrusion attempt.
