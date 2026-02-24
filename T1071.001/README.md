# [T1071](https://attack.mitre.org/techniques/T1071/)

This technique is used by adversaries to issue commands to a system remotely by using OSI application layer protocols to avoid detection. This helps blending in malicious commands into existing traffic. 
Adversaries utilize different protocols including those used for web browsing, transferring files, electronic mail and DNS.

## [T1071.001](https://attack.mitre.org/techniques/T1071/001/): Command & Control via Web Protocols

### 1. Scenario

This test simulates traffic to a C2 domain and disguising the traffic as normal web traffic with the use of "User-Agent" strings ("Opera/8.81"). 
The result of the commands will be embedded within the protocol traffic between client & server.

### 2. Problem

![T1071.001 Before Rule Image](../Evidences/T1071.001%20Before_Rule.png)

- **Stealth**: The attack uses standard HTTP traffic (Port 80/443), which bypasses most firewall blocklists.
- **Signatures**: Standard rules may look for specific "bad"" strings, can be bypasssed easily by changing user agents.
- **False Positives** - Initial attempt resulted on correlating "file drops" with "Network Traffic". However, further investigation revealed Windows drops temporary artifacts (`PSScriptPolicyTest_*.ps1`) in the same temp folders used by malware.

### 3. Solution

1. **Detection (Network)**: Instead of blacklisting specific strings, I wrote a rule detecting the method of masquerading—specifically, the manual usage of the -A (User-Agent) flag in curl, which is rare for legitimate automated tasks.
2. **False Positive Suppression**: Included a "Filter Rule" to explicitly ignore known benign Windows artifacts (`PSScriptPolicyTest`).
3. **Correlation Strategy**: I designed a rule that links "File Drops" with "C2 traffic".

### 4. Custom Rules
```xml
<group name="sysmon,correlation,">
  <rule id="100011" level="10">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)curl\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-A\s|\s--user-agent\s</field>
    <description>Suspicious Curl Execution with Spoofed User-Agent (Potential C2)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>
</group>
```

#### After Audit

```xml
<group name="sysmon, C2">

  <rule id="101200" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)curl\.exe|powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-A\s|\s-useragent\s</field>
    <description>Suspicious Curl Execution with Spoofed User-Agent (Potential C2)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

</group>

```

### 5. Result

#### Before Audit

![T1071.001 After Rule Image](../Evidences/T1071.001%20After_Rule.png)

- **Detections**: Rule 100011 successfully detected the spoofed User-Agent immediatly, regardless of whether the attacker pretended to be "Opera" or "Chrome".
- **Noise Reductions**: The filter rule (100050) successfully suppressed alerts for the `PSScriptPolicyTest` file, preventing false alarms.
- **Correlation Logic**: It triggers a Critical (Level 14) Alert only when a true unknown binary is dropped and immediatly attempts communicate outbound.

#### After Audit

![T1071.001 After Rule Audit Image](../Evidences/T1071.001%20After_Rule_AA.png)

- **Rule optimization** - Stripped out legacy file-drop correlation rules that were irrelevant to this specific network-based C2 test, keeping the rule base strictly focused on execution behavior.
- **Cross-binary detection** - Expanded the target binaries to include powershell.exe, and added the -UserAgent regex flag to catch adversaries using Invoke-WebRequest alongside native curl.exe.
- **Severity calibration**: Elevated the alert to Level 12 (High Importance). Deliberate User-Agent spoofing eliminates the possibility of benign user error and strongly indicates active Command and Control (C2) firewall evasion.
