# [T1003](https://attack.mitre.org/techniques/T1003/)
This technique is used by adversaries to dump credentials for account login or other credential materials like hashes/clear text.
 Obtained from OS caches or other memory structures, next course of action usually involves [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via the dumped credentials.
 
In this case we will be using sub-technique .001-7, which involves dumping of credentials using pypykatz which is a mimikatz implementation using python, allowing it to run on any OS and is not dependant on windows tools/utilities.

<br>

## [T1003.001](https://attack.mitre.org/techniques/T1003/001): Credential Dumping

### 1. Scenario
This test simulates a credential access/dump via a tool called pypykatz, which is an open source tool to dump memory of **Local Security Authority Subsystem Service** (lsass.exe). Goal is to
 extract plaintext passwords and NTLM hashes for privilege escalation or lateral movement.

### 2. Problem

![T1003.001-7 Before rule logs](../Evidences/T1003.001-7%20Before_Rule.png)

1. **Alert Severity** - After successfully executing the credential dump using `pypykatz`, I observed that the SIEM only generated **Level 3 Alerts** for "Suspicious cmd shell execution". This only detects the execution of the tool but heavily
miscategorizes  the severity of the attack.

2. **Missing Telemetry** - Upon inspecting the logs, I noticed a complete absence of **Sysmon EventID 10 (Process Access)** for `lsass.exe`.
   - **Investigation**: I analyzed the raw Event Viewer logs on the endpoint and confirmed that no memory access events were generated.
   - **Root cause**: Reviewing the `sysmonconfig.xml` (based on the SwiftOnSecurity standard) revealed that the **Process Access** block used `onmatch="include"` but contained no active rules. This disabled logging for all process access to reduce noise.

3. **SIEM Ingestion Failure** - Even after fixing the sysmon configuration to generate the raw logs (solution below), the Wazuh Dashboard still failed to trigger an alert.
   - **Investigation**: I verified the raw EVENT ID 10 logs were now appearing in the Windows Event Viewer, showing `python.exe` (SourceImage) accessing `lsass.exe` (TargetImage).
   - **Root Cause**: Wazuh's default ruleset lacked specific logic to correlate a language binary (`python.exe`) accessing Local Security Authority process. It treated the event as generic information rather than a high severity alert.

### 3. Solution
1. **Enabling Telemetry** - To enable the EVENT ID logs to trigger I modified the sysmon configuration (`sysmonconfig.xml`). I added an inclusion rule to the `ProcessAccess` section to explicitly log any attempts to access the `lsass.exe` process.

```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    </ProcessAccess>
</RuleGroup>
```
2. **Tuning the noise** - Once monitoring was enabled, I observed that legitimate processes like `MsMpEng.exe` (Windows Defender) and `svchost.exe` accessed `lsass.exe` when this attack was performed thus creating log noise. So to tune out the noise, Wazuh rule will be the filter rather than filtering directly at the endpoint as it enables a broader approach.

### 4. Custom Rule
TO convert raw data ro hogh-fidelity alert, I engineered a custom Wazuh rule. I bypassed the standard rule dependancy chain by directly using the `sysmon_event_10` group. This rule specifically targets the behavior of non-system binaries (like Python) accessing `lsaaa.exe`.
```xml
<rule id="100010" level="10">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.sourceImage" type="pcre2">(?i)python\.exe|pypykatz</field>
    <description>CRITICAL: Python Script Accessed LSASS Memory (Credential Dumping)</description>
    <mitre>
        <id>T1003.001</id>
    </mitre>
</rule>
```

### 5. Result

![T1003.001-7 After_Rule](../Evidences/T1003.001-7%20After_Rule.png)

1. **Detection**: Custom Rule (Rule 10010) fires immediatly upon `lsass.exe` being accessed by `python.exe`.
2. **Accuracy**: The alert only activates when `python.exe` accesses `lsass.exe` and tunes out noise of `MsMpEng.exe` and `svchost.exe` accessing `lsass.exe`.


