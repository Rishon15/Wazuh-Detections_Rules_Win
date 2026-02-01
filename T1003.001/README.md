# [T1003](https://attack.mitre.org/techniques/T1003/)
This technique is used by adversaries to dump credentials for account login or other credential materials like hashes/clear text.
 Obtained from OS caches or other memory structures, next course of action usually involves [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via the dumped credentials.
 
In this case we will be using sub-technique .001-7, which involves dumping of credentials using pypykatz which is a mimikatz implementation using python.
 Thus it can run on any OS and is not dependant on windows tools/utilities.

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
