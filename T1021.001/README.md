# T1021

It is the MITRE ATT&CK corresponding to [Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/). 
Adversaries use this to pivot/lateral move using compromised credentials to gain access. Other instances include gaining persistence in network as an authorized user in a domain.

<br>

## T1021.001: Remote Desktop Protocol/Service

### 1. Scenario
This test simulates a lateral movement attempt to a Domain Controller via **Remote Desktop Protocol** feature of Windows using compromised credentials. 
In the environment setup for this test the user executing the RDP to domain controller is not included in the Remote Desktop Users List, it affects the scenario.

### 2. Problem

![T1021.001-1 Before_Rule](../Evidences/T1021.001-1%20Before_Rule.png)

After the test is executed, two key observations are made:
1. **Access Denied** - as the simulated user (Victim_User) is not included in the lists of users with "Allow Logon Locally" permission on the Domain Controller, EventID 4625 is generated for Failed Logon. This then triggers the ruleid
60122 to fire due to EeventID 4625.
2. **NTLM** - On further inspection of conditions that trigger rule id 92657, we find that this rule triggers when NTLM is used to authenticate to a service or device. In this case the user uses compromised credentials together with the IP address instead of the domain name to authenticate.
This downgrades the suthentication method to NTLM which is successful triggering the EventID 4624 for Successful Logon.

**Gap**:
- **Rule 60122 (Logon Failure)** - Detected the final block but failed to capture the method of authentication (NTLM).
- **Rule 92657 (NTLM Success)** - Correctly identified the method of authentication (NTLM). However, using this rule can lead to noisy alerts as valid share services, file shares and printers use NTLM authentication.

### 3. Solution
To create an alert I would have to confirm the use of NTLM authentication while also filtering out background noise.  
I rejected relying on the "Logon Failure" (Rule 60122) because in this case it occurs due to misconfiguration, I focused on **Protocol Downgrade** as the primary **Indicator of Compromise** (IoC).

**Strategy**: I developed a rule based on Rule ID 92657 with strict filters -
- **Filter 1**: Inspect field name `lmPackageName` to confirm NTLM usage.
- **Filter 2**: Restricting the alert to **Privileged Accounts**. This ignores standard users accessing file shares or authenticating via NTLM, authenticating to a privileged user via NTLM is highly suspicious.
- **Filter 3**:  Target Network (Type 3) and Remote Interactive (Type 10) logons to focus on external connections.

### 4. Custom Rule
I implemented the following rule by adding it to `local_rules.xml`:
```xml
<group name="windows, lateral_movement,">
  <rule id="100055" level="10">
    <if_sid>92657, 60106</if_sid>
    <field name="win.eventdata.lmPackageName" type="pcre2">(?i)NTLM</field>
    <field name="win.eventdata.logonType">^3$|^10$</field>
    <field name="win.eventdata.targetUserName">^Administrator$|^Victim_User$</field>
    <description>Suspicious NTLM Authentication to Privileged User (Potential Pass-the-Hash or RDP via IP)</description>
    <mitre>
      <id>T1021.001</id> <id>T1550.002</id> </mitre>
  </rule>
</group>
```

### 5. Result
Upon re-executing the attack:

![T1021.001-1 After_Rule](../Evidences/T1021.001-1%20After_Rule.png)

1. **Detection**: Custom rule (Rule 100055) fires immediatly upon NTLM authentication.
2. **Accuracy**: The alert correctly identifies the source IP, the compromised user (Victim_User) and the use of weak NTLM protocol.
3. **Noise Reduction**: Background traffic from valid services (here DWM-2 and UMFD-2) was successfully ignored.


