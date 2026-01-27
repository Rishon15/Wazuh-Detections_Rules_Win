# T1021

It is the MITRE ATT&CK corresponding to [Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/). 
Adversaries use this to pivot/lateral move using compromised credentials to gain access. Other instances include gaining persistence in network as an authorized user in a domain.

## T1021.001: Remote Desktop Protocol/Service

### 1. Scenario
This test simulates a lateral movement attempt to a Domain Controller via **Remote Desktop Protocol** feature of Windows using compromised credentials. 
In the environment setup for this test the user executing the RDP to domain controller is not included in the Remote Desktop Users List, it affects the scenario.

### 2. Problem
After the test is executed, two key observations are made:
1. **Access Denied** - as the simulated user (Victim_User) is not included in the lists of users with "Allow Logon Locally" permission on the Domain Controller, EventID 4625 is generated for Failed Logon. This then triggers the ruleid
60122 to fire due to EeventID 4625.
2. **NTLM** - On further inspection of conditions that trigger rule id 92657, we find that this rule triggers when NTLM is used to authenticate to a service or device. In this case the user uses compromised credentials together with the IP address instead of the domain name to authenticate.
This downgrades the suthentication method to NTLM which is successful triggering the EventID 4624 for Successful Logon.

**Gap**:
- **Rule 60122 (Logon Failure)** - Detected the final block but failed to capture the method of authentication (NTLM).
- **Rule 92657 (NTLM Success)** - Correctly identified the method of authentication (NTLM). However, using this rule can lead to noisy alerts as valid share services, file shares and printers use NTLM authentication.

-  
