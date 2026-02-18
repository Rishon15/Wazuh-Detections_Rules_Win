# [T1592](https://attack.mitre.org/techniques/T1592/)

This technique is used by adversaries to gather information about the victim's host system, such as administrative data, assigned IP addresses, and configuration details like the operating system and language. This data can be gathered either by active scanning or phishing for information, and later used to tailor follow-up attacks.

## [T1592.001](https://attack.mitre.org/techniques/T1592/001/): Reconnaissance on Hardware Information via Windows Cmdlet

### 1. Scenario

This test simulates an attacker running a windows cmdlet to query `Win32_PnPEntity` to get information on "camera" or "image" devices that can be connected to host systems.

### 2. Problem

![T1592.001 Before Rule image](../Evidences/T1592.001%20Before_Rule.png)

- **Availability of Tests** - Currently due to the limited number of tests available on `Reconnaissance` only this test could be conducted which is not as severe as the other reconnaissance techniques.
- **Legitimate Cmdlet** - `Get-CimInstance` is a legitimate windows cmdlet used by administrators for system management, configuration and monitoring.

### 3. Solution

- **Contextual Detection** - Although `Get-CimInstance` is used by administrators for legitimate uses, they would never query for camera or image devices using `-Query` flag, as it can be checked via APIs or GUI interaction.
- **Test execution** - Even with the limited number of tests available, this test still shows the reconnaissance part of the MITRE ATT&CK framework.

### 4. Custom Rule

```xml
<group name="sysmon, recon">

  <rule id="100100" level="8">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)PowerShell.EXE</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(Get-CimInstance|Get-WmiObject|gwmi|gcim).*Win32_PnPEntity.*(Camera|Image)</field>
    <description>MEDIUM: Host Hardware Reconnaissance (Camera/Image Device Enumeration)</description>
    <mitre>
      <id>T1592.001</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1592.001 After Rule Image](../Evidences/T1592.001%20After_Rule.png)

- **Detection**: This rule will instantly flag the specific PowerShell command used in this test.
- **Context**: By setting it to Level 8, we acknowledge that it is suspicious but not an immediate emergency.
