# [T1041](https://attack.mitre.org/techniques/T1041/)

This technique involves exfiltration of data over a Command and Control (C2) channel. Adversaries use standard protocols like HTTP(S) to blend in with normal traffic.

### 1. Scenario

This test simulates an Adversary using native Powershell cmdlet `Invoke-WebRequest` to upload stolen data to an external server. This is a "Living off the Land" technique, as `Invoke-WebRequest` is a standard administrative tool present on all windows systems.

### 2. Problem

![T1041 Before Rule image](../Evidences/T1041%20BEfore_Rule.png)

- **Context Misinterpretation** - Default Wazuh rule only flags this with 92027 Rule id that fires only when `powershell.exe` instance is launched by `powershell.exe`. Which doesn't categorize this incident properly.
- **Test Execution** - When this test is executed, it fails due to `example.com` not accepting `POST` requests, but in this case the attempt matters not its result.

### 3. Solution

- **Behavioral Targeting** - Creating a rule that detects the intent as admins use `Invoke-WebRequest` binary to download files but rarely use it to `POST` or upload data.
- **Keyword Detection** - The rule targets specific flags like `POST`, `PUT` or `-BODY` while ignoring request like `GET`.

### 4. Custom Rule
```xml
<group name="sysmon, exfiltration">

  <rule id="101300" level="13">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Invoke-WebRequest|iwr|curl|wget</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-Method POST|-Method PUT|-InFile|-Body</field>
    <description>HIGH: PowerShell Exfiltrating Data via Method POST</description>
    <mitre>
      <id>T1041</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1041 After Rule image](../Evidences/T1041%20After_Rule.png)

- **Precise Detection**: The new rule successfully ignored the "Process Tree" noise and focuses on the command arguments.
- **Resilience**: Unlike the default rules, this detection logic works regardless of whether the command is run via a script, a batch file, or manually by a hands-on-keyboard attacker, closing the detection gap for "Living off the Land" exfiltration.
