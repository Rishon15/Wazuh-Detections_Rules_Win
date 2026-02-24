# [T1041](https://attack.mitre.org/techniques/T1041/)

This technique involves exfiltration of data over a Command and Control (C2) channel. Adversaries use standard protocols like HTTP(S) to blend in with normal traffic.

### 1. Scenario

This test simulates an Adversary using native Powershell cmdlet `Invoke-WebRequest` to upload stolen data to an external server. This is a "Living off the Land" technique, as `Invoke-WebRequest` is a standard administrative tool present on all windows systems.

### 2. Problem

![T1041 Before Rule image](../Evidences/T1041%20Before_Rule.png)

- **Context Misinterpretation** - Default Wazuh rule only flags this with 92027 Rule id that fires only when `powershell.exe` instance is launched by `powershell.exe`. Which doesn't categorize this incident properly.
- **Test Execution** - When this test is executed, it fails due to `example.com` not accepting `POST` requests, but in this case the attempt matters not its result.

### 3. Solution

- **Behavioral Targeting** - Creating a rule that detects the intent as admins use `Invoke-WebRequest` binary to download files but rarely use it to `POST` or upload data.
- **Keyword Detection** - The rule targets specific flags like `POST`, `PUT` or `-BODY` while ignoring request like `GET`.

### 4. Custom Rule

#### Before Audit

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

#### After Audit

```xml
<group name="sysmon, exfiltration">
  <rule id="101300" level="13">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Invoke-WebRequest|iwr|curl|wget</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-Method POST|-Method PUT|-InFile|-Body|-X POST|-X PUT|-d\s+|--data|-F\s+|--form|-T\s+|--upload-file</field>
    <description>HIGH: Command-Line Data Exfiltration Detected (T1041)</description>
    <mitre>
      <id>T1041</id>
    </mitre>
  </rule>
</group><group name="sysmon, exfiltration">
  <rule id="101300" level="13">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Invoke-WebRequest|iwr|curl|wget</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-Method POST|-Method PUT|-InFile|-Body|-X POST|-X PUT|-d\s+|--data|-F\s+|--form|-T\s+|--upload-file</field>
    <description>HIGH: Command-Line Data Exfiltration Detected (T1041)</description>
    <mitre>
      <id>T1041</id>
    </mitre>
  </rule>
</group>
```

### 5. Result

![T1041 After Rule image](../Evidences/T1041%20After_Rule.png)

#### Before Audit

- **Precise Detection**: The new rule successfully ignored the "Process Tree" noise and focuses on the command arguments.
- **Resilience**: Unlike the default rules, this detection logic works regardless of whether the command is run via a script, a batch file, or manually by a hands-on-keyboard attacker, closing the detection gap for "Living off the Land" exfiltration.

#### After Audit

- **Evasion prevention** - Expanded regex to include native curl.exe parameters (-X, --data, -F) to catch attackers bypassing PowerShell aliases.
- **Severity validation** - Confirmed Level 13 severity to appropriately flag the critical, late-stage impact of data exfiltration.
