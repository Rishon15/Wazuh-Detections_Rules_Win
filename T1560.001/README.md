# [T1560](https://attack.mitre.org/techniques/T1560/)

This technique is used by adversaries to compress and/or encrypt data that is collected before it is exfiltrated. Helps in obfuscating collected data and minimizes the chance of being detected when transferring data outside of network. Compression can be done using built-in utilities, 3rd party libraries or custom methods.

## [T1560.001](https://attack.mitre.org/techniques/T1560/001/): Archive data using Windows binary

### 1. Scenario

This test simulates the use of `makecab.exe` which is a Windows Utility used to compress files into files into Cabinet (.cab) format. Its to reduce its probability of getting detected when being exfiltrated by reducing file size.

### 2. Problem

![T1560.001 Before Rule image](../Evidences/T1560.001%20Before_Rule.png)

- **Misclassification** - Default detection logic only classifies this as "Suspicious Parent Process" (Rule 92032) with low severity level.
- **Test Execution** - THe default path for the test included path that resulted in masss execution of files which generated large number of logs.
- **Constraints** - Making a rule that detects only the execution of `makecab.exe` will result in noisy alerts due to it being a trusted Windows binary, often referred to as "Living of the Land" meaning adversaries can abuse this trusted Windows utility for thier own use.

### 3. Solution

- **Dual Layer Detection** - "Target-based Detection" by triggering an alert if sensitive directories are mentioned in the execution of `makecab.exe` along with "Location-based Detection" meaning if the command is executed from a suspicious directory then it should fire.
- **Refined Emulation** - `Invoke-AtomicTest` command should be used along with `PromptForInputArgs` to use custom directory locations to reduce the amount of logs generated and focus on the "intent" than the "scope".

### 4. Custom Rule

```xml
<group name="sysmon, collection">

  <rule id="101500" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)makecab\.exe</field>
    
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Users|Documents|Desktop|AppData|Temp|Public|ProgramData</field>
    
    <description>HIGH: Data Staging via Makecab (Suspicious Target Path)</description>
    <mitre>
      <id>T1560.001</id>
    </mitre>
  </rule>

  <rule id="101501" level="12">
    <if_group>sysmon_eid1_detections</if_group>
    
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)makecab\.exe</field>
    
    <field name="win.eventdata.currentDirectory" type="pcre2">(?i)Temp|ProgramData|AppData|Public</field>
    
    <description>HIGH: Data Staging via Makecab (Suspicious Execution Directory)</description>
    <mitre>
      <id>T1560.001</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1560.001 After Rule image](../Evidences/T1560.001%20After_Rule.png)

- **Scenario A** - Rule 101500 fires based on the CommandLine targeting the Sensitive folder/data.
- **Scenario B** - Rule 101501 fired based on the CurrentDirectory from which the attack was executed.
