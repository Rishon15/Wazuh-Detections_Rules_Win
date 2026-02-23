# T1016

It is the MITRE ATT&CK corresponding to **System Network Configuration Discovery**. Adversaries use this technique to discover network configuration settings such as IP and MAC addresses, of systems they have access to or to gather information about remote systems.

<br>

## T1016-1: Windows Network Discovery

### 1. Scenario

This test simulates **System Network Configuration Discovery** on Windows. It involves an attacker running standard Windows utilities like `ipconfig`, `arp`, `nbtstat` and `netsh`.


### 2. Problem
After executing this test via AtomicTest, logs are generated with level 3 alerts. These are classified as "Low" severity alerts, which underestimates the potential impact of the incident. Default rules of Wazuh only mark these as "suspicious processes", thus they require tuning to detect malicious intent.

 ![before_rule](../Evidences/T1016-1%20Before-Rule.png)

1. **Rule 93032** - triggers because cmd.exe ran a script.
2. **Rule 32036** - triggers because net.exe was started by cmd.exe.
3. **Rule 93031** - triggers because net.exe or net1.exe executing.

**Gap:** No alert is generated that can indicate the criticality of the event, as this could be an attacker trying to find other devices in the network for lateral movement or privilege escalation.


### 3. Solution
To detect the intent rather than just the tools, I implemented a custom rule -
- **Logic** - Targets behavior by detecting **command chaining**, as the specific parent processes can be bypassed.
- **Resilience** - Use of "sysmon_eid1_detections" group, included in the default rules files, thus this rule triggers on process creation rather than a specific parent process.
- **Regex Logic** - PCRE2 Regex to detect the use of two or more network discovery commands in a single command string.


### 4. Custom Rule

#### Before Audit

Regex rule to detect and have elevated alert level
```xml
<group name="windows,sysmon,">
  <rule id="100116" level="10">
    <if_group>sysmon_eid1_detections</if_group>
    <regex field="win.eventdata.commandLine|win.eventdata.parentCommandLine" type="pcre2">(?i)(ipconfig|netsh|arp|nbtstat|net\s+config).+&amp;.+(ipconfig|netsh|arp|nbtstat|net\s+config)</regex>
    <description>T1016: Multiple Chained Network Recon Commands Detected</description>
    <mitre>
      <id>T1016</id>
    </mitre>
  </rule>
</group>
```

This rule fires on the following conditions:
- When Event ID 1 is created, indicating a process creation.
- Any two commands listed in the regex group are executed sequentially using a chaining operator.

This behavior indicates that the attacker has gained access to the system and is actively enumerating the network environment.

#### After Audit

```xml
<group name="windows, sysmon, discovery,">
  
  <rule id="100900" level="8">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(.*(ipconfig|netsh|arp|nbtstat|net\s+config).*){2,}</field>
    <description>T1016: Multiple Chained Network Discovery Commands Detected</description>
    <mitre>
      <id>T1016</id>
    </mitre>
  </rule>
    
</group>
```

The initial rule triggered on every single execution of a network command, creating immense log noise from benign IT activity; to fix this, I refactored the logic to focus on keyword density.

### 5. Result

#### Before Audit

![After Rule](../Evidences/T1016-1%20After_Rule.png)

The result is that the low severity level alerts are replaced by level 10 alerts which have higher visibility in an actual SOC environment and are indicative of Discovery stage of an attack. The below attached log is indicative of it.

#### After Audit

![T1016 After Rule Audit image](../Evidences/T1016%20After_Rule_AA.png)

- **Filters out noise**: The new regex (...){2,} requires two or more commands in a single execution, successfully ignoring normal, single-use administrative tasks.
- **Increases accuracy**: Eliminates the "wall of red" caused by duplicate alerts firing on child processes.
- **Calibrates severity**: Downgraded to Level 8 (Medium-High) to reflect reconnaissance behavior, preventing SOC alert fatigue while maintaining visibility for threat hunting.
