# T1016- Network and System configuration discovery

It is the MITRE ATT&CK corresponding to **System Network Configuration Discovery**. Used by adversaries to find about network configuration settings like IP and MAC addresses of systems they have access to or via information discovery of remote systems.
<br>
<br>

## T1016-1

### 1. Scenario
This Mitre-id involves System Network Configuration discovery on windows. it simulates an attacker running Network Reconnaissance using windows tools like "ipconfig", "arp", "nbtstat" and "netsh".
<br>
<br>

### 2. Problem
After executing this test via AtomicTest, logs are generated with level 3 alerts. These are classified as low level alerts, which are an understatement to the severity of the incident which occurred. Default rules of Wazuh only mark these as suspicious processes run, thus they require tuning to more specific needs.
1. **Rule 93032** - triggers due to cmd.exe running a script.
2. **Rule 32036** - triggers as net.exe was started by cmd.exe.
3. **Rule 93031** - triggered due to net or net1.exe running.

Gap - No alert is generated that can indicate the criticality of the event, as this could be an attacker trying to find other devices in the network for lateral movement or privilege escalation.
<br>
<br>

### 3. Solution
To detect the intent rather than just the tools, I wrote a custom rule
- **Logic** - To detect the behavior by targeting chaining commands being executed, as the specific parent processes can be bypassed.
- **Resilience** - Used the "sysmon_eid1_detections" group included in the default rules files, thus this rule triggers on process creation rather than a specific parent process.
- **Regex Logic** - PCRE2 Regex to detect the use of two or more network discovery commands in a single execution string.
<br>

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
<br>

### 4. Result
The result is that the low criticality level alerts are replaced by level 10 alerts which have higher visibility in an actual SOC environment and are indicative of Reconnaissance stage of an attack. The below attached log is indicative of it.
