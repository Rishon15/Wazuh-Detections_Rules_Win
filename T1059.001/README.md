# [T1059](https://attack.mitre.org/techniques/T1059/)

This technique includes abuse of command & script interpreters, used by adversaries to execute commands, scripts or binaries. Most systems come with built-in command line interfaces and scripting capabilities which makes it easy for the attackers to take advantage of this capability to execute commands by obfuscating it to evade detection.

## [T1059.001](https://attack.mitre.org/techniques/T1059/001/): Execution of scripts via Data Obfuscation

### 1. Scenario

This test simulates an adversary abusing PowerShell commands and scripts for execution. Here the attacker uses the `-e` flag which is an abbreviation of `EncodedCommand` typically used for obfuscation of command for defense evasion.

### 2. Problem

![T1059.001 Before Rule image](../Evidences/T1059.001%20Before_Rule.png)

- **Evasion via Obfuscation** - Standard rules include targeting specific keywords like `iex` or `Invoke-WebRequest`, but in this test the adversary encodes it using `Base64` thus bypassing detection measures.
- **Context** - While detecting the `-EncodedCommand` flag is possible, legitimate system administrators may also use it.

### 3. Solution

- **Behavioral Targeting** - Instead of attempting to decode the payload or guess static strings, we targeted the obfuscation behavior itself: the use of the -EncodedCommand parameter followed by a Base64 string.

- **Hierarchical Correlation (Parent/Child Rules)**

  - A Parent Rule (Level 7) to log the presence of the encoded flag. Level 7 appropriately categorizes this as a "Bad word" match that warrants logging but not an immediate emergency.
  - A Child Rule (Level 14) that triggers only if the parent rule fires and the Base64 string exceeds 50 characters. Legitimate admin tasks rarely require massive blocks of encoded text, making a 50+ character string a high-fidelity indicator of an obfuscated dropper or attack framework.

### 4. Custom Rule

```xml
<group name="sysmon, execution">

  <rule id="100400" level="7">
    <if_group>sysmon_eid1_detections</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell.*\-(e|en|enc|encode|encodedcommand)\s+</field>
    <description>WARNING: PowerShell EncodedCommand flag detected (Keyword Match)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100401" level="14">
    <if_sid>100400</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\-(e|en|enc|encode|encodedcommand)\s+['"]?[A-Za-z0-9\+\/\=]{50,}</field>
    <description>HIGH: Suspiciously long Obfuscated PowerShell Payload (50+ Chars)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

### 5. Result

![T1059.001 After Rule Image](../Evidences/T1059.001%20After_Rule.png)

- **High-Fidelity Detection**: Rule 100401 successfully triggered a Level 14 alert, perfectly identifying the highly suspicious, long-form obfuscated payload.
- **Resilient Engineering**: The regex design accounts for multiple syntax variations (such as -e, -enc, quotes, and padding).
