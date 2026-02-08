# [T1053](https://attack.mitre.org/techniques/T1053/)

This technique is used by adversaries to achieve persistence overa system remotely, this is done by abusing "Task Scheduling" functionality. Task scheduling is a method of executing a specific task or script at a specific date and time.
 Requires intial foothold on a system as a member of an admin or otherwise privileged group on the remote system.

## [T1053.005](https://attack.mitre.org/techniques/T1053/005/): Persistence via Scheduled Tasks

### 1. Scenario

This test simulates how adversaries can abuse the "Windows Task Scheduler" to perform task scheduling for initial or recurring execution of malicious code. 
In this case [schtask](https://attack.mitre.org/software/S0111) utility is run directly on the command from "temp" directory.

### 2. Problem



