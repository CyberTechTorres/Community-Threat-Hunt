#  Threat Hunt Report: Azuki Import/Export

Analyst: Andres Torres Richardson

Date Completed: 2025-10-25

Environment Investigated: AZUKI-SL (IT admin workstation)

Timeframe: November, 2025

## Executive Summary

In the month of Novermber 2025 , Azuki Import/Export Trading Co has been targetted by a financially motivated threat actor targeting import/export companies. The adversary leveraged (enter kill chain here) and anti-forensics measures to achieve their objectives. Each flag represents a key stage of the attack chain, culminating in attempts to cover tracks and exit the environment undetected.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-11-18T22:44:11Z** | Flag 1   | Initial Remote Access via RDP                | Inbound Remote IP 88.97.178.12                          |
| **2025-11-18T22:44:11Z** | Flag 2   | Compromised User Account                     | `kenji.sato`                                            |
| **2025-11-19T01:04:05Z** | Flag 3   | Enumerating network topology                 | `ARP.EXE -a` Command Executed                           |
| **2025-11-19T18:37:40Z** | Flag 18  | Malicious Script Method                      | `wupdate.ps1` Downloaded Externally for Execution       |
| **2025-11-19T18:49:27Z** | Flag 6   | Folder Excluded for Evasion                  | `C:\Users\KENJI~1.SAT\AppData\Local\Temp`               |
| **2025-11-19T18:49:29Z** | Flag 5   | File Extension Excluding for Evasion         | RegistryValueName's `.bat, .ps1, .exe` Excluded         |
| **2025-11-19T19:05:33Z** | Flag 4   | Malware Staging Directory Created            | `C:\ProgramData\WindowsCache`                           |
| **2025-11-19T19:07:21Z** | Flag 7   | Download Binary Abuse                        | `certutil.exe` for Fetching Downloads                   |
| **2025-11-19T19:07:22Z** | Flag 12  | Credential Dumping Tool Usage                | `mm.exe`                                                |
| **2025-11-19T19:07:46Z** | Flag 8   | Persistence As Scheduled Task                | schtask.exe /create /tn `Windows Update Check`          |
| **2025-11-19T19:07:46Z** | Flag 9   | Scheduled Task Folder Path Creation          | `C:\ProgramData\WindowsCache\svchost.exe`               |
| **2025-11-19T19:08:26Z** | Flag 13  | Type of Memory Extraction Module             | Mimikatz sekurlsa logonpasswords module                 |
| **2025-11-19T19:08:58Z** | Flag 14  | Data Staging Archive `export-data.zip`       | Compressed Company Data                                 |
| **2025-11-19T19:09:21Z** | Flag 15  | File Upload to Cloud Services                | 443 port connectivity to `discord.com`                  |
| **2025-11-19T19:09:48Z** | Flag 17  | Creation Of Hidden Account                   | Account With Elevated Rights called `support`           |
| **2025-11-19T19:10:37Z** | Flag 19  | Targeted IP for Lateral Movement             | `cmdkey.exe" /list` followed by `cmdkey.exe /generic:10.1.0.188 /user:fileadmin /pass:**********` |
| **2025-11-19T19:10:41Z** | Flag 20  | Tool for Lateral Movement                    | `mstsc.exe /V:` Used for RDP Connectivity to 10.1.0.188 |
| **2025-11-19T19:11:04Z** | Flag 10  | Connection to C2 Server                      | Remote IP `78.141.196.6`                                |
| **2025-11-19T19:11:04Z** | Flag 11  | Port Connectivity to C2 Server               | HTTPS / 443                                             |
| **2025-11-19T19:11:39Z** | Flag 16  | Log clearing via `wevtutil`                  | Cleared Security, System, and App logs by `cl` command  |



---
### Starting Point – Identifying the Initial System

**Objective:**
Determine where initial access was obtained to validate the incident timeline. 


Considering intelligence related to the “JADE SPIDER” threat actor, the typical dwell time ranges from approximately 21 to 45 days, with the most recent observed activity reported in November. <br/>
Based on this, the investigation window was set from 45 days prior through the current date range of interest, specifically 2025-10-09T00:00:00.0000000Z to 2025-11-22T23:00:00.0000000<br/>
Endpoint Device in question that has been compromised is "azuki-sl".<br/>
I will filter for interactive Logontype which can indicate a public remote IP.<br/>

**Host of Interest (Starting Point):** `azuki-sl`  
**Why:** Admin Account with desired data useful for adversary.
**KQL Query Used:**
```
DeviceLogonEvents
| where AccountDomain contains "azuki-sl"
| where TimeGenerated between (datetime(2025-10-09T00:00:00.0000000Z) .. datetime(2025-11-22T23:00:00.0000000Z))
| where DeviceName contains "azuki-sl"
| where LogonType contains "Interactive"
| where isnotempty(RemoteIP)
| sort by TimeGenerated desc
```

<img width="1151" height="359" alt="1st" src="https://github.com/user-attachments/assets/3169d930-d582-4941-b071-b28bcc6701e7" />
The user account kenji.sato on device azuki-sl shows remote access activity from IP address 159.26.106.98.<br/> 
Let’s query specifically for the earliest instance where this account established a remote session from any external source.<br/> 
After all it's the AccountNames (not necessarily the domain) that are compromised first which is the initial source of malicious actions.<br/> 

**KQL Query Used:**
```
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-10-09T00:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where AccountName contains "kenji.sato"
| where LogonType contains "Interactive"
| where isnotempty(RemoteIP)
| where RemoteIPType contains "Public"
| sort by TimeGenerated desc

```
<img width="1128" height="495" alt="2nd" src="https://github.com/user-attachments/assets/478978cf-38f4-43dd-b732-af0d1f581318" />

Logs show a TimeGenerated frame between 11/18/2025 and 11/22/2025<br/>
(2025-11-18T22:44:11.6770861Z - 2025-11-22T00:27:58.4166424Z)
This will now be the new timeframe to query moving forward.<br/>

Here I see all the different Devices the user kenji.sato has accessed. "azuki-sl", "azuki-kslog", "azuki-logks", "azuki-wks01", "azuki-logistics"<br/>
First log that shows signs of a suspicious RemoteIP accessing this account via RDP due to its LogonType being "RemoteInteractive" is 88.97.178.12 with Timestamp of 2025-11-18T22:44:11.6770861Z


---

## Flag-by-Flag Findings

---

🚩 **Flag 1 – INITIAL ACCESS - Remote Access Source**  
🎯 **Objective:** Determine initial access from any external connections.  
📌 **Finding (answer):** **88.97.178.12**  
🔍 **Evidence:**
- **Host:** "azuki-logistics"  
- **Timestamp:** 2025-11-18T22:44:11.6770861Z  
- **Process:** Interactive external RDP connection<br/>
💡 **Why it matters:** Origin helps with threat actor attribution and can block ongoing attacks.<br/>

**KQL Query Used:**
```
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-10-09T00:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where AccountName contains "kenji.sato"
| where LogonType contains "Interactive"
| where isnotempty(RemoteIP)
| where RemoteIPType contains "Public"
| sort by TimeGenerated desc

```
<img width="1128" height="495" alt="2nd" src="https://github.com/user-attachments/assets/b39d6820-8a7c-455c-ae73-eb4a4909cdc6" />



---

🚩 **Flag 2 – INITIAL ACCESS - Compromised User Account**  
🎯 **Objective:** Which account credentials were compromised? 
📌 **Finding (answer):** `kenji.sato`  
🔍 **Evidence:**  
- **Host:** "azuki-logistics" 
- **Timestamp:** 2025-11-18T22:44:11.6770861Z<br/>
💡 **Why it matters:** Reveals which account within the Domain has been the victim to brute-force or a phishing attack.<br/>

**KQL Query Used:**
```
DeviceLogonEvents
| where AccountDomain contains "azuki-sl"
| where TimeGenerated between (datetime(2025-10-09T00:00:00.0000000Z) .. datetime(2025-11-22T23:00:00.0000000Z))
| where DeviceName contains "azuki-sl"
| where LogonType contains "Interactive"
| where isnotempty(RemoteIP)
| sort by TimeGenerated desc

```

---

🚩 **Flag 3 – DISCOVERY - Network Reconnaissance**  
🎯 **Objective:** Identify any signs of enumerating network topology.  
📌 **Finding (answer):** `"ARP.EXE" -a`  
🔍 **Evidence:**  
- **Host:** "azuki-logistics"  
- **Timestamp:** 2025-11-19T01:04:05.73442Z 
- **Process:** powershell.exe  
- **CommandLine:** `"ARP.EXE" -a`<br/>
💡 **Why it matters:**  Identifies intention for lateral movement opportunities and high-value targets.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where AccountName contains "kenji.sato"
| where InitiatingProcessCommandLine has_any ("powershell", "cmd")
| sort by TimeGenerated desc
| project TimeGenerated, AccountDomain, AccountName, ActionType, ProcessCommandLine

```

<img width="1202" height="613" alt="3rd" src="https://github.com/user-attachments/assets/4581cd3b-45a5-4a4c-ac1c-c1f22fc27a79" />



---

🚩 **Flag 4 – DEFENCE EVASION - Malware Staging Directory**  
🎯 **Objective:**  Identify the primary malware directory. 
📌 **Finding (answer):** `C:\ProgramData\WindowsCache`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamp:** 2025-11-19T19:05:33.7665036Z 
- **Process:** `"attrib.exe" +h +s C:\ProgramData\WindowsCache`<br/>
💡 **Why it matters:** It reveal's the scope of compromise and helps locate additional malicious artefacts.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl", "azuki-kslog", "azuki-logks", "azuki-wks01", "azuki-logistics")
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_any ("+h", "+s")
| project Timestamp, AccountDomain, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine, ProcessRemoteSessionIP, ProcessRemoteSessionDeviceName
| sort by Timestamp desc

```
<img width="1138" height="659" alt="Flag4" src="https://github.com/user-attachments/assets/41ee5c2b-9836-46bb-bf45-5ce9596885d0" />


---

🚩 **Flag 5 – Defender Configuration Recon**  
🎯 **Objective:** Expose tampering or inspection of AV defenses, disguised under HR activity.  
📌 **Finding (answer):** `"powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring $true"`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamps:** 2025-07-18T14:58:41Z and 2025-07-18T15:00:06Z  
- **Process:** powershell.exe  
- **CommandLine:** `Set-MpPreference -DisableRealtimeMonitoring $true`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Disables Defender’s real‑time protection to permit payload staging/credential theft with reduced detection.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "RealTimeMonitoring"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="797" height="613" alt="Screenshot 2025-08-17 220314" src="https://github.com/user-attachments/assets/5aafbc90-ff20-4695-bc12-d6e5ae757ab4" />

---

🚩 **Flag 6 – Defender Policy Modification**  
🎯 **Objective:** Validate if core system protection settings were modified.  
📌 **Finding (answer):** **DisableAntiSpyware** (registry value name)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T14:38:21Z  
- **ActionType:** RegistryValueSet  
- **RegistryKey:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`  
- **RegistryValueName:** `DisableAntiSpyware` → **1**  
💡 **Why it matters:** Weakens baseline protections at policy level; corroborates defense evasion.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryKey, PreviousRegistryValueData, PreviousRegistryValueName
```
<img width="868" height="792" alt="Screenshot 2025-08-17 220703" src="https://github.com/user-attachments/assets/3a95118b-7155-43a7-a5cb-2cbc0bd0a090" />

---

🚩 **Flag 7 – Access to Credential-Rich Memory Space**  
🎯 **Objective:** Identify if the attacker dumped memory content from a sensitive process.  
📌 **Finding (answer):** HR-related dump file disguise = **HRConfig.json**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamps:** 2025-07-18T15:10:47Z & 15:12:27Z  
- **Process:** `rundll32.exe`  
- **CommandLines:**  
  - `"rundll32.exe" C:\Windows\System32\comsvcs.dll, MiniDump 7784 C:\HRTools\HRConfig.json full`  
  - `"rundll32.exe" C:\Windows\System32\comsvcs.dll, MiniDump 716 C:\HRTools\HRConfig.json full`  
- **Initiating:** powershell.exe  
- **SHA256:** `076592ca1957f8357cc201f0015072c612f5770ad7de85f87f254253c754dd7`  
💡 **Why it matters:** comsvcs.dll MiniDump likely targeted LSASS; output masked as HR config to blend with business activity.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "Dump"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256

```
<img width="879" height="567" alt="Screenshot 2025-08-17 221121" src="https://github.com/user-attachments/assets/1c15856c-3250-4f8d-ad99-5cc96f053f63" />

---

🚩 **Flag 8 – File Inspection of Dumped Artifacts**  
🎯 **Objective:** Detect whether memory dump contents were reviewed post‑collection.  
📌 **Finding (answer):** `"notepad.exe" C:\HRTools\HRConfig.json`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:13:16Z  
- **Process:** notepad.exe (initiated by powershell.exe)  
- **SHA256:** `da5807bb0997ccb5132950ec87eda2b33b1ac4533cf17a22a6f3b576ed7c5b`  
💡 **Why it matters:** Confirms post‑dump review/validation of harvested credentials or secrets.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "HRConfig.json"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="760" height="268" alt="Screenshot 2025-08-17 221257" src="https://github.com/user-attachments/assets/cd60c854-428b-4fde-aa35-a48941216c7e" />

---

🚩 **Flag 9 – Outbound Communication Test**  
🎯 **Objective:** Catch network activity establishing contact outside the environment.  
📌 **Finding (answer):** **.net** (TLD of unusual outbound domain)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Suspicious Domain:** `eo7j1sn715wkekj.m.pipedream.net` (amid mostly Microsoft `*.msedge.net`/`*.azureedge.net`)  
💡 **Why it matters:** Non‑standard webhook/C2 infrastructure used as low‑profile beacon prior to exfiltration.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl != ""
| where RemoteUrl !contains ".com"
| summarize Count = count() by RemoteUrl
| sort by Count desc
```
<img width="498" height="575" alt="Screenshot 2025-08-17 221558" src="https://github.com/user-attachments/assets/ff3a81e7-bcd1-43fb-a85c-169e54aeb922" />

---

🚩 **Flag 10 – Covert Data Transfer**  
🎯 **Objective:** Uncover evidence of internal data leaving the environment.  
📌 **Finding (answer):** Last unusual outbound connection → **52.54.13.125**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm · **ActionType:** ConnectionSuccess  
- **RemoteUrl:** `eo7j1sn715wkekj.m.pipedream.net`  
- **Sequence:** 52.55.234.111 → **52.54.13.125** (last at 2025-07-18T15:28:44Z)  
💡 **Why it matters:** Validates egress path to external service consistent with data staging/exfil.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl !~ ""
| where RemoteUrl contains "pipedream.net"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl
```
<img width="492" height="411" alt="Screenshot 2025-08-17 221959" src="https://github.com/user-attachments/assets/3497fc89-96b0-4dff-955d-1ef4930d7e02" />


---

🚩 **Flag 11 – Persistence via Local Scripting**  
🎯 **Objective:** Verify if unauthorized persistence was established via legacy tooling.  
📌 **Finding (answer):** File name tied to Run‑key value = **OnboardTracker.ps1**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:50:36Z  
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- **Value Name:** `HRToolTracker` → **C:\HRTools\LegacyAutomation\OnboardTracker.ps1**  
- **Initiating Process:** PowerShell `New-ItemProperty ... -Force`  
💡 **Why it matters:** Ensures re‑execution at logon; disguised as HR “Onboarding” tool.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where InitiatingProcessCommandLine contains "-c"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```
<img width="1643" height="231" alt="Screenshot 2025-08-17 222159" src="https://github.com/user-attachments/assets/2b76f134-956d-448c-8c57-c8c55a5bfc73" />

---

🚩 **Flag 12 – Targeted File Reuse / Access**  
🎯 **Objective:** Surface the document that stood out in the attack sequence.  
📌 **Finding (answer):** **Carlos Tanaka**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Repeated Access:** `Carlos.Tanaka-Evaluation.lnk` (count = 3) within HR artifacts list  
💡 **Why it matters:** Personnel record of focus; aligns with promotion‑manipulation motive.
**KQL Query Used:**
```
DeviceEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| summarize Count = count() by FileName
| sort by Count desc
```
<img width="434" height="767" alt="Screenshot 2025-08-17 222304" src="https://github.com/user-attachments/assets/273f916d-e5fe-40dc-924f-802f9724ebc7" />



---

🚩 **Flag 13 – Candidate List Manipulation**  
🎯 **Objective:** Trace tampering with promotion‑related data.  
📌 **Finding (answer):** **SHA1 = 65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34**  
🔍 **Evidence:**  
- **File:** `PromotionCandidates.csv`  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18 16:14:36 (first **FileModified**)  
- **Path:** `C:\HRTools\PromotionCandidates.csv`  
- **Initiating:** `"NOTEPAD.EXE" C:\HRTools\PromotionCandidates.csv`  
💡 **Why it matters:** Confirms direct manipulation of structured HR data driving promotion decisions.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FolderPath contains "HR"
| summarize Count = count() by FileName
| sort by Count desc

```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/user-attachments/assets/ce206008-93b6-48c1-a99c-2868db039031" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName == "PromotionCandidates.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessCommandLine

```
<img width="1880" height="433" alt="Screenshot 2025-08-17 223349" src="https://github.com/user-attachments/assets/f31b2be7-75d2-4dac-b491-8006c9f342b4" />


---

🚩 **Flag 14 – Audit Trail Disruption**  
🎯 **Objective:** Detect attempts to impair system forensics.  
📌 **Finding (answer):** **2025-07-19T05:38:55.6800388Z** (first log‑clear attempt)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Process:** `wevtutil.exe`  
- **Command:** `"wevtutil.exe" cl Security` (+ additional clears shortly after)  
- **SHA256:** `0b732d9ad576d1400db44edf3e750849ac481e9bbaa628a3914e5eef9b7181b0`  
💡 **Why it matters:** Clear Windows Event Logs → destroys historical telemetry; classic anti‑forensics.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="https://github.com/user-attachments/assets/af5db852-e1c5-4ff3-8919-aef0a6baa225" />



---

🚩 **Flag 15 – Final Cleanup and Exit Prep**  
🎯 **Objective:** Capture the combination of anti‑forensics actions signaling attacker exit.  
📌 **Finding (answer):** **2025-07-19T06:18:38.6841044Z**  
🔍 **Evidence:**  
- **File:** `EmptySysmonConfig.xml`  
- **Path:** `C:\Temp\EmptySysmonConfig.xml`  
- **Host:** nathan-iel-vm · **Initiating:** powershell.exe  
💡 **Why it matters:** Blinds Sysmon to suppress detection just prior to exit; ties off anti‑forensics chain.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName in ("ConsoleHost_history.txt","EmptySysmonConfig.xml","HRConfig.json")
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/user-attachments/assets/6334babb-6839-4281-b025-74346f5623e9" />


---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell) – Flags 1–5, 7–8  
- **Persistence:** T1547.001 (Run Keys) – Flag 11  
- **Discovery:** T1033/T1087 (whoami /all; group/user discovery) – Flags 1–3, 4  
- **Credential Access:** T1003.001 (LSASS dump) – Flag 7 (MiniDump via comsvcs.dll)  
- **Command & Control / Exfil:** T1071/T1041 – Flags 9–10 (pipedream.net, .net TLD, IP 52.54.13.125)  
- **Defense Evasion:** T1562.001/002 & T1070.001 – Flags 5–6 (Defender), 14–15 (log clear, Sysmon blind)

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
