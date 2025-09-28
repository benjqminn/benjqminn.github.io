# Holmes CTF: "The Enduring Echo" 🔊

**👤 Author:** Benjamin Taylor ([@benjqminn](https://github.com/benjqminn))

**🤝 Team:** Sherlock's Homies
- [Benjamin Taylor](https://www.linkedin.com/in/btayl106/)  
- [Greyson Brummer](https://www.linkedin.com/in/greyson-brummer-b82119301/)  
- [Jonathan Lutabingwa](https://www.linkedin.com/in/jonathan-lutabingwa/)  
- [Lansina Diakite](https://www.linkedin.com/in/lansina-diakite-7a673b202/)  
- [Shaunak Peri](https://www.linkedin.com/in/shaunak-peri-315744245/)

**🏆 Ranking**: 634 / 7,085 teams

**📝 Prompt:** LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.

**📌 Summary:** Actor “JM” breached Nicole Vale’s honeypot via web shell, stole credentials, set up persistence, and pivoted into the internal network. Evidence came from memory, bash history, configs, and process analysis.

**🟩 Challenge Difficulty:** *EASY*

---

## 📋 TL;DR (Answers)

- **First command (non-cd):** `systeminfo`
- **Parent process (full path):** `C:\Windows\system32\wbem\wmiprvse.exe`
- **Remote-exec tool:** `wmiexec.py`
- **Attacker IP:** `x.x.x.x`
- **First persistence element:** `<string>`
- **Script executed by persistence:** `C:\FOLDER\PATH\FILE.ext`
- **Local account created:** `<username>`
- **Exfil domain:** `<domain>`
- **Password generated:** `<password>`
- **Internal pivot IP:** `x.x.x.x`
- **Forwarded TCP port:** `<port>`
- **Registry path for mappings:** `HKLM\...\...`
- **MITRE ATT&CK ID for pivot technique:** `Txxxx.xxx`
- **Command to enable command-line logging (pre-attack):** `<command>`

---

## 🚩 Flag 1: First Command

**Question:** What was the first (non cd) command executed by the attacker on the host? (string) 

**Walkthrough:** 
- To start this challenge, all we are given is a `.zip` file named `The_Enduring_Echo.zip`.
- Navigating to the `winevt` logs, the first place I assumed to check for the "non cd" command executed by the attacker was `Security.evtx`.

![winevt security log](enduring_images/task1-evidence.png)
- Opening the Event Viewer, we can filter this log for Event ID `4688`, aka `Process Creation` events only.
- Since we know from previous challenges that the attacker is using the "Heisen-9-WS-6" computer that he gained credentials to, we can use the `Computer(s)` field to check only the logs containing this computer.

![Filter Current Log](enduring_images/task1-evidence2.png)
- Now, to narrow our search down even more, we can use the `Find` feature to search for only logs containing a `CommandLine` field.

![CommandLine Filter](enduring_images/task1-evidence3.png)
- After skimming through the logs given, we see that on `8/24/2025 6:51:09 PM`, there is a log with Event ID `4688` being the first `CommandLine` text of this session.
- Cross-referencing with other log activity, this seems to be the time at which the attacker made their way onto the host.

![Process Command Line](enduring_images/task1-evidence4.png)
- You can see that the "Process Command Line" value is `systeminfo`.

**Answer:** `systeminfo`  

---

## 🚩 Flag 2: 

**Question:** Which parent process (full path) spawned the attacker’s commands? (C:\FOLDER\PATH\FILE.ext) 

**Walkthrough:** 
- To find Flag 2, we are going to be looking through the `Security.evtx` logs some more.
- Since I was trying to find these flags using the Event Viewer alone, I first tried some `Find` keywords that would be more obvious indicators of the parent process spawning the commands of the attacker.

![wmi search query](enduring_images/task2-evidence.png)
- Trying the search query `wmi` proved successful: since `WMIPrvSE.exe` can run code on behalf of remote callers, and `WMI` can execute commands without dropping files, it was one of the queries I searched for.

![wmiprvse.exe log](enduring_images/task2-evidence2.png)
-  We can see in this specific log at `8/20/2025 12:48:05 PM` that the "Process Command Line" value is `C:\Windows\system32\wbem\wmiprvse.exe`.
-  Although this flag was found through trial and error, common sense was the key driving factor of my search queries, and it turned up successful.

**Answer:** `C:\Windows\system32\wbem\wmiprvse.exe`  

---

## 🚩 Flag 3: 

**Question:** Which remote-execution tool was most likely used for the attack? (filename.ext)  

**Walkthrough:** 
- For Flag 3, we know from the previous question that the attacker was using `WmiPrvSE.exe` as their parent process of suspicious commands.
- `WmiPrvSE.exe` is found within the `wmiexec` module, which is run or called from the `wmiexec.py` script.
- Using deduction, the third flag is `wmiexec.py`.

**Answer:** `wmiexec.py`  

---

## 🚩 Flag 4: 

**Question:** What was the attacker’s IP address? (IPv4 address)

**Walkthrough:** 
- To find Flag 4, we will be leveraging the `Security.evtx` logs once again.
- Whenever the attacker logs onto the network, there is bound to be a `Logon` event left behind with the attacker's machine information.
- To try and find this said event, we can search for Event ID `4624`, the indicator that "an account was successfully logged on".

![Event ID 4624](enduring_images/task4-evidence.png)
- The time of the "first command" executed by the attacker for Flag 1 was `8/24/2025 6:51:09 PM`.
- This is a good time range to start looking around.
- About 30 minutes after the first command was executed, there is a `Logon` event in which a "Source Network Address" can be found under the "Network Information" section.

![Attacker IP Address](enduring_images/task4-evidence2.png)
- The IPv4 address listed is most definitely the attacker's IP address, as it lines up with the timeline of the attack and what times the attacker was logged in.

**Answer:** `10.129.242.110`  

---

## 🚩 Flag 5: 

**Question:** What is the first element in the attacker's sequence of persistence mechanisms? (string)  

**Walkthrough:** 
- Earlier, when I was inspecting the provided files for this challenge, I found a folder named `Tasks`.
- The file path for this folder was `The_Enduring_Echo\C\Windows\System32\Tasks`.

![Tasks Folder](enduring_images/task5-evidence.png)
- This folder contains multiple files that are "scheduled task definitions", essentially created when the attacker makes a scheduled task that runs at boot/on a schedule.
- In other words, these are classic persistence mechanisms.
- Starting from the bottom, I first inspected `SysHelper Update` (the only task that wasn't OneDrive-related or MicrosoftEdge-related).
- Opening the `Security.evtx` logs, I filtered the logs for Event ID `4688`, aka `Process Creation` events only.

![Event ID 4688](enduring_images/task5-evidence2.png)
- With the `Process Creation` events all listed again, I searched using the `Find` action for the string `SysHelper Update` to narrow down my search to logs containing this scheduled task.

![SysHelper Update Find](enduring_images/task5-evidence3.png)
- The first log highlighted seemed like one of interest: upon expanding it, there is a command that (1) creates a scheduled task by the name `SysHelper Update`, (2) specifies the action the task runs, (3) runs as SYSTEM, and (4) schedules it to run every 4 minutes, and redirects the output to an administrative share.

![SysHelper Log](enduring_images/task5-evidence4.png)
- These are all key indicators of a persistence mechanism.
- The time also correlates with the time the attacker was in the system, this log being created at `8/24/2025 7:03:50 PM`.
- Looking at the previous logs in this time frame, there also seemed to be nothing unusual related to persistence mechanisms.
- Therefore, the first element in the sequence of persistence mechanisms is `SysHelper Update`.

**Answer:** `SysHelper Update` 

---

## 🚩 Flag 6: 

**Question:** Identify the script executed by the persistence mechanism. (C:\FOLDER\PATH\FILE.ext)

**Walkthrough:** 
- Finding Flag 6 is simple, as the answer lies in the log from the previous question.
- Looking at the command from the `SysHelper Update` schedule task creation command, the script and path are also specified.

![Path and File of Script](enduring_images/task6-evidence.png)

**Answer:** `C:\Users\Werni\Appdata\Local\JM.ps1`  

---

## 🚩 Flag 7:

**Question:** What local account did the attacker create? (string) 

**Walkthrough:** 
- To find a new local account created in the `Security.evtx` logs, we can filter by Event ID `4720`.
- Specifically, Event ID `4720` returns "A user account was created" events.

![Event ID 4720](enduring_images/task7-evidence.png)
- After filtering the logs, there is only one log returned with Event ID `4720`.

![SAM Account Name](enduring_images/task7-evidence2.png)
- Looking under the "Attributes" characteristics, we can see the "SAM Account Name" is `svc_netupd`.

**Answer:** `svc_netupd`  

---

## 🚩 Flag 8:

**Question:** What domain name did the attacker use for credential exfiltration? (domain)
 
**Walkthrough:** 
- To find the domain name that the attacker used for credential exfiltration, checking through the files for related files was the first step I took.

![Powershell script file](enduring_images/task8-evidence.png)
- None of the files seemed of interest for Flag 8, except for one: located in `The_Enduring_Echo\C\Users\Werni\AppData\Local` directory, there was a Windows PowerShell script named `JM.ps1`.

![Domain Name Exfiltration](enduring_images/task8-evidence2.png)
- Upon opening this `JM.ps1` file in Notepad, there is a domain name located in the parameters of an `Invoke-WebRequest` command.

**Answer:** `NapoleonsBlackPearl.htb`  

---

## 🚩 Flag 9: 

**Question:** What password did the attacker's script generate for the newly created user? (string)  

**Walkthrough:** 
- The Windows PowerShell script named `JM.ps1` contains a function in which a username and password are generated for the new user.

![Username and Password Function](enduring_images/task9-evidence.png)
- Looking at this script, we can see that the generated password is a concatenation of `Watson_` and the timestamp of the date the script was run (in the format `"yyyyMMddHHmmss"`).
- To find out the password, we will have to search the logs for when this script was executed to get an exact timestamp and find the credentials of this new user.

![User Creation Time](enduring_images/task9-evidence2.png)
- In the `Security.evtx` logs, we can see an exact timestamp of when the new user from Flag 7 was created.
- The time given for the `svc_netupd` user creation is `8/24/2025 7:05:09 PM`.
- To find the timezone of these logs, we will need to look in the `SYSTEM` registry hive (using Zimmerman's Registry Explorer v2.1.0).

![Timezone of SYSTEM](enduring_images/task9-evidence3.png)
- Knowing the timezone is in Pacific Standard Time, my system is in Eastern Standard Time.
- We need to convert the `8/24/2025 7:05:09 PM` in EST to PST to follow the system guidelines.
- This would mean the correct system time in the `SYSTEM` timezone is `8/24/2025 4:05:09 PM`.
- Converting this to 24-hour format, we get `8/24/2025 16:05:09 PM`.
- In `"yyyyMMddHHmmss"` form, this is equivalent to `20250824160509`.
- Concatenating the `Watson_` to the front of this timestamp, the password for the new user is `Watson_20250824160509`.

**Answer:** `Watson_20250824160509`  

---

## 🚩 Flag 10: 

**Question:** CogNet Scanner — how many open ports does the server have?  

**Walkthrough:** 
- 

**Answer:** `11`  

---

## 🚩 Flag 11: Organization

**Question:** Which organization does the previously identified IP belong to?  

**Walkthrough:** 
- 

**Answer:** `SenseShield MSP`  

---

## 🚩 Flag 12: Cryptic Banner

**Question:** One of the exposed services displays a banner containing a cryptic message. What is it?  

**Walkthrough:** 
- 

**Answer:** `He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`  

---

**Next challenge writeup:** [Holmes — The Watchman's Residue 👮](./holmes_watchmans_residue.md)

