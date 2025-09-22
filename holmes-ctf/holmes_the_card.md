# Holmes CTF: "The Card" 🃏

**Author:** Benjamin Taylor ([@benjqminn](https://github.com/benjqminn))

**Group:** Sherlock's Homies
- [Benjamin Taylor](https://www.linkedin.com/in/btayl106/)  
- [Greyson Brummer](https://www.linkedin.com/in/greyson-brummer-b82119301/)  
- [Jonathan Lutabingwa](https://www.linkedin.com/in/jonathan-lutabingwa/)  
- [Lansina Diakite](https://www.linkedin.com/in/lansina-diakite-7a673b202/)  
- [Shaunak Peri](https://www.linkedin.com/in/shaunak-peri-315744245/)

**Prompt:** Holmes receives a breadcrumb from Dr. Nicole Vale - fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.

**Summary:** Multi-stage web attack against Nicole Vale’s honeypot attributed to actor “JM”: initial reconnaissance (distinct User-Agent), WAF bypass with web shell deployment, database exfiltration, malware persistence, and infrastructure mapping via Cogwork platforms.

---

## 📋 TL;DR (Answers)

- **User-Agent (first used):** `Lilnunc/4A4D - SpecterEye`
- **Web shell filename:** `temp_4A4D.php`
- **Exfiltrated DB:** `database_dump_4A4D.sql`
- **Recurring string:** `4A4D`
- **OmniYard campaigns linked:** `5`
- **Tools + malware count:** `9`
- **Malware SHA-256:** `7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477`
- **C2 IP (from CogWork):** `74.77.74.77`
- **Persistence file path:** `/opt/lilnunc/implant/4a4d_persistence.sh`
- **Open ports (CogNet scan):** `11`
- **Owning organization:** `SenseShield MSP`
- **Banner string:** `He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`

---

## 🚩 Flag 1: First User-Agent

**Question:** Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot.  

**Walkthrough:** 
- To find Flag 1, we were asked to look through the logs given to find the "first User-Agent" used by the attacker against the honeypot.
- This task seemed quite simple, and once I downloaded the logs from the given "Scenario Files" section, I opened the log titled "access.log".
- Looking at line 1, we can see that the attacker used User-Agent `Lilnunc/4A4D - SpecterEye`.
- Therefore, the value for flag 1 is: `Lilnunc/4A4D - SpecterEye`

![First User Agent](card_images/task-1-evidence.png)
**Solution Line of `access.log`:** 
- `2025-05-01 08:23:12 121.36.37.224 - - [01/May/2025:08:23:12 +0000] "GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"`

**Answer:** `Lilnunc/4A4D - SpecterEye`  

---

## 🚩 Flag 2: Web Shell Deployment

**Question:** It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name?  

**Walkthrough:** 
- To find Flag 2, it is another case of looking through the logs.
- Since this question references the WAF, I naturally figured it would be best to look through `waf.log`
- A simple `CTRL + F` command searching for "WAF" allowed me to specify which lines contained any information about WAFs, so I started by going line-by-line (as this was a relatively small file).
- On `2025-05-15 11:25:01` the logs show a "CRITICAL" alert, with a "BYPASS" action (exactly what we are looking for). This line specifies a "Web shell creation detected", so I knew I was on the right track.
- The following line, at `2025-05-15 11:25:12`, another "BYPASS" action takes place. This log specifies a PHP web shell created, with the name `temp_4A4D.php`. This is the flag for our question.

![WAF](card_images/task-2-evidence.png)
**Solution Line of `waf.log`:** 
- `2025-05-15 11:25:12 [CRITICAL] waf.exec - IP 121.36.37.224 - Rule: WEBSHELL_DEPLOYMENT - Action: BYPASS - PHP web shell temp_4A4D.php created`

**Answer:** `temp_4A4D.php`  

---

## 🚩 Flag 3: Database Exfiltration

**Question:** The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated?  

**Walkthrough:** 
- To find Flag 3, I kept looking through `waf.log`.
- We are looking for data exfiltration in particular this time, and something had caught my eye from before when I was looking for Flag 2.
- There is a rule in `waf.log` called "DATA_EXFILTRATION", and looking here was my first instinct.
- When we look at this line, occurring at `2025-05-15 11:24:34`, it gives an "Unknown Error". This line is illegible in the `waf.log` file, so I cross-checked the timestamps in the `application.log` file.
- In `application.log`, we can see that at `2025-05-15 11:24:34` there is a "Data exfiltration attempt from 121.36.37.224".
- The command was given (`'find /var/www -name "*.sql" -o -name "*.tar.gz" -o -name "*.bck"'`), but this didn't help much with finding the name of the database.
- Next, I tried the third file we were given: `access.log`.
- We can see that at the same time, the attacker used `"POST /api/v2/debug/exec HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`.
- They probed for backups and dumps; it didn’t give the DB name, but narrowed our search.
- Looking further in the logs, we see some `GET` commands.
- The attacker seemingly packed files using a web shell, and then a few logs later, we can see they downloaded the DB dump.
- **Packing the Files:** `2025-05-18 15:02:34 121.36.37.224 - - [18/May/2025:15:02:34 +0000] "GET /uploads/temp_4A4D.php?cmd=tar%20-czf%20/tmp/exfil_4A4D.tar.gz%20/var/www/html/config/%20/var/log/webapp/ HTTP/1.1" 200 128 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"`
- **Downloading the DB:** `2025-05-18 14:58:23 121.36.37.224 - - [18/May/2025:15:58:23 +0000] "GET /uploads/database_dump_4A4D.sql HTTP/1.1" 200 52428800 "-" "4A4D RetrieveR/1.0.0"`
- In this last line, we can see that there was a 52 MB `.sql` file downloaded.
- This correlates with the exfiltration, giving us the flag and name of the database file: `database_dump_4A4D.sql`.

![Exfiltration Database](card_images/task-3-evidence.png)
**Solution Line of `access.log`:** 
- `2025-05-18 14:58:23 121.36.37.224 - - [18/May/2025:15:58:23 +0000] "GET /uploads/database_dump_4A4D.sql HTTP/1.1" 200 52428800 "-" "4A4D RetrieveR/1.0.0"`

**Answer:** `database_dump_4A4D.sql`  

---

## 🚩 Flag 4: Recurring String

**Question:** During the attack, a seemingly meaningless string seems to be recurring. Which one is it?  

**Walkthrough:** 
- To find the 4th Flag, I moved into my terminal to make the search easier.
- From the first flag, one string stood out to me. When looking for the "first User-Agent", the solution `Lilnunc/4A4D - SpecterEye` contains the string `4A4D`. This string also appeared in the database dump from the last question, etc.
- I searched across all of the logs to find anything that wasn't a typical path, header, or filename using the command:
- `Select-String -Path .\access.log, .\application.log, .\waf.log -Pattern "4A4D" | Format-Table Filename, LineNumber, Line -AutoSize`
- This search query organized and specified each instance of this unfamiliar string, and proved that it showed up in many situations throughout the attack:
1. *User-Agent: `Lilnunc/4A4D - SpecterEye`*
2. *Web shell: `temp_4A4D.php`*
3. *DB dump: `database_dump_4A4D.sql`*
4. *Backup: `backup_2025_4A4D.tar.gz`*
5. *Downloader UA: `4A4D RetrieveR/1.0.0`*

![Meaningless String](card_images/task-4-evidence.png)
-  Funnily enough, the flag for this question happens to be `4A4D`.

**Answer:** `4A4D`  

---

## 🚩 Flag 5: Campaigns Linked

**Question:** OmniYard-3 … count how many campaigns appear to be linked to the honeypot attack.  

**Walkthrough:** 
- To find the 5th Flag, we navigated to the designated `IP:port` that was given. 
- Upon opening the `IP:port` in the browser, we were met with a "CogWork-Intel Graph".
- This graph contained 63 entities and 7 different types.<br>

![Campaign Graph](card_images/task-5-chart.png)
- From this graph, we can see that there is one central node with 5 different sub-nodes stemming from it. We can assume this is the specified honeypot attack.
- Based on this, the answer to this flag is `5`.

**Answer:** `5`  

---

## 🚩 Flag 6: Tools + Malware

**Question:** How many tools and malware in total are linked to the previously identified campaigns?  

**Walkthrough:** 
- The answer to this flag lies within the same graph that we used for the previous question.<br>

![Campaign Graph Entities](card_images/task-6-evidence.png)
- As you can see in the image, there is an "Entity Types" legend that specifies the type of entities that are found in the graph.
- The question is asking for "tools" and "malware" specifically.
- If we zoom in on the campaigns surrounding the honeypot (5 campaigns in particular), we can count `4 tools` and `5 malware` used.
- Adding these together, 4 + 5, gives us our flag: `9`.

**Answer:** `9`  

---

## 🚩 Flag 7: SHA-256 Hash

**Question:** The threat actor has always used the same malware in their campaigns. What is its SHA-256 hash?  

**Walkthrough:** 
- Using the same `IP:port` combo as the previous two questions, this question requires us to look a little deeper into the malware used in the attacks.
- Searching the graph for `4A4D`, the malware that the attacker has used throughout the campaigns, shows us that there are 11 entities and 3 different types associated.<br>

![4A4D Search](card_images/task-7-4a4d-search.png)
- This means that all of these entities, including one organization, 5 campaigns, and 5 malware, are all associated with `4A4D`.<br>

![4A4D Graph](card_images/task-7-4a4d-graph.png)
- If we inspect any of the malware used, they all link to a weird Indicator named `indicator--vehicle-chaos-hash-2025-0005`. In this case, I chose the `Vehicle Chaos Engine` malware and went to the "Links" section.

![Indicator Hash](card_images/task-7-vehicle-chaos-malware.png)
- Further inspection of this `Indicator` takes us to the `indicator--vehicle-chaos-hash-2025-0005` page.
- If we go to the "Details" pane, there is a "Pattern" listed in the properties.
- The pattern listed is `[file:hashes.SHA256 = '7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477']`.
- If we look deeper into this, there is a SHA256 hash embedded. This is the correct flag for the question.
- Flag / SHA-256 Hash: `7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477`.

![SHA-256 Hash](card_images/task-7-sha-256.png)

**Answer:** `7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477`  

---

## 🚩 Flag 8: C2 IP Address

**Question:** Use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects.  

**Walkthrough:** 
- Now that we have the SHA-256 value from the previous flag, we are tasked with locating the IP address to which the malware connects.
- On the "CogWork Security" website that the new `IP:port` took us to, we `CTRL + C` the SHA-256 and then `CTRL + V` into the search query box.

![Search Query SHA-256](card_images/task-8-hash-lookup.png)
- We can see here that this is not only a `Malicious` threat, but the filename also matches the `4A4D` pattern that we have been seeing throughout this activity. This means it is most definitely the correct file.
- Clicking "View Details" takes us to a more specific breakdown of the file:

![View Details SHA-256](card_images/task-8-ip-haship_hash.png)
- We can see here that an HTTPS IP address is given, and after submission we find out this is the correct value.
- Therefore, the flag (and IP address to which the malware connects) is `74.77.74.77`.

**Answer:** `74.77.74.77`  

---

## 🚩 Flag 9: Persistence File Path

**Question:** What is the full path of the file that the malware created to ensure its persistence on systems?  

**Walkthrough:** 
- Continuing off of the previous question, the flag for this question is found right below the last answer.
- The question is asking for the file path to ensure persistence on systems, and if we scroll down we see a field titled "File Operations".

![File Operations](card_images/task-9-file-path.png)
- In this section, there are two `CREATE` operations. The first of which has "persistence" in the name.
- It is safe to assume that this is the correct file path for system persistence.
- Therefore, the flag (and file path to ensure system persistence) is `/opt/lilnunc/implant/4a4d_persistence.sh`.

**Answer:** `/opt/lilnunc/implant/4a4d_persistence.sh`  

---

## 🚩 Flag 10: Open Ports

**Question:** CogNet Scanner — how many open ports does the server have?  

**Walkthrough:** 
- For this task, we are given a third and final `IP:port` address and told to use the CogNet Scanner Platform to find more details about the infrastructure of the TA.

![CogNet Scanner](card_images/task-10-search.png)
- Searching the CogNet Scanner Platform with the IP address we found in a previous flag, `74.77.74.77`, returns one single result.
- This search page contains some open ports and even some vulnerabilities with CVSS scores of 8.8 and 9.7 out of 10. It seems we are dealing with a pretty dangerous target.
- Clicking on the "Details" button, we are taken to a more in-depth breakdown of the information regarding this target.
- We can see from this page the number of open ports, which is what this question is asking for.

![Detailed Breakdown](card_images/task-10-open-ports.png)
- Therefore, the flag (and number of open ports) is `11`.

**Answer:** `11`  

---

## 🚩 Flag 11: Organization

**Question:** Which organization does the previously identified IP belong to?  

**Walkthrough:** 
- The answer to this flag is right above the number of open ports from the previous question.<br>

![Campaign Graph Entities](card_images/task-10-open-ports.png)
- As you can see in the image, under the "Network Information" section, there is a list of information pertaining this target.
- This information contains Location, ISP, Organization, and Coordinates.
- We want to find the organization for this question, which is listed in this section as `SenseShield MSP`.
- Therefore, the flag (and organization) is `SenseShield MSP`.

**Answer:** `SenseShield MSP`  

---

## 🚩 Flag 12: Cryptic Banner

**Question:** One of the exposed services displays a banner containing a cryptic message. What is it?  

**Walkthrough:** 
- Using the same CogNet scan, we can find more information about this target.
- I navigated to the "Services" tab on the top navigation pane, and was met with more details on some ports and services.

![Services Tab](card_images/task-12-services.png)
- This question is asking for a banner containing a cryptic message, so my thought process was to scroll through until I found something weird or out of the ordinary.
- Scrolling through the services provided, I found one that stood out: `7477/tcp`.
- This was an unknown service with an unknown version, running on Port 7477 and using TCP protocol.

![Suspicious Banner](card_images/task-12-cryptic-message.png)
- This seemed to be it. The Service Banner displayed was: `He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`.

**Answer:** `He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`  

---

