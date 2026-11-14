# Threat Hunt 28: Wrong Shell

| | |
|---|---|
| **Analyst** | Jason Moore |
| **Organization** | PacificWatch SOC (lab scenario) |
| **Workspace** | LAW-HuntPractice |
| **Host** | NL-WS01 (10.1.10.4), Windows workstation |
| **User** | sarah.cole |
| **Hunt window** | 15 Oct 2026, 10:00–17:00 UTC |
| **Data sources** | SysmonProcess_CL, SysmonNetwork_CL, SysmonDNS_CL, SysmonFileCreate_CL, SysmonRegistryEvent_CL, SecurityEvent_CL |
| **Questions** | 30 / 30 (7 sections) |

## Table of Contents

- [Executive Summary](#executive-summary)
- [Objectives](#objectives) · [Scope](#scope)
- [Attack Timeline](#attack-timeline-utc-15-oct-2026)
- [MITRE ATT&CK Summary](#mitre-attck-summary)
- [Indicators of Compromise](#indicators-of-compromise)
- [Investigation Walkthrough](#investigation-walkthrough)
  - [Section 1: The Outbound Anomaly](#section-1-the-outbound-anomaly) (Q1–Q4)
  - [Section 2: A Name That Doesn't Belong](#section-2-a-name-that-doesnt-belong) (Q1–Q4)
  - [Section 3: The Uninvited Session](#section-3-the-uninvited-session) (Q1–Q4)
  - [Section 4: Hands on Keyboard](#section-4-hands-on-keyboard) (Q1–Q4)
  - [Section 5: What They Came For](#section-5-what-they-came-for) (Q1–Q5)
  - [Section 6: The Second Skin](#section-6-the-second-skin) (Q1–Q5)
  - [Section 7: What the Network Missed](#section-7-what-the-network-missed) (Q1–Q4)
- [Detection Gaps](#detection-gaps)
- [Final Assessment](#final-assessment)
- [Analyst Notes](#analyst-notes)

> All KQL used in this hunt is also saved as standalone files in [`queries/`](queries/). Click a question to expand it.

---

## Executive Summary

On the morning of 15 October 2026, PacificWatch SOC received two reports about workstation **NL-WS01**. An IT administrator had seen repeated outbound HTTP traffic to an unfamiliar domain, and the assigned user, **sarah.cole**, had received a Netflix-branded email that looked suspicious. The outbound traffic was still active when the case was handed over.

The hunt found that the beaconing process was **`svchost1.exe`**, running from sarah.cole's **Downloads** folder and posing as the Windows Service Host. The way in was not the phishing email but a **direct RDP logon from the internet**. At 10:04:29 UTC an attacker on a **Kali Linux** host (`WorkstationName: kali`) at **187.15.135.77** logged on as sarah.cole with valid credentials. There were no failed logons. Three minutes later, Edge in that session launched `svchost1.exe`, which began beaconing to **`egravy.com`** (5.182.33.151 and 185.196.9.213) over **HTTP/80**. The `havoc` upload path points to the **Havoc** C2 framework.

A **human operator** then worked the host through the implant. They made several mistakes typical of someone used to Linux: `ls` on Windows (the "wrong shell"), a typo in `net localgroup`, and confusion over paths. Escalation attempts with `net localgroup` and then `secedit.exe` **all failed** (no 4732 or 4704 events), so the operator stayed at Medium integrity. They read and **exfiltrated `passwords.txt` and `vpn-access-notes.txt`** with Havoc's `download` command, without staging, and also displayed client contacts and board-meeting documents. Finally they deployed a second implant, **`imageloader.exe`**, in a new folder **`Pictures\picture-loader`**, deleted the intermediate file `sishelper.exe`, and set the HKCU Run value **`image`** so the implant restarts at logon. The image theme across these names was deliberate camouflage.

No lateral movement was seen. **The threat was not contained** at the end of the window: the beacon was live, persistence was in place, internet-facing RDP was still open, and the stolen VPN and password data give the attacker other routes back into the environment.

**Root cause:** RDP exposed directly to the internet with single-factor authentication, together with sarah.cole's credentials having been compromised earlier.

---

## Objectives

- Identify the process behind the outbound traffic the IT administrator reported, and its C2 infrastructure.
- Trace the implant back to how it arrived and was run.
- Determine how the attacker got access, from where, and on what platform.
- Reconstruct the operator's actions: discovery, privilege escalation, collection and exfiltration.
- Identify persistence and anti-forensic activity.
- Assess scope (lateral movement), root cause, containment status and priority remediation.

## Scope

| Item | Value |
|---|---|
| Host | NL-WS01 (10.1.10.4) |
| Accounts | NL-WS01\sarah.cole |
| Time | 2026-10-15 10:00–17:00 UTC (`OriginalTime` used for all chronology) |
| Filter | `Campaign == 'NL-WS01'` |
| Out of scope | Email gateway, VPN, proxy and firewall logs (recommended follow-up) |

---

## Attack Timeline (UTC, 15 Oct 2026)

| Time | Event | Source |
|---|---|---|
| 10:00:57 | sarah.cole network logon from 84.233.199.115 (`DESKTOP-AMOL2RQ`), legitimate | SecurityEvent 4624 T3 |
| 10:01:06 | sarah.cole unlocks her session (Type 7), legitimate | SecurityEvent 4624 T7 |
| 10:01:54 | sarah.cole opens `passwords.txt` in Notepad, legitimate | Sysmon 1 |
| 10:04:22 | **Attacker NLA logon from 187.15.135.77, `WorkstationName: kali`** | SecurityEvent 4624 T3 |
| 10:04:29 | **Attacker RDP session (Type 10) as sarah.cole** | SecurityEvent 4624 T10 |
| 10:07:52 | **`msedge.exe` launches `Downloads\svchost1.exe`** (PID 6468, Session 2, Medium) | Sysmon 1 |
| 10:07:54 | First DNS lookup of `egravy.com`, resolving to 5.182.33.151 and 185.196.9.213 | Sysmon 22 |
| 10:10–10:12 | Discovery: `hostname`, `ipconfig/all`, `net user`, `net localgroup administrators`, `net share`, `systeminfo` | Sysmon 1 |
| 10:36:32 | sarah.cole reconnects from 187.14.57.251 (`DESKTOP-AMOL2RQ`), legitimate | SecurityEvent 4624 |
| 12:15:35 | `net localgroups administrator sarah.cole/add` fails (typo) | Sysmon 1 |
| 12:16:40 | `net localgroup administrators sarah.cole /add` fails (not elevated, no 4732) | Sysmon 1 |
| 12:20:48 | **`ls Users\sarah.cole\Documents\`**, a Linux command on Windows, fails | Sysmon 1 |
| 12:21:36 | Operator switches to `dir` | Sysmon 1 |
| 14:00:27 | `type vpn-access-notes.txt` | Sysmon 1 |
| 14:01:10 | `type passwords.txt` | Sysmon 1 |
| 14:01:35 | `secedit /configure ... /areas USER_RIGHTS` fails (no 4704) | Sysmon 1 |
| 14:02:17 | **`download passwords.txt`** | Sysmon 1 |
| 14:03:06 | **`download vpn-access-notes.txt`** | Sysmon 1 |
| 14:03:41–14:04:02 | `type Client-Contacts.csv`, `type Board-Meeting-Oct2026.docx` | Sysmon 1 |
| 15:14:41 | `upload /home/kali/havoc/load/svchost.exe ...\AppData\sishelper.exe` | Sysmon 1 |
| 15:15:54 | `del /f /q ...\Pictures\sishelper.exe` | Sysmon 1 |
| 15:17:05 | `mkdir ...\Pictures\picture-loader` | Sysmon 1 |
| 15:19:16 | **`reg add HKCU\...\Run /v "image"` pointing to `picture-loader\imageloader.exe`** | Sysmon 1 / 13 |
| 17:00 | Hunt window closes. Beacon still active, persistence in place. | |

<p align="center">
  <img src="images/timeline.png" alt="Attack timeline" width="800">
</p>

---

## MITRE ATT&CK Summary

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | RDP logon as sarah.cole with no 4625 failures |
| Initial Access / Lateral Movement | Remote Services | T1021 | Type 10 RDP logon from 187.15.135.77 (`kali`) |
| Execution | User Execution: Malicious File | T1204.002 | `msedge.exe` launches `Downloads\svchost1.exe` |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd.exe /c ...` children of `svchost1.exe` |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | `svchost1.exe`; the `picture-loader\imageloader.exe` / `image` theme |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | `del /f /q ...\sishelper.exe` |
| Discovery | File and Directory Discovery | T1083 | `ls` / `dir` across `Documents` and `projects` |
| Privilege Escalation / Persistence | Account Manipulation | T1098 | `net localgroup administrators sarah.cole /add` (failed) |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `type passwords.txt`, `vpn-access-notes.txt` |
| Collection | Data Staged | T1074 | Assessed: **not observed** (direct, file-by-file exfiltration) |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/80 beacon to `egravy.com` |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Havoc `download` of two files |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | HKCU Run value `image` |

---

## Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| File | `svchost1.exe` | Initial beacon, `C:\Users\sarah.cole.NL-WS01\Downloads\` |
| Hash (MD5) | `8DC2433856C0BDBF2864072066AB228E` | svchost1.exe |
| Hash (SHA256) | `F339DB580C27D0739E30BD5CC805BDE0D7A61FAC2518835FD21640076C7AE2EA` | svchost1.exe (IMPHASH all zeros) |
| Domain | `egravy.com` | C2 |
| IP | `5.182.33.151` | C2 (A record) |
| IP | `185.196.9.213` | C2 (A record) |
| Port | `80/TCP` | C2 transport (HTTP) |
| IP | `187.15.135.77` | Attacker RDP source |
| Hostname | `kali` | Attacker workstation name |
| File | `imageloader.exe` | Persistent implant, `...\Pictures\picture-loader\` |
| Directory | `picture-loader` | Hiding folder under `Pictures` |
| File | `sishelper.exe` | Intermediate implant (deleted, possibly still in `AppData`) |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\image` | Persistence |
| Tool | Havoc C2 (`/home/kali/havoc/load/svchost.exe`) | Framework |
| Files exfiltrated | `passwords.txt`, `vpn-access-notes.txt` | Credential theft |
| Pivot | `DESKTOP-AMOL2RQ` (84.233.199.115, 187.14.57.251) | **Legitimate** user client, kept for exclusion |

---

## Investigation Walkthrough

## Section 1: The Outbound Anomaly

<details>
<summary><strong>S1 Q1: The suspicious process</strong> → <code>svchost1.exe</code></summary>

**Objective:** Identify the process responsible for the repeated outbound connections.

**Finding:** `svchost1.exe`, running from `\Users\sarah.cole.NL-WS01\Downloads\`, made 27 connections to two external IPs on port 80.

**Evidence:**

| ProcessName | Image | Connections | DestIPs | Ports |
|---|---|---|---|---|
| svchost1.exe | `\Users\sarah.cole.NL-WS01\Downloads\svchost1.exe` | 27 | 185.196.9.213, 5.182.33.151 | 80 |
| powershell.exe | `\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 28 | 8.8.8.8 | 53 (benign `NetMonitor.ps1` IT script) |

**Why it matters:** The real `svchost.exe` only runs from `System32`. A near-match name in a user's Downloads folder is classic masquerading.

**KQL:**
```kql
SysmonNetwork_CL
| where Campaign == 'NL-WS01'
| where OriginalTime between (datetime(2026-10-15T10:00:00Z) .. datetime(2026-10-15T17:00:00Z))
| where not(ipv4_is_private(DestinationIp))
| extend ProcessName = tostring(split(Image, "\\")[-1])
| summarize Connections = count(), DestIPs = make_set(DestinationIp), Ports = make_set(DestinationPort) by ProcessName, Image
| order by Connections desc
```

<p align="center"><img src="images/s1-q1.png" alt="S1 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Alert on any process named like a system binary (`svchost*`, `lsass*`, `csrss*`, `explorer*`) running outside `C:\Windows\`.
</details>

<details>
<summary><strong>S1 Q2: C2 domain</strong> → <code>egravy.com</code></summary>

**Objective:** Identify the domain the beacon resolves.

**Finding:** `svchost1.exe` queried `egravy.com` three times (10:07:54–10:34:25 UTC).

**Evidence:** `QueryName = egravy.com`, `QueryResults = ::5.182.33.151;::185.196.9.213;` (order changes between responses).

**Why it matters:** This ties the C2 IPs to one domain, which is the block target at DNS and the proxy. The first lookup came 1.7 s after execution, so the beacon starts immediately.

**KQL:**
```kql
SysmonDNS_CL
| where Campaign == 'NL-WS01'
| where Image has "svchost1.exe" or QueryResults has_any ("185.196.9.213", "5.182.33.151")
| summarize Queries = count(), FirstSeen = min(OriginalTime), LastSeen = max(OriginalTime),
            Results = make_set(QueryResults) by Image, QueryName
```

<p align="center"><img src="images/s1-q2.png" alt="S1 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Alert on DNS queries from executables in user-writable paths to newly registered or low-reputation domains.
</details>

<details>
<summary><strong>S1 Q3: C2 addresses</strong> → <code>5.182.33.151, 185.196.9.213</code></summary>

**Objective:** Name both IPs the C2 domain resolves to.

**Finding:** `egravy.com` resolves to two A records, and the beacon alternates between them.

**Evidence:** DNS `QueryResults` and network `DestinationIp` both show 5.182.33.151 and 185.196.9.213.

**Why it matters:** The redundant infrastructure means both IPs must be blocked. Blocking one leaves the beacon working.

**KQL:**
```kql
SysmonNetwork_CL
| where Campaign == 'NL-WS01' and Image has "svchost1.exe"
| summarize Connections = count(), First = min(OriginalTime), Last = max(OriginalTime) by DestinationIp
```

<p align="center"><img src="images/s1-q3.png" alt="S1 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Add both IPs and the domain to threat intel and to firewall and proxy blocklists, and watch for other hosts contacting them.
</details>

<details>
<summary><strong>S1 Q4: Transport channel</strong> → <code>80</code></summary>

**Objective:** Identify the C2 destination port.

**Finding:** All beacon connections use TCP/80, plain HTTP.

**Evidence:** `Ports = ["80"]` for all 27 `svchost1.exe` connections.

**Why it matters:** HTTP blends in with web traffic and is rarely blocked outbound. With no TLS, beacon contents can be inspected if a proxy or packet capture exists.

**KQL:**
```kql
SysmonNetwork_CL
| where Campaign == 'NL-WS01' and Image has "svchost1.exe"
| summarize count() by DestinationPort, Protocol
```

<p align="center"><img src="images/s1-q4.png" alt="S1 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Force outbound HTTP through an authenticated proxy, and alert on direct port-80 connections from non-browser processes.
</details>

## Section 2: A Name That Doesn't Belong

<details>
<summary><strong>S2 Q1: Delivery application</strong> → <code>msedge.exe</code></summary>

**Objective:** Identify what launched the beacon.

**Finding:** `ParentImage = \Program Files (x86)\Microsoft\Edge\Application\msedge.exe` (PID 7536).

**Evidence:** Sysmon EID 1 at 10:07:52.354, User `NL-WS01\sarah.cole`, Integrity Medium, CommandLine `"\Users\sarah.cole.NL-WS01\Downloads\svchost1.exe"`.

**Why it matters:** The file was opened directly from the browser, inside the attacker's RDP session three minutes after logon.

**KQL:**
```kql
SysmonProcess_CL
| where Campaign == 'NL-WS01' and Image has "svchost1.exe"
| project OriginalTime, User, ParentImage, ParentProcessId, Image, ProcessId, CommandLine, IntegrityLevel
```

<p align="center"><img src="images/s2-q1.png" alt="S2 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Alert on browsers launching unsigned executables from `Downloads`, and enforce SmartScreen and Mark-of-the-Web blocking.
</details>

<details>
<summary><strong>S2 Q2: Execution timestamp</strong> → <code>2026-10-15 10:07:52 UTC</code></summary>

**Objective:** Find the exact creation time of the beacon process.

**Finding:** `OriginalTime = 2026-10-15T10:07:52.3541990Z` (Sysmon `UtcTime` 10:07:52.353).

**Why it matters:** This is the start of compromise on NL-WS01: 3m23s after the attacker's RDP logon and 1.7 s before the first C2 DNS lookup.

<p align="center"><img src="images/s2-q2.png" alt="S2 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Correlate new Type 10 logons from public IPs with process creation in user-writable paths within a short window.
</details>

<details>
<summary><strong>S2 Q3: Session context</strong> → <code>2</code></summary>

**Objective:** Identify the Windows session hosting the beacon.

**Finding:** `TerminalSessionId = 2`, an interactive, non-console session that fits RDP.

**Evidence (raw event):** `TerminalSessionId: 2`, `LogonId: 0x1e2ddc7`, `ProcessGuid: {5824a1ec-a5f8-6ad0-3624-000000000900}`, `MD5=8DC24338…228E`, `SHA256=F339DB58…2EA`, `IMPHASH=000…0`.

**Why it matters:** The real svchost runs only in Session 0. Session 2 confirms the masquerade and the RDP origin.

**KQL:**
```kql
SysmonProcess_CL
| where Campaign == 'NL-WS01' and Image has "svchost1.exe"
| take 1
| project pack_all()
```

<p align="center"><img src="images/s2-q3.png" alt="S2 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `svchost.exe`-named processes with `TerminalSessionId != 0`.
</details>

<details>
<summary><strong>S2 Q4: Process legitimacy</strong> → <code>no</code></summary>

**Objective:** Decide whether the process is a legitimate Windows service.

**Finding:** It deviates on every attribute.

| Attribute | Real svchost.exe | Observed |
|---|---|---|
| Name | svchost.exe | svchost1.exe |
| Session | 0 | 2 |
| Account | SYSTEM / service accounts | sarah.cole |
| Directory | C:\Windows\System32 | Downloads |
| Parent | services.exe | msedge.exe |
| Integrity | System | Medium |

**Why it matters:** Several deviations together form a clear masquerading pattern (T1036.005).

<p align="center"><img src="images/s2-q4.png" alt="S2 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Build a parent/path/session baseline rule for critical Windows process names.
</details>

## Section 3: The Uninvited Session

<details>
<summary><strong>S3 Q1: Attacker source</strong> → <code>187.15.135.77</code></summary>

**Objective:** Identify the attacker's source IP.

**Finding:** At 10:04:22.909 a Type 3 (NLA) logon from 187.15.135.77, workstation `kali`, followed at 10:04:29.544 by a Type 10 RDP logon (TargetLogonId `0x22c6761`). The `UMFD-4` / `DWM-4` logons in between show Windows creating the new desktop session.

**Why it matters:** This is the only RDP logon in the window, and it came minutes before the beacon ran.

**KQL:**
```kql
SecurityEvent_CL
| where Campaign == 'NL-WS01' and EventID == 4624
| where OriginalTime between (datetime(2026-10-15T10:00:00Z) .. datetime(2026-10-15T17:00:00Z))
| project OriginalTime, Account, LogonType, IpAddress,
          WorkstationName = column_ifexists("WorkstationName",""), TargetLogonId = column_ifexists("TargetLogonId","")
| order by OriginalTime asc
```

<p align="center"><img src="images/s3-q1.png" alt="S3 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Alert on any 4624 Type 10 from a public IP address.

**Analyst note:** The beacon's Sysmon `LogonId` (`0x1e2ddc7`) doesn't match the RDP TargetLogonId (`0x22c6761`). Attribution rests on timing, session context and workstation name, and the mismatch is listed as an open item.
</details>

<details>
<summary><strong>S3 Q2: Attacker platform</strong> → <code>kali</code></summary>

**Objective:** Identify the connecting workstation's name.

**Finding:** `WorkstationName = kali` on the 10:04:22 Type 3 logon.

**Why it matters:** `kali` is the default Kali Linux hostname, an offensive-security distribution. Leaving the default in place suggests a throwaway or quickly built attack box.

<p align="center"><img src="images/s3-q2.png" alt="S3 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Alert on 4624 or 4625 events with `WorkstationName` in a list of known attack-distro defaults (`kali`, `parrot`, `WIN-*` from public IPs).
</details>

<details>
<summary><strong>S3 Q3: Legitimate workstation</strong> → <code>DESKTOP-AMOL2RQ</code></summary>

**Objective:** Separate the legitimate user's external logons from the attacker's.

**Finding:** 84.233.199.115 (10:00:57) and 187.14.57.251 (10:36:32) both come from `DESKTOP-AMOL2RQ`, each as Type 3 followed by Type 7 (unlock).

**Why it matters:** Same client, changing ISP addresses and a normal unlock pattern: this is sarah.cole herself. It also shows RDP exposure was a standing remote-work practice.

<p align="center"><img src="images/s3-q3.png" alt="S3 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Baseline each user's known client workstation names, and alert on new ones combined with a new public IP.
</details>

<details>
<summary><strong>S3 Q4: Brute force assessment</strong> → <code>no</code></summary>

**Objective:** Determine whether the password was guessed.

**Finding:** There are no 4625 events for sarah.cole. The attacker went from NLA to an RDP session in about 6.6 s.

**Why it matters:** The credentials were obtained beforehand, possibly through the Netflix-themed phishing lure, reuse, or an infostealer. Brute force (T1110) is ruled out, and Valid Accounts (T1078) applies.

**KQL:**
```kql
SecurityEvent_CL
| where Campaign == 'NL-WS01' and EventID == 4625
| summarize count() by Account, IpAddress
```

<p align="center"><img src="images/s3-q4.png" alt="S3 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Enforce MFA on remote access, and check user credentials against known breach data.
</details>

## Section 4: Hands on Keyboard

<details>
<summary><strong>S4 Q1: Operator tell</strong> → <code>ls</code></summary>

**Objective:** Find the failed directory-listing command.

**Finding:** At 12:20:48 and 12:21:15 the beacon ran `cmd.exe /c ls Users\sarah.cole\Documents\` (and `...\projects`). `cmd.exe` has no `ls`, and the operator switched to `dir` at 12:21:36.

**Why it matters:** This is the "wrong shell": a Linux-native operator typing bash habits into a Windows shell.

**KQL:**
```kql
SysmonProcess_CL
| where Campaign == 'NL-WS01'
| where ParentImage has "svchost1.exe"
| project OriginalTime, ParentImage, Image, ProcessId, CommandLine
| order by OriginalTime asc
```

<p align="center"><img src="images/s4-q1.png" alt="S4 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `cmd.exe /c` command lines containing Linux-only commands (`ls`, `cat`, `pwd`, `uname`, `ifconfig`).
</details>

<details>
<summary><strong>S4 Q2: Alternative escalation tool</strong> → <code>secedit.exe</code></summary>

**Objective:** Identify the alternative policy-modification utility.

**Finding:** At 14:01:35: `secedit /configure /db ...\Temp\cfg.db /cfg ...\Temp\security.inf /areas USER_RIGHTS`.

**Why it matters:** After the group-add attempts failed, the operator tried to grant user rights through a custom security template.

<p align="center"><img src="images/s4-q2.png" alt="S4 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `secedit.exe /configure` run by non-admin users or from templates in `Temp`.
</details>

<details>
<summary><strong>S4 Q3: Escalation proof</strong> → <code>no</code></summary>

**Objective:** Determine whether any escalation succeeded.

**Finding:** There were no 4732 (member added to group) or 4704 (user right assigned) events in the window.

| Time | Method | Result |
|---|---|---|
| 12:15:35 | `net localgroups administrator sarah.cole/add` | Failed (syntax) |
| 12:16:40 | `net localgroup administrators sarah.cole /add` | Failed (no 4732) |
| 14:01:35 | `secedit /configure /areas USER_RIGHTS` | Failed (no 4704) |

**Why it matters:** The attacker stayed at Medium integrity, which limited them to the user's own data and HKCU persistence.

**KQL:**
```kql
SecurityEvent_CL
| where Campaign == 'NL-WS01'
| where EventID in (4732, 4728, 4756, 4704)
| project OriginalTime, EventID, Account, Activity
```

<p align="center"><img src="images/s4-q3.png" alt="S4 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `net localgroup ... /add` and `secedit /configure` regardless of whether they succeed, because the attempt itself is the signal.
</details>

<details>
<summary><strong>S4 Q4: Operator method</strong> → <code>human</code></summary>

**Objective:** Decide between live operator and automated script.

**Finding:** It was a hands-on-keyboard human operator, based on wrong-OS commands, a typo then a fix, repeated `dir` path attempts, a change of tactic after failure, irregular timing (gaps of seconds and hours), and confusion over the `sishelper.exe` path.

**Why it matters:** Interactive Havoc C2 operation by someone at home on Linux but weaker on Windows. Persistence was nonetheless carefully themed (S6 Q5).

<p align="center"><img src="images/s4-q4.png" alt="S4 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Treat interactive `cmd.exe` children of unknown binaries as active intrusions that need immediate response.
</details>

## Section 5: What They Came For

<details>
<summary><strong>S5 Q1: Credential file</strong> → <code>passwords.txt</code></summary>

**Objective:** Identify the credential file accessed.

**Finding:** `type \Users\sarah.cole\Documents\passwords.txt` at 14:01:10.

**Why it matters:** Plaintext credential storage (T1552.001). All credentials in the file must be treated as compromised.

<p align="center"><img src="images/s5-q1.png" alt="S5 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Run a DLP or file-name watch for `password*`, `creds*` and `*vpn*` files, and require a password manager.
</details>

<details>
<summary><strong>S5 Q2: Legitimate access</strong> → <code>10:01:54</code></summary>

**Objective:** Find when the legitimate user first opened the file.

**Finding:** At 10:01:54.721 UTC, `explorer.exe` launched `notepad.exe` (PID 8688) on `passwords.txt` as sarah.cole.

**Why it matters:** This sets a baseline: the file was in normal use before the attacker arrived at 10:04:22, which separates user activity from the attacker's 14:01 access. The other matches were Azure Guest Configuration (`oscfg.exe`) password-policy checks, which are benign.

**KQL:**
```kql
SysmonProcess_CL
| where Campaign == 'NL-WS01' and CommandLine has "passwords"
| project OriginalTime, User, ParentImage, Image, ProcessId, CommandLine
| order by OriginalTime asc
```

<p align="center"><img src="images/s5-q2.png" alt="S5 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Compare file access by the expected parent (`explorer.exe`) with access through `cmd.exe` spawned by unknown binaries.
</details>

<details>
<summary><strong>S5 Q3: Exfiltration command</strong> → <code>download</code></summary>

**Objective:** Identify the C2 file-transfer command.

**Finding:** Havoc Demon `download`, logged as `cmd.exe /c download <path>` at 14:02:17 and 14:03:06.

**Why it matters:** Exfiltration over the existing HTTP C2 channel (T1041), with no separate exfiltration channel to detect.

<p align="center"><img src="images/s5-q3.png" alt="S5 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `cmd.exe` command lines starting with C2 framework verbs (`download`, `upload`, `shell`, `sleep`).
</details>

<details>
<summary><strong>S5 Q4: Exfiltrated files</strong> → <code>passwords.txt, vpn-access-notes.txt</code></summary>

**Objective:** Name both files transferred to the attacker.

**Finding:**

| Time | File |
|---|---|
| 14:02:17 | `\Users\sarah.cole\Documents\passwords.txt` |
| 14:03:06 | `\Users\sarah.cole\Documents\projects\vpn-access-notes.txt` |

`Client-Contacts.csv` and `Board-Meeting-Oct2026.docx` were displayed through `type`, so their contents are also exposed.

**Why it matters:** The VPN notes give the attacker a way into the corporate network that doesn't depend on NL-WS01.

<p align="center"><img src="images/s5-q4.png" alt="S5 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Review VPN authentication logs for any use of the exposed credentials after 14:03 UTC on 15 Oct.
</details>

<details>
<summary><strong>S5 Q5: Staging assessment</strong> → <code>no</code></summary>

**Objective:** Determine whether data was staged or archived before exfiltration.

**Finding:** No archive utilities (`7z`, `rar`, `tar`, `makecab`, `Compress-Archive`) and no `copy`, `xcopy`, `robocopy` or `move` commands were seen. Files were downloaded individually from where they sat.

**Why it matters:** Opportunistic, low-sophistication collection. T1074 was assessed and **not observed**.

**KQL:**
```kql
SysmonProcess_CL
| where Campaign == 'NL-WS01'
| where Image has_any ("7z", "rar", "tar.exe", "makecab", "xcopy", "robocopy")
    or CommandLine has_any ("Compress-Archive", ".zip", ".7z", ".rar", " copy ", " move ")
| project OriginalTime, User, Image, CommandLine
```

<p align="center"><img src="images/s5-q5.png" alt="S5 Q5 screenshot" width="800"></p>

**Detection Recommendation:** Keep archive-utility alerting in place. Its absence here doesn't make it less valuable for other intrusions.
</details>

## Section 6: The Second Skin

<details>
<summary><strong>S6 Q1: Persistent beacon</strong> → <code>imageloader.exe</code></summary>

**Objective:** Identify the persistent copy of the implant.

**Finding:** `\Users\sarah.cole.NL-WS01\Pictures\picture-loader\imageloader.exe`, the target of the Run key.

**Why it matters:** A second implant under a new name survives a reboot or the removal of `svchost1.exe`.

**KQL:**
```kql
SysmonFileCreate_CL
| where Campaign == 'NL-WS01'
| where TargetFilename has_any ("sishelper", "imageloader", "picture-loader") or TargetFilename endswith ".exe"
| project OriginalTime, Image, TargetFilename
| order by OriginalTime asc
```

<p align="center"><img src="images/s6-q1.png" alt="S6 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `.exe` files created under `Pictures`, `Documents`, `Music` or `Videos`.
</details>

<details>
<summary><strong>S6 Q2: Hiding directory</strong> → <code>picture-loader</code></summary>

**Objective:** Identify the folder created for the implant.

**Finding:** `mkdir \Users\sarah.cole.NL-WS01\Pictures\picture-loader` at 15:17:05.

**Why it matters:** A folder the user can write to without admin rights, named to look harmless.

<p align="center"><img src="images/s6-q2.png" alt="S6 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Alert on directory creation followed by an executable write in user media folders by a non-explorer process.
</details>

<details>
<summary><strong>S6 Q3: Cleanup evidence</strong> → <code>sishelper.exe</code></summary>

**Objective:** Identify the intermediate file deleted.

**Finding:** `upload ... \AppData\sishelper.exe` (15:14:41), then `del /f /q ...\Pictures\sishelper.exe` (15:15:54) and a `dir` check (15:16:24).

**Why it matters:** Indicator removal (T1070.004). Because the upload and delete paths differ, a copy may still be in `\Users\sarah.cole\AppData\`, which needs verifying during eradication.

<p align="center"><img src="images/s6-q3.png" alt="S6 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Alert on `del /f /q` of executables by `cmd.exe` children of untrusted binaries.
</details>

<details>
<summary><strong>S6 Q4: Registry value</strong> → <code>image</code></summary>

**Objective:** Identify the Run key value name.

**Finding:** At 15:19:16, `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "image" /t REG_SZ /d "...\picture-loader\imageloader.exe" /f`.

**Why it matters:** The implant runs at every sarah.cole logon (T1547.001). It's HKCU rather than HKLM because escalation failed.

**KQL:**
```kql
SysmonRegistryEvent_CL
| where Campaign == 'NL-WS01'
| where TargetObject has @"CurrentVersion\Run"
| project OriginalTime, Image, EventType, TargetObject, Details
```

<p align="center"><img src="images/s6-q4.png" alt="S6 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Alert on Run/RunOnce writes whose data points to user-profile paths.
</details>

<details>
<summary><strong>S6 Q5: Naming pattern</strong> → <code>deliberate</code></summary>

**Objective:** Assess the naming of the persistence elements.

**Finding:** `Pictures`, `picture-loader`, `imageloader.exe` and `image` are four separately chosen names that share one theme.

**Why it matters:** This was deliberate camouflage, in contrast to the operator's clumsy command-line work, and suggests a pre-planned persistence approach.

<p align="center"><img src="images/s6-q5.png" alt="S6 Q5 screenshot" width="800"></p>

**Detection Recommendation:** Don't rely on names looking harmless. Detect on location, signer and parent instead.
</details>

## Section 7: What the Network Missed

<details>
<summary><strong>S7 Q1: Lateral movement</strong> → <code>no</code></summary>

**Objective:** Determine whether internal hosts were targeted.

**Finding:** No RFC 1918 destinations from the implant processes, and no lateral-movement commands (`net use`, `psexec`, `wmic /node`, `Enter-PSSession`, scans).

**Why it matters:** On-host compromise was limited to NL-WS01, **but** the stolen VPN and password data allow out-of-band movement that wouldn't show in this host's telemetry.

**KQL:**
```kql
SysmonNetwork_CL
| where Campaign == 'NL-WS01'
| where Image has_any ("svchost1.exe", "imageloader.exe", "sishelper.exe", "cmd.exe")
| extend Internal = ipv4_is_private(DestinationIp)
| summarize Connections = count(), Ports = make_set(DestinationPort) by Image, DestinationIp, Internal
```

<p align="center"><img src="images/s7-q1.png" alt="S7 Q1 screenshot" width="800"></p>

**Detection Recommendation:** Extend the hunt to VPN, identity provider and other endpoints for the exposed accounts.
</details>

<details>
<summary><strong>S7 Q2: Root cause</strong> → <code>RDP</code></summary>

**Objective:** Identify the exposed remote access service.

**Finding:** Remote Desktop Protocol (TCP/3389) was reachable from the internet with single-factor authentication.

**Evidence:** Type 3 (NLA) → Type 10 (RemoteInteractive) from 187.15.135.77, a new desktop session (`DWM-4`/`UMFD-4`), the beacon in Session 2, and no 4625s.

**Why it matters:** Internet-exposed RDP plus stolen credentials gave the attacker the whole intrusion.

<p align="center"><img src="images/s7-q2.png" alt="S7 Q2 screenshot" width="800"></p>

**Detection Recommendation:** Remove public RDP, and require a VPN or RD Gateway with MFA, or just-in-time access (Azure Bastion / Defender JIT).
</details>

<details>
<summary><strong>S7 Q3: Threat status</strong> → <code>no</code></summary>

**Objective:** Determine whether the threat was contained.

**Finding:** It was not contained. The beacon was active at handover, the Run key was in place, RDP was still exposed, and sarah.cole's credentials were not reset. No remediation events appear.

**Why it matters:** The attacker keeps access to the host and holds credentials that work elsewhere.

<p align="center"><img src="images/s7-q3.png" alt="S7 Q3 screenshot" width="800"></p>

**Detection Recommendation:** Isolate the device automatically when C2 IOCs are confirmed on an endpoint.
</details>

<details>
<summary><strong>S7 Q4: Priority remediation</strong> → Delete the Run value</summary>

**Objective:** Name the single change that breaks the persistence.

**Finding:** Delete the `image` value from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so `imageloader.exe` no longer launches at sarah.cole's logon.

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "image"
```

**Why it matters:** The Run value is the only autostart trigger seen. Removing it disables persistence, but **not** the running beacon or the stolen credentials, so it must be done together with full containment.

<p align="center"><img src="images/s7-q4.png" alt="S7 Q4 screenshot" width="800"></p>

**Detection Recommendation:** Regularly audit autoruns (Sysinternals Autoruns or Defender) for user-profile executables.
</details>

---

## Detection Gaps

| Gap | Impact | Recommendation |
|---|---|---|
| RDP reachable from the internet with no MFA | Valid stolen credentials gave interactive access | Remove public 3389, and require VPN, RD Gateway or JIT with MFA |
| No alert on Type 10 logons from public IPs | The intrusion went unnoticed until traffic was reported | SIEM rule on 4624 LogonType 10 where `IpAddress` is public |
| No alert on attack-distro workstation names | `kali` was logged but not acted on | Watchlist rule on `WorkstationName` |
| Executables allowed to run from `Downloads` and `Pictures` | Both implants ran from user folders | WDAC / AppLocker path rules for user-writable directories |
| Direct outbound HTTP/80 from arbitrary processes | C2 blended in as web traffic | Egress through an authenticated proxy, and block uncategorized domains |
| No alert on system-binary name masquerading | `svchost1.exe` wasn't flagged | Rule matching name, path, parent and session for critical binaries |
| Plaintext credentials in user documents | Immediate credential theft | Password manager policy and DLP scanning |
| No automated containment | The threat was still active at handover | Automated device isolation on confirmed C2 IOC matches |
| Email telemetry not in scope | The Netflix phishing link can't be confirmed | Pull email gateway logs for the lure and possible credential harvesting |

---

## Final Assessment

NL-WS01 was compromised by a **human operator using the Havoc C2 framework** from a **Kali Linux** host at **187.15.135.77**. Access came through **internet-exposed RDP with valid sarah.cole credentials**, obtained beforehand, likely through the Netflix-branded phishing email or credential reuse. The operator ran a masquerading beacon (`svchost1.exe`) over HTTP/80 to `egravy.com`. Privilege escalation failed, but they stole credential files (`passwords.txt` and `vpn-access-notes.txt`) and set up themed HKCU persistence (`Pictures\picture-loader\imageloader.exe` through Run value `image`).

**Severity: High.** The compromise is confined to one host and standard-user privileges, but credential theft (especially VPN access notes) extends the risk to the wider environment, and the threat is **still active**.

### Containment and Remediation (priority order)

1. **Isolate NL-WS01** from the network, preserving a memory image and disk before rebuilding.
2. **Block** `egravy.com`, `5.182.33.151`, `185.196.9.213` and `187.15.135.77` at DNS, proxy and firewall.
3. **Disable or reset sarah.cole**, revoke her sessions, and **rotate every credential** in `passwords.txt` and `vpn-access-notes.txt`. Review VPN logs from 14:02 UTC on 15 Oct onward.
4. **Remove public RDP exposure** and enforce MFA on all remote access.
5. **Eradicate:** remove the Run value `image`, kill and delete `svchost1.exe` and `imageloader.exe`, remove `picture-loader`, sweep for `sishelper.exe` in `AppData`, and sweep the estate for the SHA256 hash. **Rebuild preferred.**
6. **Notify** stakeholders about the exposure of `Client-Contacts.csv` and `Board-Meeting-Oct2026.docx` (possible privacy or legal review).

---

## Analyst Notes

- **The hunt's "wrong shell" theme** appears both in the masquerading beacon (a fake Service Host) and in the operator's habit of typing Linux commands into Windows `cmd.exe` (`ls`, plus `download` and `upload` passed through `cmd /c`).
- **The phishing email was probably a lure rather than the execution vector.** Execution happened inside the attacker's RDP session. The email may have been how the credentials were harvested, which should be confirmed with email and web proxy logs.
- **Noise excluded:** scheduled IT scripts in `\Windows\Temp\` (`NetMonitor.ps1`, `IT-HealthCheck.ps1`, `UserActivity.ps1`, `BackupValidator.ps1`, `CertCheck.ps1`, `SWInventory.ps1`), including PowerShell DNS traffic to 8.8.8.8, and Azure Guest Configuration (`gc_worker.exe` / `oscfg.exe`) baseline checks.
- **Open items:** (1) the LogonId mismatch between the Sysmon beacon (`0x1e2ddc7`) and the RDP session (`0x22c6761`); (2) the `sishelper.exe` upload path (`AppData`) differs from the delete path (`Pictures`); (3) the actual write of `imageloader.exe` to disk should be confirmed in SysmonFileCreate_CL.
- **`OriginalTime`** was used for all chronology. `TimeGenerated` reflects ingestion (18 Oct 2026) and was ignored.
