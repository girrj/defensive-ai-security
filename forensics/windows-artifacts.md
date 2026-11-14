# Windows forensic artifacts, organized by question

Collection is usually done with a KAPE-style target set, or with Velociraptor or EDR live response. Parsing is done with Eric Zimmerman's tools (EZ Tools), Hayabusa or Chainsaw for event logs, and a timeline tool to merge the results.

## Was a program executed?

| Artifact | Location | What it proves | Notes |
| --- | --- | --- | --- |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Execution, run count, last 8 run times, files referenced | Off by default on Windows Server. Parser: PECmd |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Presence of a program with its SHA-1, path, and first-seen time | Strong for hashes, but presence ≠ proof of execution. Parser: AmcacheParser |
| **ShimCache (AppCompatCache)** | `SYSTEM` hive | The file existed and was shimmed, with order and last-modified time | On Windows 10+, entries do **not** prove execution. Parser: AppCompatCacheParser |
| **BAM / DAM** | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Last execution time per user | Windows 10 1709 and later |
| **UserAssist** | `NTUSER.DAT\...\Explorer\UserAssist` | GUI program launches per user, with count and last time | ROT13-encoded names |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` | Per-application network bytes and resource use, hourly | Good for exfiltration volume. Parser: SrumECmd |
| **Security 4688** | Security.evtx | Process creation with parent, and command line if that policy is enabled | Often not enabled. Check the audit policy |
| **Sysmon 1** | Microsoft-Windows-Sysmon/Operational | Process creation with hashes, command line, and parent | Only if Sysmon is deployed |
| **PowerShell 4104** | Microsoft-Windows-PowerShell/Operational | Script block content, logged deobfuscated | Turned on for suspicious blocks even without policy |

## How did they get in and move around?

| Event | Log | Meaning |
| --- | --- | --- |
| 4624 | Security | Successful logon. **Logon type**: 2 interactive, 3 network (SMB, PsExec), 4 batch, 5 service, 7 unlock, 10 RDP, 11 cached |
| 4625 | Security | Failed logon (sub-status explains why) |
| 4648 | Security | Logon with explicit credentials (`runas`, lateral tools) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4776 | Security | NTLM credential validation (on a DC, shows source workstation) |
| 4768 / 4769 | Security (DC) | Kerberos TGT and service ticket requests. Watch for RC4 encryption (0x17) in Kerberoasting |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | RDP authentication succeeded, with source IP |
| 21 / 24 / 25 | TerminalServices-LocalSessionManager/Operational | RDP session logon, disconnect, and reconnect |
| 7045 | System | New service installed (PsExec-style lateral movement) |
| 5140 / 5145 | Security | Network share accessed (`ADMIN$`, `C$`) |
| WinRM 91, 168 | Microsoft-Windows-WinRM/Operational | Remote PowerShell session |

Correlate on the **Logon ID** to tie a 4624 to the 4688 process creations and 4663 object accesses that follow it.

## Persistence

| Mechanism | Where to look | Event or parser |
| --- | --- | --- |
| Run / RunOnce keys | `HKLM` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Run*` | RECmd, Autoruns, Sysmon 13 |
| Services | `SYSTEM\CurrentControlSet\Services` | System 7045, Security 4697 |
| Scheduled tasks | `C:\Windows\System32\Tasks\`, `TaskCache` registry | Security 4698 / 4702, TaskScheduler/Operational 106, 140, 200 |
| WMI event subscriptions | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` | WMI-Activity/Operational 5861, Sysmon 19–21 |
| Startup folders | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | File system timeline |
| IFEO / AppInit / COM hijacks | `Image File Execution Options`, `AppInit_DLLs`, `HKCU\Software\Classes\CLSID` | Autoruns |
| New accounts | SAM, Security 4720 (created), 4732 (added to local group), 4728 (added to global group) | |

## User and file activity

| Artifact | What it shows |
| --- | --- |
| `$MFT` | Every file's metadata, including both `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps. A mismatch suggests timestomping. Parser: MFTECmd |
| `$UsnJrnl:$J` | File create, rename, and delete history. Recovers names of deleted attacker tools |
| LNK files and Jump Lists | Files and folders opened, including from removable or network drives |
| ShellBags | Folders browsed in Explorer, including folders that no longer exist |
| Recycle Bin `$I` files | Original path and deletion time |
| Browser history | Download sources, webmail, and file-sharing uploads |

## Anti-forensics indicators

- Security 1102 / System 104: event log cleared
- `wevtutil cl`, `Clear-EventLog`, or `fsutil usn deletejournal` in command lines
- Gaps in event record IDs
- `$SI` timestamps earlier than `$FN` timestamps (timestomping)
- Prefetch entries for `sdelete`, `cipher /w`, or `vssadmin`

## Fast triage of event logs

```bash
# Hayabusa: Sigma-based timeline across all .evtx files
hayabusa csv-timeline -d ./evtx -o timeline.csv -p verbose

# Chainsaw: hunt with Sigma rules (including the ones in this repository)
chainsaw hunt ./evtx -s detections/sigma/ --mapping mappings/sigma-event-logs-all.yml
```
