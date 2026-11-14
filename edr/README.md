# EDR operations guide

How to work EDR alerts, use the response actions safely, and keep coverage honest. The guide is vendor-neutral, and the concepts carry over to any major EDR.

## 1. Coverage comes first

An EDR only protects the hosts it is running on. Before you tune anything, measure:

| Check | How | Target |
| --- | --- | --- |
| Sensor coverage | Compare CMDB, AD computer objects, and cloud instance lists against the EDR console | ≥ 98% of in-scope endpoints and servers |
| Sensor health | Hosts not seen in 24h or 7d, sensors in reduced-functionality mode, outdated versions | Every unhealthy sensor has a ticket |
| Prevention policy | Hosts in detect-only mode and the reason for each | Detect-only is an exception with an owner and an expiry |
| Telemetry reaching SIEM | Event volume per host per day in SIEM vs. the EDR console | No silent gaps |

Unmanaged hosts (OT, legacy OS, appliances, contractor laptops) need a compensating control, such as network detection, segmentation, or WAF, and a documented risk acceptance.

## 2. Triaging an EDR alert

1. **Open the process tree, not just the alert.** Go up to the grandparent (how did this start?) and down to the children (what did it do?).
2. **Look at the command line in full.** Decode any Base64 or obfuscation before you judge it.
3. **Check signer and prevalence.** Is the binary signed, by whom, and how many hosts in the fleet have it? A file on one host that is unsigned and was first seen today deserves attention.
4. **Check network activity from the process.** New external destinations in the minutes after the alert are a strong signal.
5. **Check the user.** An interactive user, a service account, or SYSTEM? Was the user logged on at the time?
6. **Pivot across the fleet.** Search for the same hash, command line, or parent-child pattern on other hosts.

## 3. Response actions: when and how

| Action | Use when | Watch out for |
| --- | --- | --- |
| **Network containment** | Confirmed malicious execution, credential theft, lateral movement, ransomware precursors | Cuts the host off from the business. For servers, coordinate with the owner unless it's ransomware, where you isolate first and inform right after |
| **Kill process** | A single malicious process with no persistence | Persistence restarts it. Check autoruns first |
| **Quarantine file** | A confirmed malicious file on disk | Hash and collect the file **before** quarantine, for analysis and IOC sweeps |
| **Live response session** | You need artifacts that telemetry lacks: files, registry, memory | Every command is logged, and you are changing a live system. Read-only commands first |
| **Block hash / IOC** | Known malicious hash to stop fleet-wide | Hash blocks are easy to bypass. Pair them with a behavioral detection |

### Live response: collection order

Collect the most volatile evidence first. See [forensics/](../forensics/) for the collection scripts.

1. Running processes with command lines and parent PIDs
2. Network connections, with the owning process
3. Logged-on sessions
4. Scheduled tasks, services, and Run keys (persistence)
5. Recently created executables in user-writable paths
6. Event logs (Security, System, PowerShell Operational, Sysmon if present)
7. A memory dump of a specific process, or full memory if warranted

Write all output to a case-named directory, hash it, and pull it off the host. Don't leave collected data on the endpoint.

## 4. Tuning without losing coverage

- Exclusions must be **narrow**: path + signer + command line, never a bare process name.
- Every exclusion gets a ticket, an owner, a reason, and a review date.
- Never exclude a whole directory that users can write to (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`).
- After any exclusion change, re-run a known-bad test (an atomic test or a harmless simulation) to confirm the detection still fires.

## 5. Detections in this repository that rely on EDR telemetry

Process creation: `webshell_child_process_*`, `lsass_memory_dump`, `lolbin_download_execute`, `powershell_encoded_or_hidden`, `scheduled_task_suspicious`, `ransomware_recovery_inhibition`, and `ai_agent_*`.
Registry: `persistence_run_key_suspicious_path`.
Service install: `remote_service_install_psexec_style`.
