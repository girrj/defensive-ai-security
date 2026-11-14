# Playbook: suspected web shell on an internet-facing server

**Triggers:** `webshell_child_process_*` Sigma rules, `webshell_spawns_shell_then_discovery` YARA-L, a YARA hit in a web root, or a WAF or IPS alert followed by unusual responses.

## 1. Triage (first 30 minutes)

- [ ] Confirm the parent and child processes and the full command line from EDR or Sysmon. Record the first time the shell was spawned.
- [ ] Identify the application: its web root, the account it runs as, and whether that account has local administrator or sudo rights.
- [ ] Pull the web access logs around the first spawn time (±2 hours). Look for a POST request to an unusual script path, a request to an upload directory, or a response size that doesn't fit the page.
- [ ] Decide on severity. Any of these makes it critical: discovery commands, credential access, outbound connections to new destinations, or new local accounts.

## 2. Containment

Agree the approach with the service owner first. Pulling the server offline destroys volatile evidence and alerts the attacker.

- [ ] Block the attacker's source IPs at the WAF or edge. Expect them to rotate.
- [ ] Put the web shell path behind a WAF deny rule instead of deleting the file. The file is evidence.
- [ ] If credential access happened, isolate the host through EDR network containment and plan credential resets.
- [ ] Block outbound connections from the server to anything except what it needs.

## 3. Evidence collection

Collect the most volatile evidence first:

1. Process list with command lines, and network connections
2. Memory image, if the host is critical or the attacker used fileless techniques
3. The web shell file(s): hash them, then copy them with their timestamps preserved
4. Web server access and error logs, and application logs
5. Windows: Security, System, PowerShell Operational, and Sysmon event logs. Linux: auth.log or secure, bash history for the service account, cron entries.
6. Files changed in the web root during the incident window (`find -newermt` / MFT timeline)

Record a hash for every collected file, and note who collected it and when.

## 4. Scoping

- [ ] Scan every web root on the same platform with `detections/yara/webshell_generic.yar`.
- [ ] Search SIEM for the attacker IPs, the web shell file name, and its hash across all web servers.
- [ ] Check for lateral movement from the server: RDP or SSH to internal hosts, SMB to admin shares, and logons by the service account elsewhere.
- [ ] Check for persistence: scheduled tasks and cron, new services, new local users, and modified startup scripts.

## 5. Eradication and recovery

- [ ] Find and patch the root cause: the vulnerable component, the upload validation flaw, or the leaked credential.
- [ ] Rebuild from a known-good image if the attacker had code execution as an administrator.
- [ ] Rotate every credential that was stored on or used from the server.
- [ ] Add detection for the specific technique you saw, then monitor closely for 30 days.

## 6. Reporting

The report should include a timeline (initial access → execution → actions → detection → containment), root cause, scope, data at risk, and corrective actions with owners and dates. Every claim in the timeline should point to log output an analyst actually pulled.
