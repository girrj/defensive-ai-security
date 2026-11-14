# Playbook: ransomware precursor activity

**Triggers:** `ransomware_recovery_inhibition` (critical), `lsass_memory_dump`, mass file renames, or EDR ransomware behavior alerts.

Speed matters more than completeness here. Shadow copy deletion usually comes minutes before encryption.

## 1. Immediate (first 15 minutes)

- [ ] **Network-contain the host through EDR now.** Investigate afterwards.
- [ ] Identify the account that ran the command. If it is a domain account, disable it, and expect that the attacker may hold other credentials too.
- [ ] Check whether the same command line or parent process ran on other hosts in the last 24 hours. Several hosts point to automated deployment through GPO, PsExec, or a management tool.
- [ ] Escalate to the incident commander and notify the backup team so that backup systems are protected and taken offline if needed.

## 2. Find the staging point

Ransomware is usually deployed from a central system:

- [ ] Domain controllers: new GPOs, or recently changed scheduled tasks in SYSVOL
- [ ] Management servers: software deployment jobs created in the last 72 hours
- [ ] Remote execution: service creation (Event 7045) with random names, PsExec, or WMI process creation

## 3. Protect recovery

- [ ] Confirm that offline and immutable backups exist and are still intact.
- [ ] Revoke the attacker's access to backup consoles, so rotate backup administrator credentials.
- [ ] Do not restore to the same network segment until the access vector is closed.

## 4. Evidence

Collect memory from at least one affected host before you reboot it. Some ransomware families keep keys or configuration in memory. Keep any ransom note, an encrypted sample file, and its original if one exists.

## 5. After action

- Was LSASS dumping or credential theft visible earlier? Measure how long it took to detect.
- Which control would have stopped it at an earlier stage (MFA on remote access, LAPS, tiered admin)?
