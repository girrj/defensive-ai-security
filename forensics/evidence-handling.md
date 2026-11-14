# Evidence handling and chain of custody

Evidence that can't be shown to be authentic and unaltered is weak evidence. That holds for an internal investigation, a regulator, an insurer, or a court.

## Order of volatility (collect top to bottom)

1. CPU registers and cache (rarely practical)
2. **Memory**: processes, network connections, logged-on sessions
3. **Network state**: ARP cache, routing table, DNS cache
4. Running processes and open files
5. Temporary file systems (`/tmp`, `/dev/shm`, `%TEMP%`)
6. **Disk**: file system, logs, registry
7. Remote logs and monitoring data (SIEM, EDR, firewall, proxy, cloud audit logs). Check their **retention** right away, because some sources roll over within days
8. Backups and archival media

## Rules

- **Hash at collection** (SHA-256) and again on every transfer. Record both values.
- **Write-protect originals.** Use a hardware write blocker for physical disks and read-only mounts for images. Do all analysis on verified copies.
- **Log every action.** Who did what, when, from which workstation, and with which tool and version.
- **Normalize time.** Record each source's time zone and offset from a reference clock.
- **Minimize access.** Store evidence in a restricted location, and log every access.
- **Retain** according to legal and regulatory requirements, and apply a legal hold when litigation or a regulatory inquiry is possible.
- **Don't** open suspicious documents, run samples, or browse attacker infrastructure from an analyst's normal workstation.

## Chain of custody form

```markdown
# Chain of custody: <case ID>

## Item
| Field | Value |
|-------|-------|
| Item ID | <case>-E001 |
| Description | e.g. "Memory image of HOST-A", "Triage collection ZIP from HOST-B" |
| Source system | hostname / serial / cloud instance ID |
| Collected by | name, role |
| Collection date/time (UTC) | |
| Collection method / tool + version | |
| Original size (bytes) | |
| SHA-256 at collection | |
| Storage location | |

## Transfers
| # | Date/time (UTC) | Released by | Received by | Purpose | SHA-256 verified (Y/N) | Notes |
|---|-----------------|-------------|-------------|---------|------------------------|-------|
| 1 | | | | | | |

## Disposition
| Date | Action (returned / destroyed / archived) | Authorized by | Witness |
|------|------------------------------------------|---------------|---------|
```

## Hashing commands

```bash
# Linux / macOS
sha256sum evidence.zip | tee evidence.zip.sha256
```

```powershell
# Windows
Get-FileHash .\evidence.zip -Algorithm SHA256 | Format-List
```
