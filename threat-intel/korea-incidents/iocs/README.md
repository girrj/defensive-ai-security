# IOC file format

[`iocs.csv`](iocs.csv) holds indicators published by official or vendor sources for the [Korean incident cases](../README.md).

| Column | Meaning |
| --- | --- |
| `type` | `sha256`, `md5`, `ipv4`, `domain`, `onion`, `email`, `filename`, `command` |
| `value` | The indicator. Network values are defanged (`[.]`, `[@]`) |
| `description` | What it is |
| `incident` | The case file it belongs to (file name without `.md`) |
| `scope` | `incident`: published for that victim. `campaign`: published for the malware or campaign, without naming the victim |
| `source`, `source_url` | Who published it, and where |
| `published` | Date of the source publication |

## Using it

- **`scope=campaign` does not prove a case.** The Gunra and Oracle EBS indicators come from advisories that name no victims. A match means "this family or campaign touched you", not "this was the same incident".
- **IPs age fast.** The Gunra advisory itself says its IPs may be historical. Search past logs with them; check before you block.
- **Hashes break on recompile.** Use them for sweeps, then rely on the behavioural detections in each case file.

Refang for a SIEM lookup:

```python
import csv
for r in csv.DictReader(open("threat-intel/korea-incidents/iocs/iocs.csv")):
    print(r["type"], r["value"].replace("[.]", ".").replace("[@]", "@"))
```

## Counts

| Case | Indicators | Scope |
| --- | --- | --- |
| 01 SK Telecom (BPFDoor) | 12 files × MD5 and SHA256 = 24 | incident |
| 06 Gunra (AA26-222A) | 4 SHA256, 18 IPv4, 1 domain, 3 onion, 4 email, 2 ransom-note names = 32 | campaign |
| 11 Oracle EBS (Oracle alert) | 2 IPv4, 1 command, 3 SHA256 = 6 | campaign |
| **Total** | **61** | |
