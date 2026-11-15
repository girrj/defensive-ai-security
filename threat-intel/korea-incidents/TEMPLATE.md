# NN. Case title in English (한국어 사건명), YEAR

One or two sentences: what was hit, how, and why defenders should care.

| Field | Value |
| --- | --- |
| Detected / disclosed | Dates, with who announced what |
| Sector | English (한국어) |
| Impact | Numbers as reported by the official source; say which source if they differ |
| Initial access | What is publicly known. Write "Not published" rather than guessing |
| Related CVEs | IDs, or "None" |
| Attribution | Who claims what. Mark unconfirmed attributions as such |
| Public IOCs | Yes (and where) or None |

## Timeline

| Date | Event |
| --- | --- |

## What happened

Describe the incident at the level an investigator's public summary does: the stages, the weakness at each stage, and the control that failed. Leave out exploitation steps, payloads and anything that would help repeat the attack.

## Root causes (근본 원인)

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |

## IOCs

Only indicators published by an official or vendor source. Add them to [`iocs/iocs.csv`](iocs/iocs.csv) with `scope=incident` or `scope=campaign`, defanged.

## Detect it with this repo

| Layer | Detection |
| --- | --- |

## Lessons for SOC and CERT

## Sources

Link every claim to public reporting or an official advisory. Paraphrase; do not copy articles.

---

Checklist before opening a pull request:

- [ ] Every number and date matches a linked source
- [ ] No non-public information, no victim internals beyond official findings
- [ ] No exploitation detail beyond what a defender needs to detect it
- [ ] IOCs added to the CSV, and `python3 -m unittest discover -s threat-intel/korea-incidents/tests` passes
- [ ] Index row added to [`README.md`](README.md)
