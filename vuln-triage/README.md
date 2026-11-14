# CVE triage: KEV + EPSS + exposure

`cve_triage.py` answers the first question in any vulnerability response, *which of these do we fix first?*, from three inputs:

| Input | Source | Why it matters |
| --- | --- | --- |
| **Known exploited** | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploitation in the wild is confirmed. This is the strongest single signal. |
| **Exploit probability** | [FIRST EPSS](https://www.first.org/epss/) | The estimated probability of exploitation activity in the next 30 days |
| **Exposure** | Your asset data | An internet-facing asset gets attacked first |

CVSS is not used for ordering. It measures the impact if a flaw is exploited, not how likely exploitation is, and most CVSS 9+ vulnerabilities are never exploited.

## Priority model

| Priority | Rule | Target |
| --- | --- | --- |
| **P1** | In KEV **and** internet-facing | Mitigate within 24h, patch within 72h |
| **P2** | In KEV (internal), **or** EPSS ≥ 0.10 | Patch within 7 days |
| **P3** | EPSS ≥ 0.01 | Patch within 30 days |
| **P4** | Everything else | Normal patch cycle |

The thresholds are a starting point. Adjust them to your organization's patch capacity, and record the change.

## Usage

Standard library only, Python 3.9+.

```bash
# Individual CVEs, all internet-facing
python3 cve_triage.py CVE-2021-44228 CVE-2023-4966 CVE-2024-3400 --exposure internet

# Pull CVE IDs out of any text (an advisory, scanner output, an email)
python3 cve_triage.py -i advisory.txt

# Asset-level CSV with per-row exposure
python3 cve_triage.py -i scan.csv --format csv > triage.csv
```

`scan.csv`:

```csv
cve,asset,exposure
CVE-2024-3400,fw-edge-01,internet
CVE-2023-4966,vpn-gw-02,internet
CVE-2021-44228,app-int-07,internal
```

Example output:

```text
PRIO CVE              KEV     EPSS  EXPOSURE ASSET               REASON
P1   CVE-2024-3400    yes    0.944  internet fw-edge-01          known exploited + internet-facing
P1   CVE-2023-4966    yes    0.943  internet vpn-gw-02           known exploited + internet-facing
P2   CVE-2021-44228   yes    0.944  internal app-int-07          known exploited (internal)
```

Scores change daily. The values above are for illustration only.

### Offline mode

For air-gapped networks or reproducible reports, download the feeds once and pass them in:

```bash
python3 cve_triage.py -i scan.csv --kev-file kev.json --epss-file epss.json
```

## Tests

```bash
python3 -m unittest discover -s vuln-triage/tests
```

The tests use small fixture files and need no network access.
