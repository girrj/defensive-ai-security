# Web shells (웹셸)

## Definition (정의)

A web shell (웹셸) is unauthorized server-side code used to control an application host after access is gained.

## Why it matters

An apparently successful WAF block does not clear an already modified server.

## How to do it / what to check

Review new executable files in web roots and unusual web-server child processes; preserve the file and logs, isolate affected hosts and correct the original access path.

## In this repository

[web-shell-compromise.md](../../playbooks/web-shell-compromise.md) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md), [Case 07](../../threat-intel/korea-incidents/cases/07-lotte-card-weblogic.md)

## References

- [MITRE ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/)
