# Passive backdoors and magic packets (수동형 백도어)

## Definition (정의)

A passive backdoor (수동형 백도어) waits for a trigger in traffic instead of maintaining an obvious outbound session.

## Why it matters

Port-only or beacon-only monitoring can miss a process that reads packets and activates selectively.

## How to do it / what to check

Look for unauthorized packet sockets, unexpected kernel/network permissions, process and file artifacts, and network redirects; compare findings with a clean host baseline.

## In this repository

[bpfdoor_pid_file_artifacts.yml](../../detections/sigma/bpfdoor_pid_file_artifacts.yml) provides a related defensive procedure or detection.

## Seen in (Korean cases)

[Case 01](../../threat-intel/korea-incidents/cases/01-skt-usim-bpfdoor.md), [Case 02](../../threat-intel/korea-incidents/cases/02-kt-femtocell-and-servers.md)

## References

- [MITRE ATT&CK T1205.002](https://attack.mitre.org/techniques/T1205/002/)
