# Playbook: emergency response to a zero-day or actively exploited vulnerability

**Triggers:** a vendor emergency advisory, a CVE added to CISA KEV, a national CERT alert, credible reports of in-the-wild exploitation, or exploitation seen in your own telemetry.

The goal for the first 24 hours is to answer four questions: **Are we exposed? Have we been hit? What do we do until a patch exists? How do we know when we're done?**

## Phase 0: Intake (T+0 to T+1h)

- [ ] Open a tracking ticket. Record the CVE or advisory ID, the source, the time it was received, and the incident lead.
- [ ] Read the **primary source** (the vendor advisory and the CERT alert). Don't work from news coverage. Record the affected products, the versions, and whether an exploit or IOCs have been published.
- [ ] Run `vuln-triage/cve_triage.py` for KEV status and EPSS score (see [vuln-triage](../vuln-triage/README.md)).
- [ ] Set the initial priority:

| Condition | Priority | Patch / mitigation target |
| --- | --- | --- |
| Exploited in the wild **and** the affected asset is internet-facing | P1 | Mitigate in 24h, patch in 72h |
| Exploited in the wild, internal assets only | P2 | Mitigate in 72h, patch in 7d |
| Public PoC, no confirmed exploitation, EPSS ≥ 0.1 | P2 | Patch in 7d |
| No PoC, EPSS < 0.1 | P3 | Normal patch cycle |

## Phase 1: Exposure (T+1h to T+4h)

- [ ] Query the asset inventory and CMDB for the affected product and version. Don't trust the inventory alone. Confirm with the vulnerability scanner, EDR software inventory, and network banners where you can.
- [ ] Separate **internet-facing** instances (check external attack-surface data, WAF and load-balancer configuration, and DNS) from internal ones.
- [ ] Find the owner of every affected asset. An asset without an owner is a finding in itself.
- [ ] Publish an exposure count: affected, internet-facing, not yet confirmed.

## Phase 2: Compromise assessment (in parallel with Phase 1)

Assume that internet-facing instances may already be compromised, because exploitation often starts before disclosure.

- [ ] Search SIEM retroactively for published IOCs (IPs, domains, hashes, URI patterns), going back at least 30 days before disclosure.
- [ ] Look for the **behavior** behind the exploit, not only the IOCs: the vulnerable service spawning shells (see the `webshell_*` rules), new files in web roots, unexpected outbound connections.
- [ ] Write a temporary detection rule for the exploit pattern. Mark it `status: experimental` and put an expiry date in the description.
- [ ] Anything suspicious becomes a separate incident under [web-shell-compromise](web-shell-compromise.md) or the matching playbook.

## Phase 3: Mitigation until a patch is applied

Choose by how fast you can put it in place and how well it reduces risk:

1. Take the vulnerable interface off the internet (ACL, VPN-only, or disable the feature).
2. Apply the vendor's workaround (a configuration change or a disabled module).
3. Add a WAF or IPS virtual patch. Validate it against the exploit request pattern, and remember that encoding variants get around naive rules.
4. Increase monitoring: raise the alert level of the temporary detection, and collect full logs from the affected hosts.

For every mitigation, record who applied it, when, and how it was verified.

## Phase 4: Remediation

- [ ] Patch in priority order: internet-facing first, then systems where a compromise would hurt most.
- [ ] Verify each patch independently: scanner rescan, version check, or the vendor's verification step. A change ticket marked "done" is not verification.
- [ ] Track exceptions (systems that can't be patched yet) with an owner, a compensating control, and an expiry date.

## Phase 5: Closure

- [ ] Exposure is zero, or every remaining instance is a documented exception.
- [ ] The compromise assessment is complete and its result is recorded.
- [ ] The temporary detection is either promoted to a permanent rule or retired.
- [ ] Lessons learned: time from disclosure to mitigation for each tier. Where did the inventory fall short?

## Communication cadence (P1)

| Audience | When | Content |
| --- | --- | --- |
| CISO / management | T+4h, then daily | Exposure, compromise status, ETA, decisions needed |
| Asset owners | T+2h, then as needed | Their affected assets, required action, deadline |
| SOC shifts | Every handover | Temporary detections, what to escalate |
| Regulators / customers | As required by law or contract | Coordinate with legal before sending |
