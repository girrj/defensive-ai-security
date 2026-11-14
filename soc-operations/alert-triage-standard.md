# SOC alert triage standard

How a Tier 1 or Tier 2 analyst works through an alert, from the moment it arrives to closure or escalation. The goal is that two analysts given the same alert reach the same conclusion and write it down the same way.

## Severity matrix

Severity is set from **asset criticality** × **confidence that the activity is malicious**, not from the vendor's severity label alone.

| | Low confidence | Medium confidence | High confidence |
| --- | --- | --- | --- |
| **Crown-jewel asset** (DC, payment, customer DB, internet-facing) | Medium | High | Critical |
| **Standard server** | Low | Medium | High |
| **Workstation** | Low | Low | Medium |

Upgrade by one level when any of these apply: a privileged account is involved, there is evidence of lateral movement, data is leaving the network, or the same indicator shows up on more than one host.

## Response targets

| Severity | Acknowledge | Initial assessment | Escalate to IR |
| --- | --- | --- | --- |
| Critical | 5 min | 15 min | Immediately on confirmation |
| High | 15 min | 1 h | Within 2 h if not resolved |
| Medium | 1 h | 4 h | As needed |
| Low | 4 h | Next business day | — |

## Triage steps

1. **Read the alert's logic.** Know what the rule looks for before you judge the event. Open the rule if you have to.
2. **Verify against raw logs.** Query the source events yourself in the SIEM. Parsing errors and aggregation hide what really happened.
3. **Establish context.** Who owns the asset? What does it normally do? Has this rule fired on this host before, and how was that closed?
4. **Widen the time window.** Look at activity on the host or user from 1h before to 1h after. Attacks are sequences, and single events mislead.
5. **Check direction and translation.** NAT, proxies, and load balancers change which IP appears where. Confirm the real source and destination before you call something inbound or outbound.
6. **Enrich indicators.** Check reputation, first-seen date, passive DNS, and certificate data. A clean reputation doesn't make something benign. New infrastructure often has none.
7. **Decide and document.** Close it as one of the dispositions below, or escalate.

## Dispositions

| Disposition | Meaning | Required note |
| --- | --- | --- |
| True positive, malicious | Attack activity confirmed | Evidence, scope, escalation reference |
| True positive, authorized | The rule worked, but the activity was approved (pentest, admin task) | Who approved it, with a reference |
| Benign true positive | The rule matched as designed, but the behavior is normal here | **A tuning request**: the rule should change |
| False positive | The rule matched something it shouldn't have | **A tuning request** with an example event |
| Insufficient data | It can't be decided from the available logs | Which log is missing → a logging-gap request |

Every *benign* and *false positive* closure must create a tuning request. Otherwise the same noise comes back every shift.

## Escalation package

When you escalate to incident response, include:

- A one-line summary: *what, where, when, how sure*
- The timeline of observed events, with the queries used
- Affected assets and accounts
- Actions already taken (containment, blocks)
- Open questions
