# Awesome Blue Team (블루팀 자료 목록)

Tools, field guides, and practice data for investigating security alerts. For LLM and agent security, see the [AI defense tools directory](ai-security/defensive-tools.md).

## Digital forensics and incident response (디지털 포렌식·침해사고 대응)

| Resource | When to use it |
| --- | --- |
| [Dissect](https://github.com/fox-it/dissect) · AGPL-3.0 | Extract a specific artifact from a disk image. Its [query tool](https://docs.dissect.tools/en/latest/tools/target-query.html) can emit structured records for filtering or comparison across hosts. |
| [Plaso](https://github.com/log2timeline/plaso) · Apache-2.0 | Build a timeline (타임라인) from timestamps scattered across logs, browser history, and filesystem artifacts. Check the [supported formats](https://plaso.readthedocs.io/en/latest/) when choosing evidence sources. |
| [Timesketch](https://github.com/google/timesketch) · Apache-2.0 | Investigate a timeline with another analyst. [Import](https://timesketch.org/guides/user/upload-data/) a Plaso timeline or timestamped CSV or JSONL records, then search and annotate events around the alert. |
| [NIST CFReDS](https://cfreds.nist.gov/) · Reference datasets | Choose a documented forensic image (포렌식 이미지) and compare your findings with its case notes. The [project description](https://www.nist.gov/programs-projects/computer-forensic-reference-data-sets) explains how the collections support training and tool testing. Check the selected dataset for its terms. |

Repository guides cover [Windows artifacts](forensics/windows-artifacts.md) and [evidence handling](forensics/evidence-handling.md). Sources checked 2026-11-28.

## Network traffic analysis (네트워크 트래픽 분석)

| Resource | When to use it |
| --- | --- |
| [Arkime](https://github.com/arkime/arkime) · Apache-2.0 | Index packet captures (패킷 캡처) and locate sessions by host and time. Start with an alert's time window, then inspect the packets for the matching conversation. |
| [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/) · Field reference | Use display filters and stream inspection when an alert raises a protocol question, such as which DNS response followed a particular query. |
| [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) · Practice data | Pick a documented protocol capture, such as DNS. Trace a request and its response to practice interpreting protocol fields before applying the same method to case evidence. |

For hunts over Zeek logs, see the [network hunting guide](ndr/README.md). Sources checked 2026-11-28.
