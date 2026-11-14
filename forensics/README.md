# Digital forensics for incident response

Practical guides for answering the incident-response questions: *what ran, when, by whom, how it got in, what it touched, and is it still there.*

| Document | Contents |
| --- | --- |
| [windows-artifacts.md](windows-artifacts.md) | Windows artifacts by question (execution, persistence, lateral movement, user activity, file activity) with event IDs and parsers |
| [linux-artifacts.md](linux-artifacts.md) | Linux artifacts for server intrusions: auth, shell history, persistence, web server and container traces |
| [memory-forensics.md](memory-forensics.md) | Memory acquisition and a Volatility 3 triage workflow |
| [evidence-handling.md](evidence-handling.md) | Order of volatility, hashing, chain of custody, and a custody form template |
| [collect/collect_linux.sh](collect/collect_linux.sh) | Read-only live-response collection for Linux |
| [collect/collect_windows.ps1](collect/collect_windows.ps1) | Read-only live-response collection for Windows |

## Ground rules

1. **Preserve before you analyze.** Collect and hash first. Work on copies.
2. **Collect the most volatile evidence first.** Memory and network state disappear on reboot, and disk artifacts get overwritten gradually.
3. **Minimize your footprint.** Every command you run changes the system. Run collection tools from external media or a known path, write output off-host where possible, and log what you ran.
4. **Record time precisely.** Note the time zone and clock skew of every source. Normalize timelines to UTC.
5. **Separate fact from inference.** "Prefetch shows `x.exe` ran at 02:14 UTC" is a fact. "The attacker ran `x.exe`" is an inference that needs corroboration.
6. **Use at least two sources per key conclusion.** For example, execution from Prefetch *and* from Amcache or EDR telemetry.
