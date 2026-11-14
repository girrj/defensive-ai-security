# Memory forensics: acquisition and Volatility 3 triage

Memory holds what disk often doesn't: injected code, decrypted payloads, network connections, command lines of processes that have exited, and credentials in use.

## When to acquire memory

- Fileless or injected malware is suspected (an alert with no file on disk)
- Ransomware precursors, since keys or configuration may be in memory
- Credential theft (LSASS access), to see what was exposed
- Before rebooting or isolating any host where you want to know what was running

## Acquisition

| OS | Tool | Notes |
| --- | --- | --- |
| Windows | WinPmem, DumpIt, Magnet RAM Capture, or EDR memory collection | Run from external media or a network share. Output size ≈ RAM size |
| Linux | AVML (static binary, no kernel module) or LiME | AVML is easiest. Volatility 3 also needs a matching symbol table (ISF) for the kernel |
| VMs | Hypervisor snapshot (`.vmem` / `.vmsn`, Hyper-V `.bin` / `.vsv`) | Least intrusive. The guest isn't touched |

Hash the image right after acquisition, and record the time, the tool and its version, and who collected it (see [evidence-handling.md](evidence-handling.md)).

## Windows triage workflow (Volatility 3)

```bash
IMG=memory.raw
vol -f $IMG windows.info                       # confirm the profile and build
vol -f $IMG windows.pstree                     # process tree: odd parents, misspelled names
vol -f $IMG windows.cmdline                    # full command lines
vol -f $IMG windows.netscan                    # connections and listeners with owning PID
vol -f $IMG windows.malfind                    # RWX private memory with code (injection)
vol -f $IMG windows.dlllist --pid <PID>        # DLLs loaded from unusual paths
vol -f $IMG windows.handles --pid <PID>        # files, registry keys, mutexes
vol -f $IMG windows.svcscan                    # services, including ones hidden from the SCM
vol -f $IMG windows.filescan | grep -i -E '\\(temp|appdata|public)\\'
vol -f $IMG windows.dumpfiles --pid <PID>      # extract files for analysis
vol -f $IMG windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
```

### What to look for

| Red flag | Why |
| --- | --- |
| `svchost.exe` whose parent isn't `services.exe`, or that runs from outside `System32` | Masquerading |
| `lsass.exe` with children, or more than one `lsass.exe` | Impersonation, or credential theft tooling |
| Office, browser, or PDF reader spawning `cmd` or `powershell` | Malicious document or exploit |
| `malfind` hits with an `MZ` header or shellcode in non-image memory | Injection or reflective loading |
| Connections from processes that shouldn't talk to the network (`notepad.exe`, `rundll32.exe` with no arguments) | Injected C2 |
| Processes with no command line, or with paths in `\Users\Public` or `\ProgramData` | Dropped tooling |

## Linux triage (Volatility 3)

```bash
vol -f $IMG linux.pslist
vol -f $IMG linux.pstree
vol -f $IMG linux.bash          # bash history recovered from memory, even if cleared on disk
vol -f $IMG linux.sockstat      # network sockets (Volatility 3 2.x)
vol -f $IMG linux.malfind
vol -f $IMG linux.check_syscall # syscall table hooks (rootkits)
vol -f $IMG linux.lsmod
```

## Tips

- Use YARA over the image (`vol -f $IMG yarascan.YaraScan --yara-file rules.yar`) to sweep for known families and for the strings found during the investigation.
- Note the timestamps in the image (`windows.info` gives the system time at capture) and line them up with the incident timeline.
- Keep the image read-only and run analysis on a copy.
