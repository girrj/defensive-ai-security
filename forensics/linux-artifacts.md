# Linux forensic artifacts for server intrusions

Most Linux incidents start at an internet-facing service: a web application, SSH, an exposed management interface, or a container. These artifacts answer the usual questions.

## Access and authentication

| Artifact | Location | Notes |
| --- | --- | --- |
| Auth log | `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL) | SSH accepted and failed logons, `sudo`, `su`, and user add/modify |
| Login records | `/var/log/wtmp` (`last -f`), `/var/log/btmp` (`lastb -f`), `/var/log/lastlog` | Binary. Read them with the tools, and compare against auth.log for tampering |
| journald | `/var/log/journal/` | `journalctl -D <dir> --since ... -u sshd` works offline on a copied directory |
| SSH keys | `~/.ssh/authorized_keys` for **every** user, including root and service accounts | Added keys are the most common persistence. Check mtime and compare with a known-good copy |
| SSH configuration | `/etc/ssh/sshd_config`, `sshd_config.d/` | `PermitRootLogin`, `AuthorizedKeysFile` redirection |
| Accounts | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/` | UID 0 accounts other than root. New users with a shell. sudoers entries with `NOPASSWD` |

## Execution and commands

| Artifact | Notes |
| --- | --- |
| `~/.bash_history`, `~/.zsh_history`, `~/.python_history`, `~/.mysql_history` | Often cleared or symlinked to `/dev/null`, which is itself an indicator. Check the service account's home (e.g. `www-data`) too |
| `auditd` logs, `/var/log/audit/audit.log` | `execve` records if rules exist. `ausearch -i -m EXECVE` |
| Process accounting (`/var/log/account/pacct`) | `lastcomm` if enabled |
| `/proc/<pid>/` on a live system | `exe` (the binary, even if deleted), `cmdline`, `environ`, `cwd`, `maps`, open `fd` |

A process whose `/proc/<pid>/exe` points to `(deleted)` is a strong indicator. Copy it out from `/proc/<pid>/exe` before the process ends.

## Persistence

| Mechanism | Where to look |
| --- | --- |
| cron | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/crontabs/` (Debian) or `/var/spool/cron/` (RHEL) |
| systemd | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `~/.config/systemd/user/`. Look for new `.service` and `.timer` files |
| Shell init | `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.profile` |
| Dynamic linker | `/etc/ld.so.preload`. It should normally not exist, and any entry is suspicious |
| SSH | `authorized_keys`, including `command=` options |
| Kernel modules | `lsmod` vs. `/proc/modules` vs. modules on disk, and `/etc/modules-load.d/` |
| PAM | Modified `pam_unix.so` or new modules in `/etc/pam.d/` (credential capture backdoors) |
| Web roots | New or modified scripts, found by mtime or ctime. Scan with `detections/yara/webshell_generic.yar` |

## Web server and application

- Access logs: look for POSTs to unusual paths, requests to newly created files, and long or encoded parameters. Use the WAF and Suricata rule logic as hunting patterns.
- Error logs: stack traces at the time of exploitation often reveal the vulnerable component.
- Application logs (Tomcat `catalina.out`, `localhost_access_log`, PHP-FPM) and upload directories.

## Containers

- `docker ps -a`, `docker inspect`, and `docker diff <container>` show which files changed in the container's writable layer.
- Container logs: `docker logs` or `/var/lib/docker/containers/<id>/<id>-json.log`.
- Kubernetes: API server audit logs, `kubectl get events`, and new pods with `hostPath` mounts, `privileged: true`, or `hostPID`.

## Timeline

```bash
# File system timeline of key directories (mtime, atime, ctime)
find /etc /var/www /tmp /dev/shm /home /root -xdev -printf '%T@ %A@ %C@ %u %m %s %p\n' 2>/dev/null | sort -n > fs_timeline.txt
```

`/tmp`, `/var/tmp`, and `/dev/shm` are the usual places for dropped tooling. `/dev/shm` is memory-backed, so collect it before reboot.
