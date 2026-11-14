#!/usr/bin/env bash
# Read-only live-response collection for Linux.
#
# Collects volatile state first (processes, network, sessions), then
# persistence locations, accounts, logs, and a timeline of high-risk
# directories. It does not change system configuration, stop processes, or
# install anything. Output goes to one directory plus a tar.gz and a SHA-256
# manifest.
#
# Usage:  sudo ./collect_linux.sh [-o OUTPUT_DIR] [-c CASE_ID] [--no-logs]
# Run as root for complete results. As a normal user, some sections will be partial.
#
# Author: girrj · License: MIT

set -u
umask 077

OUT_BASE="."
CASE="case"
WITH_LOGS=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT_BASE="$2"; shift 2 ;;
    -c) CASE="$2"; shift 2 ;;
    --no-logs) WITH_LOGS=0; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

HOST="$(hostname 2>/dev/null || cat /etc/hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_BASE/${CASE}_${HOST}_${STAMP}"
mkdir -p "$OUT"/{volatile,persistence,accounts,logs,timeline,system}
LOG="$OUT/collection.log"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG"; }

# run <outfile> <command...>: record the command, capture stdout+stderr, never abort.
run() {
  local out="$1"; shift
  log "RUN $* > ${out#"$OUT"/}"
  { echo "# command: $*"; echo "# utc: $(date -u +%FT%TZ)"; "$@"; } > "$out" 2>&1 || true
}
have() { command -v "$1" >/dev/null 2>&1; }

log "START case=$CASE host=$HOST user=$(id -un) uid=$(id -u) script=$0"
[[ $(id -u) -eq 0 ]] || log "WARNING not running as root; output will be partial"

# --- 1. Volatile: processes ------------------------------------------------
run "$OUT/volatile/ps.txt" ps -eo pid,ppid,user,lstart,etimes,stat,cmd --forest
{
  echo -e "pid\tppid\tuser\texe\tdeleted\tcwd\tcmdline"
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    exe="$(readlink "$p/exe" 2>/dev/null)"
    del=0; [[ "$exe" == *"(deleted)"* ]] && del=1
    ppid="$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)"
    uid="$(awk '/^Uid:/{print $2}' "$p/status" 2>/dev/null)"
    user="$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)"
    cwd="$(readlink "$p/cwd" 2>/dev/null)"
    cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    echo -e "$pid\t$ppid\t${user:-$uid}\t$exe\t$del\t$cwd\t$cmd"
  done
} > "$OUT/volatile/proc_detail.tsv" 2>/dev/null
log "RUN /proc walk > volatile/proc_detail.tsv"

# Copy binaries of processes whose executable was deleted from disk.
mkdir -p "$OUT/volatile/deleted_exe"
awk -F'\t' 'NR>1 && $5==1 {print $1}' "$OUT/volatile/proc_detail.tsv" | while read -r pid; do
  cp "/proc/$pid/exe" "$OUT/volatile/deleted_exe/pid_${pid}.bin" 2>/dev/null && log "COPIED deleted exe pid=$pid"
done

# --- 2. Volatile: network ----------------------------------------------------
if have ss; then
  run "$OUT/volatile/sockets.txt" ss -tunap
else
  run "$OUT/volatile/sockets.txt" netstat -tunap
fi
have ip && run "$OUT/volatile/ip_addr.txt" ip addr
have ip && run "$OUT/volatile/ip_route.txt" ip route
have ip && run "$OUT/volatile/arp.txt" ip neigh
run "$OUT/volatile/resolv.conf" cat /etc/resolv.conf
run "$OUT/volatile/hosts" cat /etc/hosts
have iptables && run "$OUT/volatile/iptables.txt" iptables -S
have nft && run "$OUT/volatile/nft.txt" nft list ruleset

# --- 3. Volatile: sessions and kernel ----------------------------------------
run "$OUT/volatile/who.txt" who -a
run "$OUT/volatile/w.txt" w
have last && run "$OUT/volatile/last.txt" last -Faiw
run "$OUT/volatile/lsmod.txt" cat /proc/modules
run "$OUT/volatile/mounts.txt" cat /proc/mounts
run "$OUT/volatile/uptime.txt" uptime

# --- 4. System ----------------------------------------------------------------
run "$OUT/system/uname.txt" uname -a
run "$OUT/system/os-release" cat /etc/os-release
run "$OUT/system/date.txt" date -u
have timedatectl && run "$OUT/system/timedatectl.txt" timedatectl
have dpkg && run "$OUT/system/packages.txt" dpkg -l
have rpm && run "$OUT/system/packages.txt" rpm -qa --last
have systemctl && run "$OUT/system/services_running.txt" systemctl list-units --type=service --state=running --no-pager
have docker && run "$OUT/system/docker_ps.txt" docker ps -a --no-trunc

# --- 5. Persistence -------------------------------------------------------------
copy_tree() {  # copy readable files under a path, preserving structure
  local src="$1" dst="$OUT/persistence/files"
  [[ -e "$src" ]] || return 0
  mkdir -p "$dst"
  cp -a --parents "$src" "$dst" 2>/dev/null || true
  log "COPY $src"
}
for p in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
         /var/spool/cron /etc/systemd/system /etc/rc.local /etc/ld.so.preload /etc/profile /etc/profile.d \
         /etc/bash.bashrc /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/pam.d /etc/sudoers /etc/sudoers.d \
         /etc/modules-load.d; do
  copy_tree "$p"
done
have systemctl && run "$OUT/persistence/timers.txt" systemctl list-timers --all --no-pager
run "$OUT/persistence/ld_so_preload_exists.txt" ls -la /etc/ld.so.preload

# Per-user: authorized_keys, shell rc files, histories, user crontabs, user systemd units.
while IFS=: read -r user _ _ _ _ home _; do
  [[ -d "$home" ]] || continue
  for f in .ssh/authorized_keys .ssh/authorized_keys2 .bashrc .profile .bash_profile .zshrc \
           .bash_history .zsh_history .python_history .mysql_history .viminfo .config/systemd/user; do
    [[ -e "$home/$f" ]] || continue
    dst="$OUT/accounts/users/$user"
    mkdir -p "$dst"
    cp -a "$home/$f" "$dst/" 2>/dev/null && log "COPY $home/$f"
  done
  [[ -L "$home/.bash_history" ]] && log "NOTE $home/.bash_history is a symlink -> $(readlink "$home/.bash_history")"
done < /etc/passwd

# --- 6. Accounts ---------------------------------------------------------------
run "$OUT/accounts/passwd" cat /etc/passwd
run "$OUT/accounts/group" cat /etc/group
run "$OUT/accounts/uid0.txt" awk -F: '$3==0' /etc/passwd
run "$OUT/accounts/shadow_meta.txt" awk -F: '{print $1":"($2 ~ /^[!*]/ ? "locked/none" : "password-set")":lastchg="$3}' /etc/shadow

# --- 7. Logs -----------------------------------------------------------------
if [[ $WITH_LOGS -eq 1 ]]; then
  for f in /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/audit \
           /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/apache2 /var/log/httpd /var/log/nginx; do
    [[ -e "$f" ]] || continue
    mkdir -p "$OUT/logs/files"
    cp -a --parents "$f" "$OUT/logs/files" 2>/dev/null && log "COPY $f"
  done
  have journalctl && run "$OUT/logs/journal_7d.txt" journalctl --since "-7d" --no-pager -o short-iso-precise
fi

# --- 8. Timeline of high-risk directories (metadata only) -------------------------
{
  echo -e "mtime_epoch\tctime_epoch\tatime_epoch\tuser\tmode\tsize\tpath"
  find /tmp /var/tmp /dev/shm /etc /root /home /var/www /srv /opt -xdev \
       \( -type f -o -type l \) -mtime -30 \
       -printf '%T@\t%C@\t%A@\t%u\t%m\t%s\t%p\n' 2>/dev/null | sort -n
} > "$OUT/timeline/recent_files_30d.tsv"
log "RUN find recent files > timeline/recent_files_30d.tsv"

find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x -printf '%p\n' 2>/dev/null > "$OUT/timeline/executables_in_tmp.txt"

# --- 9. Manifest and package ------------------------------------------------------
log "END"
( cd "$OUT" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256 )
tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")"
sha256sum "$OUT.tar.gz" > "$OUT.tar.gz.sha256"
echo "collected: $OUT.tar.gz"
cat "$OUT.tar.gz.sha256"
