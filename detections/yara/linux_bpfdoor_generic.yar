/*
   Generic BPFDoor (Linux passive backdoor) detection.

   Built from behaviour described in public analyses (KISA/KrCERT notices,
   Trend Micro, AhnLab ASEC) rather than from one sample, so it survives
   recompiles that change hashes:
     - pid and staging file paths written by known builds,
     - process names it fakes with prctl/argv overwrite,
     - pseudo-terminal setup strings used to give the operator a PTY,
     - the history-suppression environment it gives the spawned shell,
     - the iptables NAT redirect it inserts for the bind-shell mode.

   KrCERT publishes an official ELF_BPFDoor rule in its BPFDoor check guide.
   Run both; this one is meant to catch variants with renamed files.

   Author: girrj
   Date:   2026-11-14
   License: MIT
*/

rule Linux_Backdoor_BPFDoor_Generic
{
    meta:
        description  = "BPFDoor-family passive backdoor (ELF) from file paths, masquerade names, PTY and shell-environment strings"
        author       = "girrj"
        date         = "2026-11-14"
        mitre_attack = "T1205.002, T1036.005, T1070.003"
        severity     = "critical"
        reference    = "https://asec.ahnlab.com/en/87863/"

    strings:
        $stage  = "/dev/shm/kdmtmpflush" ascii

        $pid1   = "/var/run/haldrund.pid" ascii
        $pid2   = "/var/run/hald-smartd.pid" ascii
        $pid3   = "/var/run/hp-health.pid" ascii
        $pid4   = "/var/run/hald-addon.pid" ascii
        $pid5   = "/var/run/system.pid" ascii

        $mask1  = "/sbin/udevd -d" ascii
        $mask2  = "dbus-daemon --system" ascii
        $mask3  = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii
        $mask4  = "avahi-daemon: chroot helper" ascii
        $mask5  = "qmgr -l -t unix -u" ascii
        $mask6  = "pickup -l -t fifo -u" ascii

        $pty1   = "/dev/ptm" ascii
        $pty2   = "ptem" ascii fullword
        $pty3   = "ldterm" ascii fullword

        $env1   = "HISTFILE=/dev/null" ascii
        $env2   = "MYSQL_HISTFILE=/dev/null" ascii

        $ipt    = /iptables -t nat -[AI] PREROUTING[^\x00]{0,80}-j REDIRECT --to-ports/ ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        (
            $stage or
            (1 of ($pid*) and 1 of ($mask*)) or
            (all of ($pty*) and 2 of ($mask*)) or
            ($ipt and 1 of ($env*) and 1 of ($mask*))
        )
}
