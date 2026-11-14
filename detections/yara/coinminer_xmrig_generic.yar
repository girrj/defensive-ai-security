/*
   Generic XMRig-family miner detection.

   Matches the configuration keys and command-line help strings that XMRig and
   most forks keep even after renaming or light repacking. Heavily packed
   samples need unpacking first.

   Author: girrj
   Date:   2026-11-14
   License: MIT
*/

rule CoinMiner_XMRig_Generic
{
    meta:
        description = "XMRig or a close fork, from config and help strings"
        author      = "girrj"
        date        = "2026-11-14"
        mitre_attack = "T1496"
        severity    = "high"

    strings:
        $pool1   = "stratum+tcp://" ascii wide
        $pool2   = "stratum+ssl://" ascii wide

        $cfg1    = "\"donate-level\"" ascii
        $cfg2    = "\"randomx\"" ascii
        $cfg3    = "\"huge-pages\"" ascii
        $cfg4    = "\"nicehash\"" ascii
        $cfg5    = "\"rig-id\"" ascii

        $help1   = "--donate-level=N" ascii
        $help2   = "--cpu-max-threads-hint" ascii
        $help3   = "--randomx-1gb-pages" ascii

        $algo1   = "rx/0" ascii
        $algo2   = "cn/r" ascii
        $algo3   = "argon2/chukwa" ascii

        $name    = "xmrig" ascii wide nocase

    condition:
        filesize < 20MB and
        (
            (1 of ($pool*) and 2 of ($cfg*)) or
            (2 of ($help*) and 1 of ($algo*)) or
            ($name and 3 of ($cfg*, $help*))
        )
}
