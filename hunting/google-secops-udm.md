# Hunting queries: Google SecOps (UDM search)

Paste these into UDM Search. Replace `<server-naming-pattern>` with a regex for your own server naming convention. They are starting points for a hunt, not alerts. Expect to tune them to your own environment. Field names follow the UDM schema. Narrow the time range first: 7 days is a sensible default.

## 1. Web server processes starting shells

```text
metadata.event_type = "PROCESS_LAUNCH" AND
principal.process.file.full_path = /(?i)[\\\/](w3wp\.exe|httpd|apache2|nginx|php-fpm|php-cgi\.exe|java|javaw\.exe|tomcat\d*\.exe)$/ AND
target.process.file.full_path = /(?i)[\\\/](cmd\.exe|powershell\.exe|pwsh\.exe|sh|bash)$/
```

Next: group by `principal.hostname` and `target.process.command_line`. A command line that shows up on only one host is the first thing to look at.

## 2. Rare outbound destinations from servers

```text
metadata.event_type = "NETWORK_CONNECTION" AND
principal.asset.hostname = /(?i)<server-naming-pattern>/ AND
network.direction = "OUTBOUND" AND
NOT target.ip = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/
```

Next: in the statistics view, count distinct `principal.hostname` per `target.ip` and keep destinations reached by only one server. Check those against threat intelligence and passive DNS.

## 3. Coin miner pool traffic

```text
(metadata.event_type = "NETWORK_CONNECTION" AND target.port IN [3333, 4444, 5555, 7777, 14444, 45700]) OR
(metadata.event_type = "PROCESS_LAUNCH" AND target.process.command_line = /(?i)(stratum\+(tcp|ssl)|--donate-level|rx\/0)/)
```

Next: if traffic passes through NAT or a forward proxy, the observed source is the gateway, not the host. Find the real host from the gateway's own logs before you draw conclusions.

## 4. Recovery inhibition (ransomware precursor)

```text
metadata.event_type = "PROCESS_LAUNCH" AND
target.process.command_line = /(?i)(vssadmin.+delete.+shadows|wmic.+shadowcopy.+delete|wbadmin.+delete|bcdedit.+recoveryenabled\s+no)/
```

Treat every hit as a live incident until you prove otherwise.

## 5. AI coding agents running shells

```text
metadata.event_type = "PROCESS_LAUNCH" AND
principal.process.file.full_path = /(?i)[\\\/](claude|codex)(\.exe)?$/
```

Next: this sets a baseline of what agents in your fleet actually run. Group by `target.process.command_line` and look for delete, credential, network-transfer, and security-setting commands.

## 6. Interactive logon to servers from workstation ranges

```text
metadata.event_type = "USER_LOGIN" AND
extensions.auth.mechanism IN ["REMOTE_INTERACTIVE", "NETWORK"] AND
target.asset.hostname = /(?i)<server-naming-pattern>/ AND
security_result.action = "ALLOW"
```

Next: compare `principal.user.userid` against the list of approved administrators. Service accounts with interactive logons are a strong lead.
