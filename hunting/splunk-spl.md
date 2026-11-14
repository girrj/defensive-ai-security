# Hunting queries: Splunk SPL

These assume Sysmon process events in `index=endpoint` (EventCode 1), web logs in `index=web`, and CIM-style field names. Change the index and sourcetype names to match your environment.

## 1. Web server processes starting shells

```spl
index=endpoint EventCode=1
  (ParentImage="*\\w3wp.exe" OR ParentImage="*\\java.exe" OR ParentImage="*\\tomcat*.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\httpd.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\certutil.exe")
| stats count min(_time) as first max(_time) as last values(CommandLine) as cmd by host ParentImage Image
| convert ctime(first) ctime(last)
| sort - count
```

## 2. Command lines seen on only one host (rarity)

```spl
index=endpoint EventCode=1 earliest=-7d
| eval cmd_norm=lower(replace(CommandLine, "\d+", "N"))
| stats dc(host) as hosts count values(host) as host by Image cmd_norm
| where hosts=1 AND count<5
| sort count
```

Replacing digits removes the noise from PIDs, ports, and timestamps, so the commands that really are rare stand out.

## 3. Web requests that look like exploitation attempts

```spl
index=web
| eval req=urldecode(uri_query)." ".http_user_agent
| where match(req, "(?i)\$\{jndi:|\$\{\$\{(lower|upper|env|::-)") OR match(req, "(?i)(\.\./){3,}|/etc/passwd|win\.ini") OR match(req, "(?i)(union\s+select|sleep\(\d+\)|benchmark\()")
| stats count values(uri_path) as paths by src_ip
| sort - count
```

## 4. Successful requests to upload paths that then execute

```spl
index=web status=200 (uri_path="*/upload*" OR uri_path="*/files/*" OR uri_path="*/temp/*")
  (uri_path="*.jsp" OR uri_path="*.jspx" OR uri_path="*.aspx" OR uri_path="*.ashx" OR uri_path="*.php")
| stats count dc(src_ip) as sources values(src_ip) as src by host uri_path
| where sources<=2
```

A script under an upload folder that only one or two clients ever request is the classic footprint of a web shell. Pull the file and scan it with `detections/yara/webshell_generic.yar`.

## 5. Shadow copy and backup deletion

```spl
index=endpoint EventCode=1
  (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*shadowcopy*delete*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*recoveryenabled*no*")
| table _time host user ParentImage Image CommandLine
```
