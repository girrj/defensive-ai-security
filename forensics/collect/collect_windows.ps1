<#
.SYNOPSIS
    Read-only live-response collection for Windows.

.DESCRIPTION
    Collects volatile state first (processes, network, sessions, DNS cache),
    then persistence (Run keys, services, scheduled tasks, WMI subscriptions,
    startup folders), accounts, recent executables in user-writable paths,
    and event logs. It does not change configuration, stop processes, or
    install anything. Output goes to one folder plus a ZIP and a SHA-256
    manifest.

    Run from an elevated PowerShell for complete results.

.PARAMETER OutputPath
    Base directory for output. Use external media or a network share where
    possible to minimize writes to the evidence disk.

.PARAMETER CaseId
    Case identifier, used in the output folder name.

.PARAMETER Days
    Look-back window for recent files and event logs. Default 14.

.PARAMETER NoEventLogs
    Skip exporting .evtx files (faster and smaller).

.EXAMPLE
    .\collect_windows.ps1 -OutputPath E:\IR -CaseId IR-2026-001

.NOTES
    Author: girrj   License: MIT   Requires: Windows PowerShell 5.1+ or PowerShell 7+
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [string]$CaseId = "case",
    [int]$Days = 14,
    [switch]$NoEventLogs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$hostName = $env:COMPUTERNAME
$stamp    = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$out      = Join-Path $OutputPath "$($CaseId)_$($hostName)_$stamp"
$dirs     = "volatile", "persistence", "accounts", "logs", "timeline", "system"
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $out $d) | Out-Null }
$logFile  = Join-Path $out "collection.log"

function Write-Log([string]$msg) {
    "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $msg | Add-Content -Path $logFile -Encoding UTF8
}

# Run a script block, save its output as CSV (objects) or text, and never abort the collection.
function Save-Output {
    param([string]$Name, [scriptblock]$Script, [switch]$Text)
    $path = Join-Path $out $Name
    Write-Log "RUN $Name"
    try {
        $result = & $Script
        if ($Text) { $result | Out-File -FilePath $path -Encoding UTF8 -Width 4096 }
        else       { $result | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 }
    } catch {
        Write-Log "ERROR $Name : $($_.Exception.Message)"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Log "START case=$CaseId host=$hostName user=$env:USERDOMAIN\$env:USERNAME admin=$isAdmin ps=$($PSVersionTable.PSVersion)"
if (-not $isAdmin) { Write-Log "WARNING not elevated; output will be partial" }

# --- 1. Volatile: processes ---------------------------------------------------
Save-Output "volatile\processes.csv" {
    $owners = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $o = $null
        try { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop } catch { }
        $owner = if ($o -and $o.User) { "$($o.Domain)\$($o.User)" } else { "" }
        $hash = $null
        if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
            try { $hash = (Get-FileHash -LiteralPath $_.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        }
        [pscustomobject]@{
            ProcessId       = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            Name            = $_.Name
            Owner           = $owner
            CreationDate    = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString("o") } else { "" }
            ExecutablePath  = $_.ExecutablePath
            SHA256          = $hash
            CommandLine     = $_.CommandLine
        }
    }
}

# --- 2. Volatile: network -----------------------------------------------------
Save-Output "volatile\tcp_connections.csv" {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{n = "ProcessName"; e = { $procs[[int]$_.OwningProcess] } }, CreationTime
}
Save-Output "volatile\udp_endpoints.csv" { Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime }
Save-Output "volatile\dns_cache.csv"     { Get-DnsClientCache | Select-Object Entry, Name, Type, Data, TimeToLive }
Save-Output "volatile\arp.csv"           { Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State }
Save-Output "volatile\routes.csv"        { Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric }
Save-Output "volatile\ipconfig.txt"      { ipconfig /all } -Text
Save-Output "volatile\smb_sessions.csv"  { Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists }
Save-Output "volatile\smb_shares.csv"    { Get-SmbShare | Select-Object Name, Path, Description }
Save-Output "volatile\firewall_profiles.csv" { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName }

# --- 3. Volatile: sessions ------------------------------------------------------
Save-Output "volatile\logon_sessions.txt" { quser 2>&1 } -Text
Save-Output "volatile\net_sessions.txt"   { net session 2>&1 } -Text

# --- 4. System ----------------------------------------------------------------------
Save-Output "system\computer.csv" {
    $os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Host = $hostName; Caption = $os.Caption; Version = $os.Version; Build = $os.BuildNumber
        InstallDate = $os.InstallDate; LastBoot = $os.LastBootUpTime
        UtcNow = (Get-Date).ToUniversalTime().ToString("o"); TimeZone = (Get-TimeZone).Id
    }
}
Save-Output "system\hotfixes.csv"  { Get-HotFix | Select-Object HotFixID, Description, InstalledOn }
Save-Output "system\installed_software.csv" {
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.PSObject.Properties["DisplayName"] -and $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
}
Save-Output "system\defender_status.csv" { Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureLastUpdated }
Save-Output "system\defender_exclusions.csv" {
    $p = Get-MpPreference
    [pscustomobject]@{ ExclusionPath = ($p.ExclusionPath -join ";"); ExclusionProcess = ($p.ExclusionProcess -join ";"); ExclusionExtension = ($p.ExclusionExtension -join ";") }
}

# --- 5. Persistence -------------------------------------------------------------------
Save-Output "persistence\run_keys.csv" {
    $keys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    # Every loaded user hive, not just the current user.
    Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
        $keys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $keys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $keys) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $item.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value }
        }
    }
}
Save-Output "persistence\services.csv" {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId
}
Save-Output "persistence\scheduled_tasks.csv" {
    Get-ScheduledTask | ForEach-Object {
        $info = $null; try { $info = $_ | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        [pscustomobject]@{
            TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State
            Author = $_.Author; UserId = $_.Principal.UserId; RunLevel = $_.Principal.RunLevel
            Actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " | "
            LastRunTime = if ($info) { $info.LastRunTime } else { "" }
            NextRunTime = if ($info) { $info.NextRunTime } else { "" }
        }
    }
}
Save-Output "persistence\wmi_event_filters.csv"   { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name, Query, EventNamespace }
Save-Output "persistence\wmi_event_consumers.csv" { Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Select-Object Name, CommandLineTemplate, ScriptText, ScriptFileName, __CLASS }
Save-Output "persistence\wmi_bindings.csv"        { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter, Consumer }
Save-Output "persistence\startup_folders.csv" {
    $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $paths += Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    $paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ -Force -File } |
        Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
}
Save-Output "persistence\ifeo_debuggers.csv" {
    Get-ChildItem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
        ForEach-Object { $p = Get-ItemProperty $_.PSPath; if ($p.PSObject.Properties["Debugger"]) { [pscustomobject]@{ Image = $_.PSChildName; Debugger = $p.Debugger } } }
}

# --- 6. Accounts ---------------------------------------------------------------------------
Save-Output "accounts\local_users.csv"  { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description, SID }
Save-Output "accounts\local_admins.csv" { Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource, SID }

# --- 7. Recent executables in user-writable locations (metadata + hash) -------------------
Save-Output "timeline\recent_executables.csv" {
    $since = (Get-Date).AddDays(-$Days)
    $roots = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemDrive\PerfLogs")
    $ext = ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".jar", ".msi", ".lnk"
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        Get-ChildItem -Path $r -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $ext -contains $_.Extension.ToLower() -and ($_.CreationTime -gt $since -or $_.LastWriteTime -gt $since) } |
            ForEach-Object {
                $h = $null; try { $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                $sig = $null; try { $sig = (Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction Stop) } catch { }
                [pscustomobject]@{
                    FullName = $_.FullName; Length = $_.Length
                    CreationTimeUtc = $_.CreationTimeUtc; LastWriteTimeUtc = $_.LastWriteTimeUtc
                    SHA256 = $h
                    SignatureStatus = if ($sig) { $sig.Status } else { "" }
                    Signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                }
            }
    }
}

# --- 8. Event logs ---------------------------------------------------------------------------------
if (-not $NoEventLogs) {
    $channels = "Security", "System", "Application",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-TaskScheduler/Operational",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                "Microsoft-Windows-WinRM/Operational",
                "Microsoft-Windows-WMI-Activity/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-Bits-Client/Operational"
    $ms = [int64]$Days * 86400000
    foreach ($c in $channels) {
        $file = Join-Path $out ("logs\" + ($c -replace '[\\/ ]', '_') + ".evtx")
        Write-Log "RUN wevtutil epl $c (last $Days days)"
        # wevtutil export is read-only on the source log.
        & wevtutil.exe epl "$c" "$file" "/q:*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Log "SKIP $c (not present or no access, exit $LASTEXITCODE)" }
    }
}

# --- 9. Manifest and package ----------------------------------------------------------------------
Write-Log "END"
$manifest = Join-Path $out "MANIFEST.sha256"
Get-ChildItem -Path $out -Recurse -File | Where-Object { $_.FullName -ne $manifest } | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($out.Length).TrimStart('\', '/')
    "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
} | Set-Content -Path $manifest -Encoding UTF8

$zip = "$out.zip"
Compress-Archive -Path $out -DestinationPath $zip -Force
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
"$zipHash  $(Split-Path $zip -Leaf)" | Set-Content -Path "$zip.sha256" -Encoding UTF8
Write-Host "collected: $zip"
Write-Host "sha256:    $zipHash"
