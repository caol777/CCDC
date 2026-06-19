# PersistHunt.ps1
# CCDC Windows Persistence / C2 Beacon Hunter
# Checks all common red team persistence and C2 locations:
#   Registry run keys, scheduled tasks, services, WMI subscriptions,
#   startup folders, named pipes, suspicious processes, C2 ports,
#   Defender exclusions, DLL hijacking paths, PowerShell history

$Error.Clear()
$ErrorActionPreference = "SilentlyContinue"

$LogFile = "C:\Windows\Temp\persist_hunt_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Bad  { param($m) $o = "[BAD]  $m"; Write-Host $o -ForegroundColor Red;    Add-Content $LogFile $o }
function Warn { param($m) $o = "[WARN] $m"; Write-Host $o -ForegroundColor Yellow; Add-Content $LogFile $o }
function Good { param($m) $o = "[OK]   $m"; Write-Host $o -ForegroundColor Green;  Add-Content $LogFile $o }
function Sep  { $o = "="*60;                Write-Host $o;                          Add-Content $LogFile $o }

Sep; Add-Content $LogFile "CCDC WINDOWS PERSISTENCE HUNTER - $(Get-Date) - $env:ComputerName"; Sep

# -----------------------------------------------------------------------
# 1. REGISTRY RUN KEYS (most common persistence)
# -----------------------------------------------------------------------
Sep; Write-Host "1. REGISTRY RUN KEYS" -ForegroundColor Cyan

$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
    "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($key in $RunKeys) {
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $val = $_.Value
            if ($val -match "temp|appdata|public|\\users\\[^\\]+\\downloads|powershell.*-enc|cmd.*\/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin" ) {
                Bad "RunKey [$key] $($_.Name) = $val"
            } else {
                Warn "RunKey [$key] $($_.Name) = $val"
            }
        }
    }
}

# -----------------------------------------------------------------------
# 2. SCHEDULED TASKS
# -----------------------------------------------------------------------
Sep; Write-Host "2. SCHEDULED TASKS" -ForegroundColor Cyan

Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
    $task = $_
    $action = ($task.Actions | Select-Object -First 1)
    $exe = $action.Execute
    $args = $action.Arguments

    if ($exe -match "temp|appdata\\roaming|\\public\\|powershell.*-enc|mshta|wscript|cscript|certutil|bitsadmin|rundll32" -or
        $args -match "temp|appdata\\roaming|\\public\\|-enc|-nop.*bypass|downloadstring|iex\b") {
        Bad "Task: $($task.TaskName) | Exec: $exe $args"
    } elseif ($exe -notmatch "^C:\\Windows\\|^C:\\Program Files") {
        Warn "Task (non-standard path): $($task.TaskName) | Exec: $exe $args"
    }
}

# -----------------------------------------------------------------------
# 3. SERVICES RUNNING FROM SUSPICIOUS PATHS
# -----------------------------------------------------------------------
Sep; Write-Host "3. SUSPICIOUS SERVICES" -ForegroundColor Cyan

Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $_.PathName
    if ($path -match "temp|appdata|\\users\\[^\\]+\\(downloads|desktop|documents)|\\public\\" ) {
        Bad "Service: $($_.Name) | Path: $path | State: $($_.State)"
    } elseif ($_.StartName -notin @("LocalSystem","LocalService","NetworkService","NT AUTHORITY\LocalService","NT AUTHORITY\NetworkService","NT AUTHORITY\SYSTEM") -and $_.StartName -ne $null) {
        Warn "Service running as non-standard account: $($_.Name) | RunAs: $($_.StartName) | Path: $path"
    }
}

# -----------------------------------------------------------------------
# 4. WMI EVENT SUBSCRIPTIONS (very common C2 persistence — often missed)
# -----------------------------------------------------------------------
Sep; Write-Host "4. WMI EVENT SUBSCRIPTIONS" -ForegroundColor Cyan

$wmiFilters     = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$wmiConsumers   = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
$wmiBindings    = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

if ($wmiFilters)   { $wmiFilters   | ForEach-Object { Bad "WMI Filter: $($_.Name) — Query: $($_.Query)" } }
if ($wmiConsumers) { $wmiConsumers | ForEach-Object { Bad "WMI Consumer: $($_.Name) — $($_.CommandLineTemplate)$($_.ScriptText)" } }
if ($wmiBindings)  { $wmiBindings  | ForEach-Object { Bad "WMI Binding: Filter=$($_.Filter) Consumer=$($_.Consumer)" } }
if (!$wmiFilters -and !$wmiConsumers -and !$wmiBindings) { Good "No WMI subscriptions found" }

# -----------------------------------------------------------------------
# 5. STARTUP FOLDERS
# -----------------------------------------------------------------------
Sep; Write-Host "5. STARTUP FOLDERS" -ForegroundColor Cyan

$startupPaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($p in $startupPaths) {
    if (Test-Path $p) {
        $items = Get-ChildItem $p -ErrorAction SilentlyContinue
        if ($items) {
            $items | ForEach-Object { Bad "Startup folder item: $($_.FullName)" }
        } else {
            Good "Startup folder empty: $p"
        }
    }
}

# -----------------------------------------------------------------------
# 6. SUSPICIOUS PROCESSES (running from temp / deleted path / C2 names)
# -----------------------------------------------------------------------
Sep; Write-Host "6. SUSPICIOUS PROCESSES" -ForegroundColor Cyan

$C2Names = @("beacon","implant","sliver","apollo","mythic","havoc","brute","ratel","realm","ninja","agent","stager","shell")
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = $_
    $path = ""
    try { $path = $proc.MainModule.FileName } catch {}
    
    foreach ($c2 in $C2Names) {
        if ($proc.Name -match $c2) { Bad "Possible C2 process: $($proc.Name) PID=$($proc.Id) Path=$path" }
    }

    if ($path -match "\\temp\\|\\appdata\\roaming\\|\\public\\|\\users\\[^\\]+\\downloads\\" ) {
        Bad "Process from suspicious path: $($proc.Name) PID=$($proc.Id) Path=$path"
    }
}

# -----------------------------------------------------------------------
# 7. ESTABLISHED CONNECTIONS TO COMMON C2 PORTS
# -----------------------------------------------------------------------
Sep; Write-Host "7. NETWORK CONNECTIONS" -ForegroundColor Cyan

$C2Ports = @(4444,5555,6666,7777,8443,9001,9002,1337,31337,50050,60000,4545,3333,2222)
$KnownProcs = @("svchost","lsass","wininit","services","smss","csrss","winlogon","explorer","MsMpEng")

$netConns = netstat -anop TCP 2>$null | Where-Object { $_ -match "ESTABLISHED" }
foreach ($conn in $netConns) {
    $cols = ($conn -split '\s+') | Where-Object { $_ -ne '' }
    if ($cols.Count -ge 5) {
        $remotePort = $cols[3].Split(":")[-1]
        $pid_ = $cols[-1]
        if ($C2Ports -contains [int]$remotePort) {
            $procName = try { (Get-Process -Id $pid_).Name } catch { "unknown" }
            Bad "Outbound to C2 port $remotePort | PID=$pid_ ($procName) | $($cols[3])"
        }
    }
}

# Flag any process with established outbound that isn't a known Windows process
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
    $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" -and $_.OwningProcess -ne 4
} | ForEach-Object {
    $procName = try { (Get-Process -Id $_.OwningProcess).Name } catch { "unknown" }
    if ($KnownProcs -notcontains $procName) {
        Warn "Outbound: $procName PID=$($_.OwningProcess) → $($_.RemoteAddress):$($_.RemotePort)"
    }
}

# -----------------------------------------------------------------------
# 8. NAMED PIPES (C2 frameworks use these — Cobalt Strike, Sliver, Mythic)
# -----------------------------------------------------------------------
Sep; Write-Host "8. NAMED PIPES" -ForegroundColor Cyan

$suspiciousPipes = @("msagent_","postex_","mojo.","chrome.","spoolss","netsvcs","ntsvcs","svcctl","samr","wkssvc","atsvc","epmapper","eventlog","browser","protected_storage","lsass")
try {
    $pipes = [System.IO.Directory]::GetFiles("\\.\\pipe\\") 2>$null
} catch {
    $pipes = Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
}
if ($pipes) {
    $pipes | ForEach-Object {
        $pipeName = $_ -replace '.*\\pipe\\', ''
        foreach ($sp in $suspiciousPipes) {
            if ($pipeName -match $sp) {
                Warn "Suspicious named pipe: $pipeName"
            }
        }
    }
}

# -----------------------------------------------------------------------
# 9. DEFENDER EXCLUSIONS (red teams add these to hide malware)
# -----------------------------------------------------------------------
Sep; Write-Host "9. DEFENDER EXCLUSIONS" -ForegroundColor Cyan

$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref) {
    if ($mpPref.ExclusionPath)      { $mpPref.ExclusionPath      | ForEach-Object { Bad "Defender path exclusion: $_" } }
    if ($mpPref.ExclusionProcess)   { $mpPref.ExclusionProcess   | ForEach-Object { Bad "Defender process exclusion: $_" } }
    if ($mpPref.ExclusionExtension) { $mpPref.ExclusionExtension | ForEach-Object { Bad "Defender extension exclusion: $_" } }
    if (!$mpPref.ExclusionPath -and !$mpPref.ExclusionProcess -and !$mpPref.ExclusionExtension) { Good "No Defender exclusions found" }
    if ($mpPref.DisableRealtimeMonitoring) { Bad "Defender real-time monitoring is DISABLED" }
}

# -----------------------------------------------------------------------
# 10. POWERSHELL HISTORY (look for download cradles, encoded commands)
# -----------------------------------------------------------------------
Sep; Write-Host "10. POWERSHELL HISTORY" -ForegroundColor Cyan

$histPaths = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
foreach ($h in $histPaths) {
    $suspicious = Get-Content $h.FullName -ErrorAction SilentlyContinue | Where-Object {
        $_ -match "DownloadString|DownloadFile|IEX|Invoke-Expression|FromBase64|-enc |-EncodedCommand|WebClient|Net\.WebClient|bitsadmin|certutil.*-decode|mshta"
    }
    if ($suspicious) {
        Bad "Suspicious PS history in $($h.FullName):"
        $suspicious | ForEach-Object { Warn "  $_" }
    }
}

# -----------------------------------------------------------------------
# 11. RECENTLY MODIFIED WINDOWS SYSTEM FILES
# -----------------------------------------------------------------------
Sep; Write-Host "11. RECENTLY MODIFIED SYSTEM FILES (last 2 hours)" -ForegroundColor Cyan

$since = (Get-Date).AddHours(-2)
$sysPaths = @("C:\Windows\System32","C:\Windows\SysWOW64")
foreach ($sp in $sysPaths) {
    Get-ChildItem $sp -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -gt $since -and $_.Extension -in @(".exe",".dll",".sys")
    } | ForEach-Object {
        Bad "Recently modified system file: $($_.FullName) | Modified: $($_.LastWriteTime)"
    }
}

# -----------------------------------------------------------------------
# 12. LOLBAS / LIVING-OFF-THE-LAND PROCESSES (common C2 execution)
# -----------------------------------------------------------------------
Sep; Write-Host "12. SUSPICIOUS LOLBAS PROCESSES" -ForegroundColor Cyan

$lolbas = @("mshta","wscript","cscript","regsvr32","certutil","bitsadmin","msiexec","wmic","rundll32","forfiles","pcalua","syncappvpublishingserver")
foreach ($lb in $lolbas) {
    $procs = Get-Process -Name $lb -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | ForEach-Object {
            Bad "LOLBAS process running: $($_.Name) PID=$($_.Id)"
        }
    }
}

# -----------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------
Sep
$badCount  = (Get-Content $LogFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "^\[BAD\]" }).Count
$warnCount = (Get-Content $LogFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "^\[WARN\]" }).Count
Write-Host "`nHUNT COMPLETE on $env:ComputerName" -ForegroundColor Cyan
Write-Host "BAD: $badCount   WARN: $warnCount" -ForegroundColor Yellow
Write-Host "Full log: $LogFile" -ForegroundColor Cyan
Sep
