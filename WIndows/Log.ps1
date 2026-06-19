# Log.ps1
# CCDC Windows Logging Setup
# Enables comprehensive logging so you can see what the red team is doing:
#   - All auditpol categories (success + failure)
#   - PowerShell script block, transcription, and module logging
#   - Process creation with full command line
#   - IIS logging
#   - SMB signing (prevents relay attacks)
#   - Sysmon (if already installed in C:\Windows\System32)

$Error.Clear()
$ErrorActionPreference = "Continue"

function Log-Step {
    param($msg)
    Write-Host $msg -ForegroundColor Cyan
}

Log-Step "[$env:ComputerName] Enabling all audit policy categories..."
auditpol /set /category:* /success:enable /failure:enable | Out-Null
Log-Step "[$env:ComputerName] Auditpol set"

Log-Step "[$env:ComputerName] Enabling process creation command-line logging..."
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] Process command-line logging enabled"

Log-Step "[$env:ComputerName] Enabling PowerShell script block logging..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] PowerShell script block logging enabled"

Log-Step "[$env:ComputerName] Enabling PowerShell module logging..."
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f | Out-Null
Log-Step "[$env:ComputerName] PowerShell module logging enabled"

Log-Step "[$env:ComputerName] Enabling PowerShell transcription logging..."
$psLogDir = "$env:SystemDrive\PSLogs"
if (!(Test-Path $psLogDir)) { New-Item -ItemType Directory -Path $psLogDir -Force | Out-Null }
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d $psLogDir /f | Out-Null
Log-Step "[$env:ComputerName] PowerShell transcription enabled → $psLogDir"

Log-Step "[$env:ComputerName] Enabling IIS logging (if present)..."
try {
    C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False | Out-Null
    Log-Step "[$env:ComputerName] IIS logging enabled"
} catch {
    Log-Step "[$env:ComputerName] IIS not found, skipping"
}

Log-Step "[$env:ComputerName] Enforcing SMB signing..."
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] SMB signing enforced (both client and server)"

Log-Step "[$env:ComputerName] Locking down non-system SMB shares to Read-only..."
$ExemptShares = @("NETLOGON","SYSVOL","ADMIN`$","C`$","IPC`$")
foreach ($Share in Get-SmbShare -ErrorAction SilentlyContinue) {
    if ($ExemptShares -contains $Share.Name) { continue }
    foreach ($Entry in (Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue)) {
        Grant-SmbShareAccess -Name $Share.Name -AccountName $Entry.AccountName -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Log-Step "[$env:ComputerName] Share $($Share.Name) set to Read-only"
}

Log-Step "[$env:ComputerName] Starting Sysmon (if installed)..."
if (Test-Path "C:\Windows\System32\Sysmon64.exe") {
    C:\Windows\System32\Sysmon64.exe -accepteula -i 2>$null
    Log-Step "[$env:ComputerName] Sysmon64 started"
} elseif (Test-Path "C:\Windows\System32\Sysmon.exe") {
    C:\Windows\System32\Sysmon.exe -accepteula -i 2>$null
    Log-Step "[$env:ComputerName] Sysmon32 started"
} else {
    Log-Step "[$env:ComputerName] Sysmon not found — download from Sysinternals and place in System32 to enable"
}

Write-Host "`n[DONE] Logging setup complete on $env:ComputerName" -ForegroundColor Green
Write-Host "       PS Transcription logs: $psLogDir" -ForegroundColor Green
Write-Host "       Event logs: Event Viewer → Security, PowerShell/Operational" -ForegroundColor Green

if ($Error[0]) {
    Write-Host "`n=== ERRORS ===" -ForegroundColor Red
    $Error | ForEach-Object { Write-Host $_ -ForegroundColor Red }
}
