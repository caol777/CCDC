# ADHardening.ps1
# CCDC AD/Windows Hardening — headless, no GUI, runs remotely
# Run as Administrator on a Domain Controller or domain-joined machine
#
# Applies:
#   - SMBv1 disable, SMBv2 keep, LDAP signing
#   - PTH mitigations (LM hash, NTLMv2, WDigest, LSA PPL)
#   - Full Defender ASR rules + remove all exclusions
#   - PrintNightmare, Zerologon, noPac registry fixes
#   - UAC hardening, BITS lockdown
#   - Audit policy, Guest disable, WinRM disable
#   - Disable Domain Admin accounts not on allowlist

$ErrorActionPreference = "Continue"
$Error.Clear()

$logPath = "C:\SecurityConfigLog.txt"
if (!(Test-Path $logPath)) { New-Item -Path $logPath -ItemType File | Out-Null }

function Write-Log {
    param($message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$ts - $message"
}

function Log-Step {
    param($msg)
    Write-Host $msg -ForegroundColor Cyan
    Write-Log $msg
}

$DC = $false
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'" -ErrorAction SilentlyContinue) {
    $DC = $true
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Log-Step "[$env:ComputerName] Domain Controller detected"
} else {
    Log-Step "[$env:ComputerName] Member server / workstation"
}

# ---- SMB ----
Log-Step "[$env:ComputerName] Disabling SMBv1..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
Set-SmbServerConfiguration -EnableSMB2Protocol $true  -Force | Out-Null
Log-Step "[$env:ComputerName] SMBv1 disabled, SMBv2 kept"

# ---- PTH Mitigations ----
Log-Step "[$env:ComputerName] Applying PTH mitigations..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
Log-Step "[$env:ComputerName] PTH mitigations applied (LM hash disabled, NTLMv2 only, WDigest off, LSA PPL on)"

# ---- LDAP Signing ----
Log-Step "[$env:ComputerName] Enforcing LDAP signing..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
Log-Step "[$env:ComputerName] LDAP signing enforced"

# ---- Defender ----
Log-Step "[$env:ComputerName] Hardening Windows Defender..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 1 /f | Out-Null
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

try {
    $asrRules = @(
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Block Office code injection
        "3B576869-A4EC-4529-8536-B80A7769E899", # Block Office executable content
        "D4F940AB-401B-4EfC-AADC-AD5F3C50688A", # Block Office child processes
        "D3E037E1-3EB8-44C8-A917-57927947596D", # Block JS/VBS launching downloads
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block obfuscated scripts
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Block email executable content
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", # Block Office macro Win32 API
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C", # Block PSExec/WMI process creation
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", # Block untrusted USB processes
        "C1DB55AB-C21A-4637-BB3F-A12568109D35", # Ransomware protection
        "01443614-CD74-433A-B99E-2ECDC07BFC25", # Block executables unless trusted
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", # Block LSASS credential stealing
        "26190899-1602-49E8-8B27-EB1D0A1CE869", # Block Office comms child processes
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", # Block Adobe Reader child processes
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"  # Block WMI event subscription persistence
    )
    Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRules -AttackSurfaceReductionRules_Actions (,$asrRules | ForEach-Object { "Enabled" }) | Out-Null
    Log-Step "[$env:ComputerName] ASR rules enabled"
} catch {
    Log-Step "[$env:ComputerName] ASR rules skipped (older Defender)"
}

foreach ($ex in (Get-MpPreference).ExclusionExtension)  { Remove-MpPreference -ExclusionExtension $ex | Out-Null }
foreach ($ex in (Get-MpPreference).ExclusionIpAddress)  { Remove-MpPreference -ExclusionIpAddress $ex | Out-Null }
foreach ($ex in (Get-MpPreference).ExclusionPath)       { Remove-MpPreference -ExclusionPath $ex | Out-Null }
foreach ($ex in (Get-MpPreference).ExclusionProcess)    { Remove-MpPreference -ExclusionProcess $ex | Out-Null }
Log-Step "[$env:ComputerName] All Defender exclusions removed"

# ---- PrintNightmare ----
Log-Step "[$env:ComputerName] Applying PrintNightmare mitigations..."
net stop spooler | Out-Null
sc.exe config spooler start=disabled | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /f 2>$null | Out-Null
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /f 2>$null | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] PrintNightmare mitigated (spooler disabled)"

# ---- DC-specific: Zerologon + noPac ----
if ($DC) {
    Log-Step "[$env:ComputerName] Applying DC-specific mitigations (Zerologon, noPac)..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota" = "0"} -ErrorAction SilentlyContinue | Out-Null
    Log-Step "[$env:ComputerName] Zerologon patched, MachineAccountQuota=0 (noPac fixed)"
}

# ---- UAC ----
Log-Step "[$env:ComputerName] Hardening UAC..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] UAC hardened"

# ---- BITS lockdown ----
Log-Step "[$env:ComputerName] Locking down BITS..."
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
Log-Step "[$env:ComputerName] BITS locked down"

# ---- Audit Policy ----
Log-Step "[$env:ComputerName] Configuring audit policy..."
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
Log-Step "[$env:ComputerName] Audit policy configured"

# ---- Misc ----
Log-Step "[$env:ComputerName] Misc hardening..."
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue | Out-Null
Disable-PSRemoting -Force -ErrorAction SilentlyContinue | Out-Null
Set-NetFirewallProfile -All -Enabled True | Out-Null
Log-Step "[$env:ComputerName] Guest disabled, WinRM disabled, Firewall enabled"

# ---- Disable unlisted Domain Admins ----
# Update $allowedAdmins for each competition to include your team's accounts
$allowedAdmins = @("Administrator") | ForEach-Object { $_.Trim().ToLower() }

if ($DC) {
    Log-Step "[$env:ComputerName] Auditing Domain Admins group..."
    $allAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty SamAccountName

    foreach ($acc in $allAdmins) {
        if ($allowedAdmins -notcontains $acc.ToLower()) {
            Disable-ADAccount -Identity $acc -ErrorAction SilentlyContinue
            Write-Host "[!] Disabled unexpected Domain Admin: $acc" -ForegroundColor Yellow
            Write-Log "Disabled unexpected Domain Admin: $acc"
        }
    }
}

# ---- Done ----
Write-Host "`n[DONE] Hardening complete on $env:ComputerName" -ForegroundColor Green
Write-Log "Hardening complete on $env:ComputerName"

if ($Error[0]) {
    Write-Host "`n=== ERRORS ===" -ForegroundColor Red
    $Error | ForEach-Object { Write-Host $_ -ForegroundColor Red }
}
