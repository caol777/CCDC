param(
    [String]$UserPassword   = "",   # password for all regular users (or "YOLO" to auto-generate)
    [String]$AdminPassword  = "",   # password for users in $AdminUsers
    [String]$AdminUsers     = "",   # comma-separated list of admin accounts to give AdminPassword
    [String]$Exclude        = ""    # comma-separated accounts to skip entirely
)

# Usage:
#   .\ADuserPassChange.ps1 -UserPassword "Summer2024!" -AdminPassword "Admin@2024!" -AdminUsers "bob,alice" -Exclude "svc_backup"
#   .\ADuserPassChange.ps1 -UserPassword "YOLO" -AdminPassword "Admin@2024!"

$ErrorActionPreference = "SilentlyContinue"

Add-Type -AssemblyName System.Web
function Get-Password {
    do { $p = [System.Web.Security.Membership]::GeneratePassword(14, 4) }
    while ($p -match '[,;:|iIlLoO0]')
    return $p + "1!"
}

if ($UserPassword -eq "" -and $AdminPassword -eq "") {
    Write-Host "Usage: .\ADuserPassChange.ps1 -UserPassword <pass> -AdminPassword <adminpass> [-AdminUsers user1,user2] [-Exclude user3]"
    Write-Host "       Use -UserPassword YOLO to auto-generate a random password."
    exit 1
}

if ($UserPassword -eq "YOLO") { $UserPassword = Get-Password }
if ($AdminPassword -eq "")    { $AdminPassword = $UserPassword }

$AdminList  = $AdminUsers -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }
$ExcludeList = $Exclude   -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }

$SystemSkip = @("krbtgt","defaultaccount","guest","wdagutilityaccount")
$AlwaysSkip = @("seccdc","blackteam")

Import-Module ActiveDirectory
$AllUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

$results = @()
$changed = 0; $skipped = 0; $failed = 0

foreach ($user in $AllUsers) {
    $uLower = $user.ToLower()

    if ($SystemSkip -contains $uLower) {
        Write-Host "[SKIP] $user (system account)" -ForegroundColor Gray
        $skipped++; continue
    }
    if ($ExcludeList -contains $uLower) {
        Write-Host "[SKIP] $user (excluded)" -ForegroundColor Gray
        $skipped++; continue
    }
    if ($AlwaysSkip | Where-Object { $uLower -match $_ }) {
        Write-Host "[SKIP] $user (protected)" -ForegroundColor Gray
        $skipped++; continue
    }

    $pass = if ($AdminList -contains $uLower) { $AdminPassword } else { $UserPassword }

    try {
        Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText $pass -Force) -Reset -ErrorAction Stop
        Write-Host "[OK]   $user" -ForegroundColor Green
        $results += [PSCustomObject]@{ User = $user; Password = $pass }
        $changed++
    } catch {
        Write-Host "[FAIL] $user : $_" -ForegroundColor Red
        $failed++
    }
}

$outFile = "C:\Windows\Temp\ad_passwords_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $outFile -NoTypeInformation
Write-Host "`n=== SUMMARY ===" -ForegroundColor Yellow
Write-Host "Changed: $changed  Skipped: $skipped  Failed: $failed"
Write-Host "Saved to: $outFile"
$results | Format-Table -AutoSize
