# ============================================================
# EDIT BEFORE RUNNING — accounts to KEEP enabled
# Everyone NOT in this list will be disabled
# Always include your admin account and any scored service accounts
# ============================================================
$AcceptedUsers = @(
    "administrator",
    "ccdc_admin"      # add competition accounts here
)
# ============================================================

$acclist = $AcceptedUsers | ForEach-Object { $_.Trim().ToLower() }
$acc     = Get-LocalUser | Select-Object -ExpandProperty Name | ForEach-Object { $_.Trim().ToLower() }

$disabled = @()
foreach ($user in $acc) {
    if ($user -notin $acclist) {
        net user $user /active:no
        $disabled += $user
    }
}

Write-Host "[DONE] Disabled $($disabled.Count) account(s): $($disabled -join ', ')"
Write-Host "Kept active: $($acclist -join ', ')"
