# 16-Passwords.ps1 - bulk credential rotation (the #1 CCDC action).
# CPP Usr.ps1 + bruhpdate.ps1 parity: rotate EVERY enabled local user's password
# to a fresh random value on non-DCs, writing a CSV the team can read.
# DCs: opt-in -DomainUsers mode (krbtgt is ALWAYS excluded - a double krbtgt
# reset broke CPP's whole domain in 2023; rotate it once, manually, deliberately).
#
# RULES (2025 NCCDC packet): one mass reset per system without approval;
# passwords max 24 chars; scored-service user password changes must be reported
# as CSVs to Ops. This module produces exactly that CSV.
#
# WARNING: any service configured to run as a rotated user will break - check
# Invoke-Inventory.ps1 output ("services of interest" StartName column) first.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$ConfirmRotation,     # required; mass resets must be deliberate (rules!)
    [switch]$DomainUsers,         # DCs only: rotate all enabled domain users (excl. krbtgt)
    # Well-known service identities stay excluded: rotating an account a service
    # runs under breaks that service at next start (lab-proven: cloudbase-init).
    [string[]]$Exclude = @('cloudbase-init', 'DefaultAccount', 'WDAGUtilityAccount'),
    [int]$Length = 20             # CCDC cap is 24
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'passwords' -BackupRoot $BackupRoot
try {
    if (-not $ConfirmRotation) {
        Write-Log 'Passwords SKIPPED: mass rotation is deliberate (rules allow ONE without approval).' 'WARN'
        Write-Log 'Re-run with -ConfirmRotation after checking inventory for service accounts.' 'WARN'
        exit 0
    }
    if ($Length -gt 24) { throw "CCDC caps passwords at 24 characters (asked for $Length)." }
    $csvPath = Join-Path $BackupDir 'rotated-passwords.csv'
    $rows = @()
    $isDC = Test-IsDomainController

    if ($isDC -and -not $DomainUsers) {
        Write-Log 'DC detected and -DomainUsers not set - nothing rotated.' 'WARN'
        Write-Log 'Domain rotation is a big hammer: services running as domain users break.' 'WARN'
        Write-Log 'Run with -DomainUsers when ready (krbtgt always excluded).' 'WARN'
        exit 0
    }

    if ($isDC) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $users = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName |
            Where-Object { $_.SamAccountName -ne 'krbtgt' -and $Exclude -notcontains $_.SamAccountName }
        foreach ($u in $users) {
            $password = New-RandomPassword -Length $Length
            $secure = ConvertTo-SecureString $password -AsPlainText -Force
            if ($PSCmdlet.ShouldProcess("domain user '$($u.SamAccountName)'", 'reset password')) {
                Set-ADAccountPassword -Identity $u.SamAccountName -NewPassword $secure -Reset
                $rows += [pscustomobject]@{ Username = $u.SamAccountName; Password = $password }
                Write-Log "Domain user '$($u.SamAccountName)' password rotated" 'CHANGE'
            }
        }
    }
    else {
        $users = Get-LocalUser | Where-Object { $_.Enabled -and $Exclude -notcontains $_.Name }
        foreach ($u in $users) {
            $password = New-RandomPassword -Length $Length
            $secure = ConvertTo-SecureString $password -AsPlainText -Force
            if ($PSCmdlet.ShouldProcess("local user '$($u.Name)'", 'reset password')) {
                Set-LocalUser -Name $u.Name -Password $secure
                $rows += [pscustomobject]@{ Username = $u.Name; Password = $password }
                Write-Log "Local user '$($u.Name)' password rotated" 'CHANGE'
            }
        }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
        # Restrict the CSV to administrators; it contains every credential.
        & icacls.exe $csvPath /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
        Add-ChangeRecord -BackupDir $BackupDir -Module 'Passwords' -Action 'BulkRotation' `
            -Target 'local users' -NewValue "$($rows.Count) rotated (values in rotated-passwords.csv)"
        Write-Log "Rotated $($rows.Count) password(s). CSV (admins-only ACL): $csvPath" 'CHANGE'
        Write-Log 'Passwords are NOT restorable to old values by design - old creds are burned.' 'WARN'
        Write-Log 'Remember the rules: ONE mass reset without approval; report scored-service passwords to Ops.' 'WARN'
    }
    else {
        Write-Log 'No users selected for rotation.' 'WARN'
    }
    Write-Log 'Passwords module complete.' 'OK'
}
catch {
    Write-Log "Passwords module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
