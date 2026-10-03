# 05-Audit.ps1 - core advanced audit policy.
# Without these events you cannot write incident reports, and at CCDC a good
# incident report RECOVERS red-team penalty points. BYU enabled ~58 subcategories;
# this is the lean core: logons, process creation (with command lines), account
# and group changes, policy changes, sensitive privilege use.
# -Full matches CPP Log.ps1: every category, success and failure (loud).
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$Full
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'audit' -BackupRoot $BackupRoot

# Subcategories worth the noise in a CCDC defensive posture.
# Names are the auditpol CLI subcategory names (as shown by `auditpol /get`),
# NOT the GPO display names: 'Logon', not 'Audit logon'.
$auditSettings = @(
    @{ Subcategory = 'Logon';                   Success = $true;  Failure = $true  },
    @{ Subcategory = 'Logoff';                  Success = $true;  Failure = $false },
    @{ Subcategory = 'Account Lockout';         Success = $true;  Failure = $true  },
    @{ Subcategory = 'Special Logon';           Success = $true;  Failure = $false },
    @{ Subcategory = 'User Account Management'; Success = $true;  Failure = $true  },
    @{ Subcategory = 'Security Group Management'; Success = $true; Failure = $true },
    @{ Subcategory = 'Process Creation';        Success = $true;  Failure = $false },
    @{ Subcategory = 'Audit Policy Change';     Success = $true;  Failure = $true  },
    @{ Subcategory = 'Sensitive Privilege Use'; Success = $false; Failure = $true  }
)

try {
    if ($Full) {
        # CPP Log.ps1 parity: everything, success and failure. Loud but complete.
        if ($PSCmdlet.ShouldProcess('audit policy', 'enable ALL categories (success+failure)')) {
            & auditpol.exe '/set' '/category:*' '/success:enable' '/failure:enable'
            if ($LASTEXITCODE -eq 0) {
                Write-Log 'Audit policy: ALL categories success+failure enabled' 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Audit' -Action 'SetAllCategories' `
                    -Target '*' -NewValue 'success+failure'
            }
            else { Write-Log 'auditpol /category:* failed' 'FAIL'; $exitCode = 1 }
        }
    }
    foreach ($s in $auditSettings) {
        $successFlag = if ($s.Success) { 'enable' } else { 'disable' }
        $failureFlag = if ($s.Failure) { 'enable' } else { 'disable' }
        $target = "audit subcategory '$($s.Subcategory)'"
        if ($PSCmdlet.ShouldProcess($target, "set success=$successFlag failure=$failureFlag")) {
            & auditpol.exe /set "/subcategory:$($s.Subcategory)" "/success:$successFlag" "/failure:$failureFlag"
            if ($LASTEXITCODE -eq 0) {
                Write-Log "$($s.Subcategory): success=$(if ($s.Success) {'on'} else {'off'}) failure=$(if ($s.Failure) {'on'} else {'off'})" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Audit' -Action 'SetAuditSubcategory' `
                    -Target $s.Subcategory -NewValue "success=$($s.Success) failure=$($s.Failure)"
            }
            else {
                Write-Log "auditpol failed setting $($s.Subcategory)" 'FAIL'
                $exitCode = 1
            }
        }
    }

    # Record command lines in process-creation events (4688) - the single most
    # valuable forensic field when hunting the red team's tooling.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'Audit ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 `
        -Module 'Audit' -BackupDir $BackupDir

    # Force advanced (subcategory) audit policy to win over the legacy 9-setting
    # policy - without this, a domain GPO using legacy settings silently overrides
    # everything set above.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 `
        -Module 'Audit' -BackupDir $BackupDir

    # ---------- verify ----------
    Write-Log '--- verify ---'
    $all = (& auditpol.exe /get /category:* | Out-String) -replace '\s+', ' '
    foreach ($sub in 'Logon', 'Process Creation', 'User Account Management', 'Security Group Management', 'Sensitive Privilege Use') {
        if ($all -match [regex]::Escape($sub)) { Write-Log "  $sub present in audit policy" 'OK' }
        else { Write-Log "  $sub MISSING from audit policy" 'WARN' }
    }
    Write-Log 'Audit module complete.' 'OK'
}
catch {
    Write-Log "Audit module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
