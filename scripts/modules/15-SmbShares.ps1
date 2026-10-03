# 15-SmbShares.ps1 - SMB share lockdown.
# CPP SMB.ps1 + Misc.ps1 parity:
#   1. Every non-exempt share's ACEs downgraded to Read (stops drop-to-share
#      webshell/wiper patterns over writable shares).
#   2. Null-session access shut off: RestrictNullSessAccess=1 plus the decoy
#      trick from CPP's 2024 writeup - NullSessionPipes/Shares set to
#      plausible-looking FAKE names, so the real pipes/shares (netlogon, samr...)
#      lose null-session access without the registry looking obviously scrubbed.
# DANGER: if a scored service writes to a share, EXEMPT it via -ExemptShares.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [string[]]$ExemptShares = @('NETLOGON', 'SYSVOL', 'ADMIN$', 'C$', 'IPC$',
        'AdminUIContentPayload', 'EasySetupPayload', 'SCCMContentLib$', 'SMS_CPSC$',
        'SMS_DP$', 'SMS_OCM_DATACACHE', 'SMS_SITE', 'SMS_SUIAgent', 'SMS_WWW',
        'SMSPKGC$', 'SMSSIG$')
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'smbshares' -BackupRoot $BackupRoot
try {
    # ---------- downgrade non-exempt shares to read-only ----------
    foreach ($share in (Get-SmbShare)) {
        $name = $share.Name
        if ($ExemptShares -contains $name) {
            Write-Log "Share '$name' exempt" 'OK'
            continue
        }
        $aces = @(Get-SmbShareAccess -Name $name)
        $writeAces = @($aces | Where-Object { $_.AccessRight -in 'Change', 'Full' })
        if ($writeAces.Count -eq 0) {
            Write-Log "Share '$name': no write ACEs (already read-only)" 'OK'
            continue
        }
        if ($PSCmdlet.ShouldProcess("share '$name'", "downgrade $($writeAces.Count) write ACE(s) to Read")) {
            foreach ($ace in $writeAces) {
                Grant-SmbShareAccess -Name $name -AccountName $ace.AccountName -AccessRight Read -Force | Out-Null
            }
            Write-Log "Share '$name': $($writeAces.Count) ACE(s) set to Read" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'SmbShares' -Action 'ShareReadOnly' `
                -Target $name -NewValue 'Read' -OldValue (($writeAces | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', ')
        }
    }

    # ---------- null-session lockdown with decoy names ----------
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Set-RegistryValue -Path $srv -Name 'RestrictNullSessAccess' -Type DWord -Value 1 `
        -Module 'SmbShares' -BackupDir $BackupDir
    # Decoys: real default pipes are netlogon/lsarpc/samr/srvsvc/browser - none of
    # these names is real, so null-session pipe access effectively dies.
    Set-RegistryValue -Path $srv -Name 'NullSessionPipes' -Type MultiString `
        -Value @('MS-IPAMM2', 'MS-NCNBI', 'MS-WSUSAR', 'BITS-samr') -Module 'SmbShares' -BackupDir $BackupDir
    Set-RegistryValue -Path $srv -Name 'NullSessionShares' -Type MultiString `
        -Value @('MS-POLICYSTORE', 'MS-CACHE01') -Module 'SmbShares' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $now = Get-ItemProperty $srv
    Write-Log ("  RestrictNullSessAccess={0} NullSessionPipes={1}" -f `
        $now.RestrictNullSessAccess, (@($now.NullSessionPipes) -join ','))
    foreach ($share in (Get-SmbShare | Where-Object { $ExemptShares -notcontains $_.Name })) {
        $acl = (Get-SmbShareAccess -Name $share.Name) | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }
        Write-Log ("  {0}: {1}" -f $share.Name, ($acl -join ' '))
    }
    Write-Log 'SmbShares module complete.' 'OK'
}
catch {
    Write-Log "SmbShares module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
