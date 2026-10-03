# 12-DomainController.ps1 - DC-specific named-CVE hardening.
# CPP Hard.ps1 parity: Zerologon (CVE-2020-1472) full protection and
# noPac (CVE-2021-42278/42287) via MachineAccountQuota=0.
# No-op on non-DCs.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'domctrl' -BackupRoot $BackupRoot
try {
    if (-not (Test-IsDomainController)) {
        Write-Log 'Not a domain controller - nothing to do.' 'OK'
        exit 0
    }

    # ---------- Zerologon (CVE-2020-1472) ----------
    # Full protection rejects vulnerable Netlogon secure channels outright.
    $netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-RegistryValue -Path $netlogon -Name 'FullSecureChannelProtection' -Type DWord -Value 1 `
        -Module 'DomainController' -BackupDir $BackupDir
    # Remove any allowlist of vulnerable channels an attacker (or weak GPO) planted.
    $vulnList = Get-ItemProperty $netlogon -Name 'vulnerablechannelallowlist' -ErrorAction SilentlyContinue
    if ($null -ne $vulnList.vulnerablechannelallowlist) {
        if ($PSCmdlet.ShouldProcess("$netlogon\vulnerablechannelallowlist", 'remove (Zerologon bypass list)')) {
            Remove-ItemProperty -Path $netlogon -Name 'vulnerablechannelallowlist' -Force
            Write-Log 'Removed vulnerablechannelallowlist' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'DomainController' -Action 'RemoveRegistryValue' `
                -Target "$netlogon\vulnerablechannelallowlist" -OldValue $vulnList.vulnerablechannelallowlist
        }
    }
    else { Write-Log 'No vulnerablechannelallowlist present' 'OK' }

    # ---------- noPac (CVE-2021-42278/42287) ----------
    # MachineAccountQuota=0 stops non-admins from creating machine accounts
    # (the sAMAccountName spoofing primitive).
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        $maq = ($domain | Get-ADObject -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
        if ("$maq" -ne '0') {
            if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'set ms-DS-MachineAccountQuota=0')) {
                Set-ADDomain -Identity $domain.DNSRoot -Replace @{ 'ms-DS-MachineAccountQuota' = '0' }
                Write-Log "ms-DS-MachineAccountQuota set to 0 (was $maq)" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'DomainController' -Action 'SetDomainAttribute' `
                    -Target 'ms-DS-MachineAccountQuota' -NewValue '0' -OldValue "$maq"
            }
        }
        else { Write-Log 'MachineAccountQuota already 0' 'OK' }
    }
    catch { Write-Log "noPac fix failed (AD module?): $_" 'FAIL'; $exitCode = 1 }

    Write-Log '--- verify ---'
    $fscp = (Get-ItemProperty $netlogon).FullSecureChannelProtection
    Write-Log ("  FullSecureChannelProtection={0} (1 = Zerologon protected)" -f $fscp)
    Write-Log 'DomainController module complete.' 'OK'
}
catch {
    Write-Log "DomainController module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
