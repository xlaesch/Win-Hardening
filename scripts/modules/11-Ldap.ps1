# 11-Ldap.ps1 - require LDAP signing (client everywhere, server on DCs).
# Unsigned LDAP lets an on-path attacker relay/capture AD traffic (LLMNR + LDAP
# relay chains). CPP Hard.ps1 parity: LDAPClientIntegrity=2 on all hosts,
# LDAPServerIntegrity=2 on domain controllers.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$StrictServerSigning   # DC: require server-side signing (breaks unsigned LDAP monitors)
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'ldap' -BackupRoot $BackupRoot
try {
    # 2 = require signing (1 = negotiate, 0 = none).
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' `
        -Name 'LDAPClientIntegrity' -Type DWord -Value 2 -Module 'Ldap' -BackupDir $BackupDir

    if (Test-IsDomainController) {
        # Server-side signing level: 1 = negotiate (signs with capable clients, keeps
        # legacy monitors/scored probes alive), 2 = required. Default 1 because scored
        # LDAP checks commonly use unsigned simple binds; -StrictServerSigning for 2.
        $level = if ($StrictServerSigning) { 2 } else { 1 }
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LDAPServerIntegrity' -Type DWord -Value $level -Module 'Ldap' -BackupDir $BackupDir
        if (-not $StrictServerSigning) {
            Write-Log 'Server signing = negotiate (1). Pass -StrictServerSigning if no legacy LDAP probes depend on this DC.' 'INFO'
        }
    }
    else {
        Write-Log 'Not a DC - LDAPServerIntegrity not applicable' 'OK'
    }

    Write-Log '--- verify ---'
    $client = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP').LDAPClientIntegrity
    Write-Log ("  LDAPClientIntegrity={0} (2 = signing required; effective on new LDAP sessions)" -f $client)
    if (Test-IsDomainController) {
        $server = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters').LDAPServerIntegrity
        Write-Log ("  LDAPServerIntegrity={0} (DC; restart of NTDS applies it)" -f $server)
    }
    Write-Log 'Ldap module complete.' 'OK'
}
catch {
    Write-Log "Ldap module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
