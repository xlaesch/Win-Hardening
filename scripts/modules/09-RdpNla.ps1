# 09-RdpNla.ps1 - require Network Level Authentication for RDP.
# NLA forces authentication BEFORE the RDP session is established, killing
# pre-auth RDP exploits and blind brute-force against the graphical stack.
# CPP Hard.ps1 parity. Keeps RDP itself enabled (CCDC teams need it).
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
$null = Start-RunLog -Name 'rdpnla' -BackupRoot $BackupRoot
try {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    # Require NLA for every RDP connection.
    Set-RegistryValue -Path "$ts\WinStations\RDP-TCP" -Name 'UserAuthentication' -Type DWord -Value 1 `
        -Module 'RdpNla' -BackupDir $BackupDir
    # Keep RDP allowed (0 = not denied).
    Set-RegistryValue -Path $ts -Name 'fDenyTSConnections' -Type DWord -Value 0 -Module 'RdpNla' -BackupDir $BackupDir
    Set-RegistryValue -Path $ts -Name 'AllowTSConnections' -Type DWord -Value 1 -Module 'RdpNla' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $nla = (Get-ItemProperty "$ts\WinStations\RDP-TCP").UserAuthentication
    $deny = (Get-ItemProperty $ts).fDenyTSConnections
    Write-Log ("  RDP: NLA required={0} (1 = yes), RDP enabled={1}" -f $nla, ($deny -eq 0))
    Write-Log 'RdpNla module complete.' 'OK'
}
catch {
    Write-Log "RdpNla module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
