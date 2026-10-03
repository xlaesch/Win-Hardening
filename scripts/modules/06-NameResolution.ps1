# 06-NameResolution.ps1 - disable LLMNR and NBT-NS.
# Both let an on-subnet attacker spoof name resolution and capture NTLM hashes
# (Responder). GOAD-Light deliberately enables both, so this module is a direct
# remediation of the lab's planted weaknesses.
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
$null = Start-RunLog -Name 'nameres' -BackupRoot $BackupRoot
try {
    # ---------- LLMNR off (both policy and service parameter) ----------
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name 'EnableMulticast' -Type DWord -Value 0 -Module 'NameResolution' -BackupDir $BackupDir
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
        -Name 'EnableMulticast' -Type DWord -Value 0 -Module 'NameResolution' -BackupDir $BackupDir

    # ---------- NBT-NS off on every adapter ----------
    # NetbiosOptions: 0 = from DHCP, 1 = enabled, 2 = disabled.
    $interfaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop
    foreach ($iface in $interfaces) {
        $current = (Get-ItemProperty $iface.PSPath -ErrorAction SilentlyContinue).NetbiosOptions
        if ($current -eq 2) {
            Write-Log "$($iface.PSChildName): Netbios already disabled" 'OK'
            continue
        }
        if ($PSCmdlet.ShouldProcess($iface.PSChildName, 'set NetbiosOptions=2 (disabled)')) {
            Set-ItemProperty -Path $iface.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord
            Write-Log "$($iface.PSChildName): NetbiosOptions 2 (NBT-NS disabled)" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'NameResolution' -Action 'DisableNetbios' `
                -Target $iface.PSChildName -NewValue 2 -OldValue $current
        }
    }

    # ---------- verify ----------
    Write-Log '--- verify ---'
    $policy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
    $svc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue).EnableMulticast
    Write-Log ("  LLMNR: policy EnableMulticast={0}, service EnableMulticast={1} (0 = off)" -f $policy, $svc)
    $nbt = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
        ForEach-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions }
    Write-Log ("  NBT-NS: adapter NetbiosOptions = {0} (all should be 2; effective after adapter/DNS restart)" -f ($nbt -join ', '))
    Write-Log 'NameResolution module complete.' 'OK'
}
catch {
    Write-Log "NameResolution module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
