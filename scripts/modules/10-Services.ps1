# 10-Services.ps1 - disable exploitable services: Print Spooler (PrintNightmare)
# and lock down BITS. CPP Hard.ps1 parity.
# Spooler is almost never scored in CCDC and is a remote-code-execution primitive.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$KeepSpooler   # if the scenario genuinely requires printing
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'services' -BackupRoot $BackupRoot
try {
    # ---------- Print Spooler off (CVE-2021-34527 PrintNightmare) ----------
    if ($KeepSpooler) {
        Write-Log 'Spooler left running (-KeepSpooler); PrintNightmare mitigations still applied.' 'WARN'
    }
    else {
        $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
        if ($spooler) {
            if ($spooler.Status -eq 'Running') {
                if ($PSCmdlet.ShouldProcess('Spooler', 'stop and disable')) {
                    Stop-Service Spooler -Force
                    Set-Service Spooler -StartupType Disabled
                    Write-Log 'Spooler stopped and disabled' 'CHANGE'
                    Add-ChangeRecord -BackupDir $BackupDir -Module 'Services' -Action 'DisableService' `
                        -Target 'Spooler' -NewValue 'Disabled/Stopped' -OldValue "$($spooler.StartType)/$($spooler.Status)"
                }
            }
            elseif ($spooler.StartType -ne 'Disabled') {
                if ($PSCmdlet.ShouldProcess('Spooler', 'disable startup')) {
                    Set-Service Spooler -StartupType Disabled
                    Write-Log 'Spooler startup disabled' 'CHANGE'
                }
            }
            else { Write-Log 'Spooler already disabled' 'OK' }
        }
        else { Write-Log 'Spooler not present' 'OK' }
    }

    # PrintNightmare mitigations (apply even with -KeepSpooler):
    $printers = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    Set-RegistryValue -Path $printers -Name 'RegisterSpoolerRemoteRpcEndPoint' -Type DWord -Value 2 `
        -Module 'Services' -BackupDir $BackupDir
    $pap = "$printers\PointAndPrint"
    # Kill the "no prompt on install" defaults exploited for driver-load privesc.
    foreach ($bad in 'NoWarningNoElevationOnInstall', 'UpdatePromptSettings') {
        $existing = Get-ItemProperty $pap -Name $bad -ErrorAction SilentlyContinue
        if ($null -ne $existing.$bad) {
            if ($PSCmdlet.ShouldProcess("$pap\$bad", 'remove (PointAndPrint hardening)')) {
                Remove-ItemProperty -Path $pap -Name $bad -Force
                Write-Log "Removed $bad (PointAndPrint)" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Services' -Action 'RemoveRegistryValue' `
                    -Target "$pap\$bad" -OldValue $existing.$bad
            }
        }
        else { Write-Log "$bad not present (OK)" 'OK' }
    }
    Set-RegistryValue -Path $pap -Name 'RestrictDriverInstallationToAdministrators' -Type DWord -Value 1 `
        -Module 'Services' -BackupDir $BackupDir

    # ---------- BITS lockdown (CPP parity) ----------
    # BITS is a common C2/persistence transport (PSExec-inspired tooling uses it).
    $bits = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\BITS'
    Set-RegistryValue -Path $bits -Name 'EnableBITSMaxBandwidth' -Type DWord -Value 0 -Module 'Services' -BackupDir $BackupDir
    Set-RegistryValue -Path $bits -Name 'MaxDownloadTime' -Type DWord -Value 1 -Module 'Services' -BackupDir $BackupDir

    Write-Log '--- verify ---'
    $sp = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($sp) { Write-Log ("  Spooler: status={0} start={1}" -f $sp.Status, $sp.StartType) }
    Write-Log ("  PrintNightmare: RestrictDriverInstallationToAdministrators={0}" -f `
        (Get-ItemProperty "$printers\PointAndPrint" -ErrorAction SilentlyContinue).RestrictDriverInstallationToAdministrators)
    Write-Log ("  BITS: EnableBITSMaxBandwidth={0}" -f (Get-ItemProperty $bits -ErrorAction SilentlyContinue).EnableBITSMaxBandwidth)
    Write-Log 'Services module complete.' 'OK'
}
catch {
    Write-Log "Services module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
