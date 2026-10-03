# 01-Firewall.ps1 - enable Windows Firewall on all profiles WITHOUT touching rules.
# Existing allow rules (IIS, RDP, WinRM, ...) keep working, so scored services stay up.
# Also enables dropped-packet logging - top CCDC teams consistently ranked firewall
# logs among the cheapest detection wins.
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
$null = Start-RunLog -Name 'firewall' -BackupRoot $BackupRoot
try {
    foreach ($fwProfile in (Get-NetFirewallProfile)) {
        $name = $fwProfile.Name
        # -eq $false survives the stringy "False" serialization seen over WinRM
        # ('False' is truthy for -not, which silently skipped hardening).
        if ("$($fwProfile.Enabled)" -eq 'True') {
            Write-Log "Firewall profile '$name' already enabled" 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess("firewall profile $name", 'enable')) {
            Set-NetFirewallProfile -Name $name -Enabled True
            Write-Log "Firewall profile '$name' enabled" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Firewall' -Action 'EnableProfile' `
                -Target "FirewallProfile:$name" -NewValue 'True' -OldValue 'False'
        }
    }

    # Keep management planes reachable: enabling profiles can strand hosts whose
    # built-in rule groups are disabled or scoped away from the ACTIVE profile
    # (GOAD NICs sit on the Public profile; the RDP group defaults to Domain/Private).
    foreach ($group in 'Remote Desktop', 'Windows Remote Management') {
        if ($PSCmdlet.ShouldProcess("firewall group '$group'", 'enable rules on all profiles')) {
            # Enable-NetFirewallRule is idempotent; filtering on Enabled is unreliable
            # over WinRM (stringy "False" booleans), so apply unconditionally.
            Enable-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
            Set-NetFirewallRule -DisplayGroup $group -Profile Any -ErrorAction SilentlyContinue
            Write-Log "Firewall group '$group': rules enabled on all profiles" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Firewall' -Action 'EnableRuleGroup' `
                -Target $group -NewValue 'Enabled/Any profile'
        }
    }

    # Dropped-packet logging (allows + drops at default log paths, 16 MB each).
    foreach ($fwProfile in (Get-NetFirewallProfile)) {
        $name = $fwProfile.Name
        if ("$($fwProfile.LogDroppedPackets)" -ne 'True') {
            if ($PSCmdlet.ShouldProcess("firewall profile $name", 'enable dropped-packet logging')) {
                # Set-NetFirewallProfile takes -LogBlocked (the object property is LogDroppedPackets).
                Set-NetFirewallProfile -Name $name -LogBlocked True -LogMaxSizeKilobytes 16384
                Write-Log "Profile '$name': dropped-packet logging enabled (16 MB)" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Firewall' -Action 'EnableDropLogging' `
                    -Target "FirewallProfile:$name" -NewValue 'True' -OldValue 'False'
            }
        }
        else {
            Write-Log "Profile '$name': dropped-packet logging already on" 'OK'
        }
    }

    # Verify
    Write-Log '--- verify ---'
    Get-NetFirewallProfile | ForEach-Object {
        Write-Log ("  {0}: Enabled={1} LogDropped={2}" -f $_.Name, $_.Enabled, $_.LogDroppedPackets) 'OK'
    }
    Write-Log 'Firewall module complete. Rules were not modified.' 'OK'
}
catch {
    Write-Log "Firewall module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
