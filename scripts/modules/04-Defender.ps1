# 04-Defender.ps1 - turn Windows Defender on and remove tampering.
# Red teams routinely disable real-time monitoring or plant exclusions for their
# tooling; national red teamers note "Defender is actually good now" (Levinson 2022).
# GOAD-Light ships srv02 with Defender deliberately OFF - this module is what flips it back.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$KeepExclusions   # set to leave existing exclusions in place
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'defender' -BackupRoot $BackupRoot
try {
    $service = Get-Service WinDefend -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log 'WinDefend service not present on this SKU - nothing to do.' 'WARN'
        exit 0
    }
    if ($service.Status -ne 'Running') {
        if ($PSCmdlet.ShouldProcess('WinDefend service', 'start')) {
            Start-Service WinDefend
            Write-Log 'WinDefend service started' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'StartService' `
                -Target 'WinDefend' -NewValue 'Running' -OldValue $service.Status
        }
    }
    else { Write-Log 'WinDefend service running' 'OK' }

    # Engine toggles red teams flip off. All idempotent Set-MpPreference calls.
    $prefs = @(
        @{ Name = 'DisableRealtimeMonitoring'; Bad = $true; Good = $false },
        @{ Name = 'DisableBehaviorMonitoring'; Bad = $true; Good = $false },
        @{ Name = 'DisableIOAVProtection';      Bad = $true; Good = $false },
        @{ Name = 'DisableScriptScanning';      Bad = $true; Good = $false }
    )
    $current = Get-MpPreference
    foreach ($p in $prefs) {
        $val = $current.($p.Name)
        if ($val -eq $p.Bad) {
            if ($PSCmdlet.ShouldProcess("Defender $($p.Name)", "set to $($p.Good)")) {
                # Set-MpPreference takes each setting as its own parameter - splat it.
                $mpSplat = @{}
                $mpSplat[$p.Name] = $p.Good
                Set-MpPreference @mpSplat
                Write-Log "Defender: $($p.Name) = $($p.Good)" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'SetPreference' `
                    -Target $p.Name -NewValue $p.Good -OldValue $val
            }
        }
        else { Write-Log "Defender: $($p.Name) already OK ($val)" 'OK' }
    }

    # Tamper protection (blocks even admins from disabling Defender via prefs).
    try {
        $status = Get-MpComputerStatus
        if (-not $status.IsTamperProtectionEnabled) {
            Set-MpPreference -DisableTamperProtection $false -ErrorAction Stop
            Write-Log 'Defender: tamper protection enabled' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'SetPreference' `
                -Target 'DisableTamperProtection' -NewValue $false -OldValue $true
        }
        else { Write-Log 'Defender: tamper protection already on' 'OK' }
    }
    catch { Write-Log "Tamper protection could not be set (may be OS-version dependent): $_" 'WARN' }
    # Registry fallback for tamper protection (CPP Hard.ps1 parity): 5 = on.
    # Locked by tamper protection itself once active - best effort.
    try {
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' `
            -Name 'TamperProtection' -Type DWord -Value 5 -Module 'Defender' -BackupDir $BackupDir -ErrorAction Stop
    }
    catch { Write-Log 'TamperProtection registry key locked (tamper protection already guards it)' 'WARN' }

    # ---------- ASR rules (CPP Hard.ps1 parity: all 15) ----------
    $asrRules = @(
        @{ Id = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Note = 'Block Office apps injecting code into other processes' },
        @{ Id = '3B576869-A4EC-4529-8536-B80A7769E899'; Note = 'Block Office apps creating executable content' },
        @{ Id = 'D4F940AB-401B-4EfC-AADC-AD5F3C50688A'; Note = 'Block Office apps creating child processes' },
        @{ Id = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Note = 'Block JS/VBScript launching downloaded executables' },
        @{ Id = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Note = 'Block obfuscated scripts' },
        @{ Id = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Note = 'Block executable content from email/webmail' },
        @{ Id = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Note = 'Block Win32 API calls from Office macros' },
        @{ Id = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Note = 'Block process creations from PSExec and WMI' },
        @{ Id = 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Note = 'Block untrusted/unsigned processes from USB' },
        @{ Id = 'C1DB55AB-C21A-4637-BB3F-A12568109D35'; Note = 'Ransomware protection' },
        @{ Id = '01443614-CD74-433A-B99E-2ECDC07BFC25'; Note = 'Block executables failing prevalence/age/trusted-list' },
        @{ Id = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Note = 'Block credential stealing from LSASS' },
        @{ Id = '26190899-1602-49E8-8B27-EB1D0A1CE869'; Note = 'Block Office comms apps creating child processes' },
        @{ Id = '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Note = 'Block Adobe Reader creating child processes' },
        @{ Id = 'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Note = 'Block WMI event subscription persistence' }
    )
    try {
        $current = Get-MpPreference
        $enabled = @($current.AttackSurfaceReductionRules_Ids)
        $missing = $asrRules | Where-Object { $enabled -notcontains $_.Id }
        if ($missing.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess('Defender ASR', "enable $($missing.Count) rules")) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids ($missing | ForEach-Object Id) `
                    -AttackSurfaceReductionRules_Actions (@('Enabled') * $missing.Count)
                Write-Log "Defender: enabled $($missing.Count) ASR rules" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'EnableAsrRules' `
                    -Target 'AttackSurfaceReductionRules_Ids' -NewValue (($missing | ForEach-Object Id) -join ',')
            }
        }
        else { Write-Log "Defender: all $($asrRules.Count) ASR rules already enabled" 'OK' }
        # ASR exclusions are as dangerous as scan exclusions - strip them (CPP parity).
        $asrEx = @($current.AttackSurfaceReductionOnlyExclusions | Where-Object { $_ })
        if ($asrEx.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess('Defender ASR', "remove $($asrEx.Count) exclusion(s)")) {
                Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $asrEx -ErrorAction SilentlyContinue
                Write-Log "Defender: removed $($asrEx.Count) ASR exclusions" 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'RemoveAsrExclusions' `
                    -Target 'AttackSurfaceReductionOnlyExclusions' -OldValue ($asrEx -join ', ')
            }
        }
        else { Write-Log 'Defender: no ASR exclusions' 'OK' }
    }
    catch { Write-Log "ASR rules not supported on this Defender version - skipped: $_" 'WARN' }

    # ---------- Defender policy-key hardening (CPP Hard.ps1 parity) ----------
    # Policy keys under Policies\...\Windows Defender survive and re-assert settings
    # even when interactive prefs are tampered with.
    $policyKeys = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet';                 Name = 'SpyNetReporting';                 Value = 2 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet';                 Name = 'SubmitSamplesConsent';            Value = 3 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet';                 Name = 'DisableBlockAtFirstSeen';         Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine';               Name = 'MpCloudBlockLevel';               Value = 6 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';   Name = 'DisableBehaviorMonitoring';       Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';   Name = 'DisableRealtimeMonitoring';       Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';   Name = 'DisableIOAVProtection';           Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';                        Name = 'DisableAntiSpyware';              Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';                        Name = 'ServiceKeepAlive';                Value = 1 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan';                   Name = 'CheckForSignaturesBeforeRunningScan'; Value = 1 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan';                   Name = 'DisableHeuristics';               Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan';                   Name = 'DisableArchiveScanning';          Value = 0 },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection';     Name = 'ForceDefenderPassiveMode';        Value = 0 }
    )
    foreach ($k in $policyKeys) {
        # Once tamper protection is ON, Defender locks its own policy keys against
        # ALL writers (admins included) - that is tamper protection working as
        # designed, and the live Set-MpPreference settings above already hold.
        try {
            Set-RegistryValue -Path $k.Path -Name $k.Name -Type DWord -Value $k.Value `
                -Module 'Defender' -BackupDir $BackupDir -ErrorAction Stop
        }
        catch {
            Write-Log "Policy key locked by tamper protection (expected, live prefs already set): $($k.Path)\$($k.Name)" 'WARN'
        }
    }

    # Exclusions: attacker-favorite persistence. Remove every list unless told not to.
    if ($KeepExclusions) {
        Write-Log 'Keeping existing exclusions (-KeepExclusions)' 'WARN'
    }
    else {
        $current = Get-MpPreference
        $lists = @('ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress')
        foreach ($list in $lists) {
            $items = @($current.$list | Where-Object { $_ })   # @($null) has Count 1 in PS
            if ($items.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess("Defender $list", "remove $($items.Count) exclusion(s): $($items -join ', ')")) {
                    $rmSplat = @{}
                    $rmSplat[$list] = $items
                    Remove-MpPreference @rmSplat -ErrorAction SilentlyContinue
                    Write-Log "Defender: removed $($items.Count) $list exclusion(s): $($items -join ', ')" 'CHANGE'
                    Add-ChangeRecord -BackupDir $BackupDir -Module 'Defender' -Action 'RemoveExclusions' `
                        -Target $list -NewValue $null -OldValue ($items -join ', ')
                }
            }
            else { Write-Log "Defender: no $list exclusions" 'OK' }
        }
    }

    # ---------- verify ----------
    Write-Log '--- verify ---'
    $status = Get-MpComputerStatus
    Write-Log ("  RealTimeEnabled={0} TamperProtection={1} AMServiceRunning={2}" -f `
        $status.RealTimeProtectionEnabled, $status.IsTamperProtectionEnabled, $status.AMServiceRunning)
    $after = Get-MpPreference
    Write-Log ("  Exclusions: path={0} ext={1} proc={2} ip={3}" -f `
        @($after.ExclusionPath | Where-Object { $_ }).Count, @($after.ExclusionExtension | Where-Object { $_ }).Count, `
        @($after.ExclusionProcess | Where-Object { $_ }).Count, @($after.ExclusionIpAddress | Where-Object { $_ }).Count)
    Write-Log 'Defender module complete. Signature updates (Update-MpSignature) left to the team - see runbook.' 'OK'
}
catch {
    Write-Log "Defender module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
