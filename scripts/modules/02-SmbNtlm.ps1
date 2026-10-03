# 02-SmbNtlm.ps1 - SMB and NTLM protocol hygiene.
# Kills the credential-theft classics: SMBv1 (EternalBlue), LM/NTLMv1 downgrade,
# unsigned SMB traffic, anonymous SAM enumeration.
# Every top-team playbook researched (BYU, Cal Poly Pomona, howtowinccdc) lists this set.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$SkipClientSigning   # set if old devices legitimately can't sign SMB
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'smbntlm' -BackupRoot $BackupRoot
try {
    # ---------- SMBv1 removal ----------
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($null -eq $smb1 -or $smb1.State -like '*Disabled*') {
        Write-Log "SMB1 optional feature already disabled ($($smb1.State))" 'OK'
    }
    elseif ($PSCmdlet.ShouldProcess('SMB1Protocol feature', 'disable (removal completes on reboot)')) {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Write-Log 'SMB1 optional feature disabled (payload removed after reboot)' 'CHANGE'
        Add-ChangeRecord -BackupDir $BackupDir -Module 'SmbNtlm' -Action 'DisableFeature' `
            -Target 'SMB1Protocol' -NewValue 'Disabled' -OldValue $smb1.State
    }

    # Runtime switch takes effect immediately, independent of the feature removal reboot.
    $srvCfg = Get-SmbServerConfiguration
    if ($srvCfg.EnableSMB1Protocol) {
        if ($PSCmdlet.ShouldProcess('SMB server', 'disable SMB1 protocol')) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Write-Log 'SMB server: SMB1 disabled (immediate)' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'SmbNtlm' -Action 'SetSmbServer' `
                -Target 'EnableSMB1Protocol' -NewValue $false -OldValue $true
        }
    }
    else { Write-Log 'SMB server: SMB1 already disabled' 'OK' }

    # ---------- SMB signing (server side) ----------
    if ($srvCfg.RequireSecuritySignature) {
        Write-Log 'SMB server: signing already required' 'OK'
    }
    elseif ($PSCmdlet.ShouldProcess('SMB server', 'require security signature')) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
        Write-Log 'SMB server: signing required' 'CHANGE'
        Add-ChangeRecord -BackupDir $BackupDir -Module 'SmbNtlm' -Action 'SetSmbServer' `
            -Target 'RequireSecuritySignature' -NewValue $true -OldValue $false
    }

    # ---------- SMB signing (client side) ----------
    if ($SkipClientSigning) {
        Write-Log 'Client-side SMB signing skipped (-SkipClientSigning)' 'WARN'
    }
    else {
        $cliCfg = Get-SmbClientConfiguration
        if ($cliCfg.RequireSecuritySignature) {
            Write-Log 'SMB client: signing already required' 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess('SMB client', 'require security signature')) {
            Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
            Write-Log 'SMB client: signing required' 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'SmbNtlm' -Action 'SetSmbClient' `
                -Target 'RequireSecuritySignature' -NewValue $true -OldValue $false
        }
    }

    # ---------- NTLM / LSA registry hardening ----------
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    # Refuse LM and NTLMv1: domain and standalone clients must send NTLMv2 only.
    Set-RegistryValue -Path $lsa -Name 'LmCompatibilityLevel' -Type DWord -Value 5 `
        -Module 'SmbNtlm' -BackupDir $BackupDir
    # Stop storing the weak LM hash of future password changes.
    Set-RegistryValue -Path $lsa -Name 'NoLMHash' -Type DWord -Value 1 `
        -Module 'SmbNtlm' -BackupDir $BackupDir
    # Block anonymous enumeration of SAM accounts and shares.
    Set-RegistryValue -Path $lsa -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 `
        -Module 'SmbNtlm' -BackupDir $BackupDir
    Set-RegistryValue -Path $lsa -Name 'RestrictAnonymous' -Type DWord -Value 1 `
        -Module 'SmbNtlm' -BackupDir $BackupDir

    # Registry belt-and-suspenders alongside the cmdlets above (CPP SMB.ps1 parity):
    # enforces the same settings even where the SMB cmdlets are unavailable.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'SMB1' -Type DWord -Value 0 -Module 'SmbNtlm' -BackupDir $BackupDir
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Module 'SmbNtlm' -BackupDir $BackupDir
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'EnableSecuritySignature' -Type DWord -Value 1 -Module 'SmbNtlm' -BackupDir $BackupDir
    if (-not $SkipClientSigning) {
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' `
            -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Module 'SmbNtlm' -BackupDir $BackupDir
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' `
            -Name 'EnableSecuritySignature' -Type DWord -Value 1 -Module 'SmbNtlm' -BackupDir $BackupDir
    }

    # ---------- verify ----------
    Write-Log '--- verify ---'
    $check = Get-SmbServerConfiguration
    Write-Log ("  SMB server: SMB1={0} RequireSigning={1}" -f $check.EnableSMB1Protocol, $check.RequireSecuritySignature)
    $lsaNow = Get-ItemProperty $lsa
    Write-Log ("  Lsa: LmCompatibilityLevel={0} NoLMHash={1} RestrictAnonymous={2} RestrictAnonymousSAM={3}" -f `
        $lsaNow.LmCompatibilityLevel, $lsaNow.NoLMHash, $lsaNow.RestrictAnonymous, $lsaNow.RestrictAnonymousSAM)
    Write-Log 'SmbNtlm module complete.' 'OK'
}
catch {
    Write-Log "SmbNtlm module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
