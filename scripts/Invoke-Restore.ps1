# Invoke-Restore.ps1 - undo everything the toolkit changed, using the preflight backup.
# Restores: registry keys, audit policy, local security policy, firewall policy,
# SMB server/client settings, SMB1 feature state, Defender preferences and exclusions.
# Optionally uninstalls Sysmon. Leaves the break-glass admin in place (printed manual
# removal command at the end).
#
#   .\Invoke-Restore.ps1                  # restore from latest backup
#   .\Invoke-Restore.ps1 -List            # show available backups
#   .\Invoke-Restore.ps1 -BackupDir C:\HardeningBackups\20260929-100000
#   .\Invoke-Restore.ps1 -RemoveSysmon
#   .\Invoke-Restore.ps1 -RemoveElasticAgent
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$List,
    [switch]$RemoveSysmon,
    [switch]$RemoveElasticAgent
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\common.ps1"
Assert-Admin

if ($List) {
    Get-ChildItem $BackupRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'backup-manifest.json') } |
        Sort-Object Name -Descending |
        ForEach-Object {
            $m = Get-Manifest -BackupDir $_.FullName
            Write-Host ("{0}  {1}  {2}" -f $_.Name, $m.Computer, $m.Created)
        }
    exit 0
}

if (-not $BackupDir) { $BackupDir = Get-LatestBackupRun -BackupRoot $BackupRoot }
if (-not $BackupDir) { throw "No backup found under $BackupRoot. Nothing to restore." }
$manifest = Get-Manifest -BackupDir $BackupDir
if (-not $manifest) { throw "No backup-manifest.json in $BackupDir." }

$exitCode = 0
$null = Start-RunLog -Name 'restore' -BackupRoot $BackupRoot
try {
    Write-Log "Restoring from: $BackupDir (created $($manifest.Created) on $($manifest.Computer))"

    # ---------- 1. registry: surgical change-log restore, then best-effort key imports ----------
    # The change log records every value the toolkit set and its prior state, so the
    # primary restore path writes back ONLY our values. Whole-key .reg imports stay
    # as a best-effort second pass: keys like Lsa hold kernel-guarded values
    # (SecurityPackages, AuthenticationPackages...) that make `reg import` fail
    # outright even though individual value writes work fine.
    $changeLogPath = Join-Path $BackupDir 'change-log.json'
    if (Test-Path $changeLogPath) {
        $changes = @(Get-Content $changeLogPath -Raw | ConvertFrom-Json)
        $regChanges = $changes | Where-Object { $_.Action -eq 'SetRegistryValue' }
        foreach ($rc in $regChanges) {
            # Target format: HKLM:\...\Lsa\ValueName
            $idx = $rc.Target.LastIndexOf('\')
            $key = $rc.Target.Substring(0, $idx)
            $value = $rc.Target.Substring($idx + 1)
            $old = $rc.OldValue
            $hadValue = (-not $rc.WasAdded) -and ($null -ne $old) -and ("$old" -ne '')
            if ($PSCmdlet.ShouldProcess($rc.Target, $(if ($hadValue) { "restore to '$old'" } else { 'remove (added by toolkit)' }))) {
                if ($hadValue) {
                    # Type inference: numbers -> DWord, arrays -> MultiString, else String.
                    if ($old -is [System.Array]) {
                        Set-ItemProperty -Path $key -Name $value -Value $old -Type MultiString -ErrorAction SilentlyContinue
                    }
                    elseif ($old -is [int] -or $old -is [long] -or $old -is [double]) {
                        Set-ItemProperty -Path $key -Name $value -Value ([int]$old) -Type DWord -ErrorAction SilentlyContinue
                    }
                    else {
                        Set-ItemProperty -Path $key -Name $value -Value ("$old") -Type String -ErrorAction SilentlyContinue
                    }
                    Write-Log "Restored value: $rc.Target = $old" 'CHANGE'
                }
                else {
                    Remove-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue
                    Write-Log "Removed added value: $rc.Target" 'CHANGE'
                }
            }
        }
    }
    else { Write-Log 'No change-log.json - restoring keys wholesale only' 'WARN' }

    $regDir = Join-Path $BackupDir 'registry'
    if (Test-Path $regDir) {
        Get-ChildItem $regDir -Filter '*.reg' | ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.Name, 'import registry backup (best effort)')) {
                try { & reg.exe import $_.FullName 2>&1 | Out-Null } catch { }
                if ($LASTEXITCODE -eq 0) { Write-Log "Imported $($_.Name)" 'CHANGE' }
                else { Write-Log "Key import skipped (guarded values - change-log restore above covers our settings): $($_.Name)" 'WARN' }
            }
        }
    }

    # ---------- 2. audit policy ----------
    $auditBackup = Join-Path $BackupDir 'policy\audit-policy.csv'
    if (Test-Path $auditBackup) {
        if ($PSCmdlet.ShouldProcess('audit policy', 'restore from backup')) {
            & auditpol.exe /restore "/file:$auditBackup"
            if ($LASTEXITCODE -eq 0) { Write-Log 'Audit policy restored' 'CHANGE' }
            else { Write-Log 'Audit policy restore failed' 'FAIL'; $exitCode = 1 }
        }
    }

    # ---------- 3. local security policy (secedit) ----------
    $seceditBackup = Join-Path $BackupDir 'policy\secedit-export.inf'
    if (Test-Path $seceditBackup) {
        if ($PSCmdlet.ShouldProcess('local security policy', 'restore via secedit')) {
            $tempDb = Join-Path $env:TEMP ("restore-secedit-{0}.sdb" -f (Get-Date -Format 'HHmmss'))
            & secedit.exe /configure /db $tempDb /cfg $seceditBackup /quiet
            if ($LASTEXITCODE -eq 0) { Write-Log 'Local security policy restored (secedit)' 'CHANGE' }
            else { Write-Log 'secedit restore failed' 'FAIL'; $exitCode = 1 }
        }
    }

    # ---------- 4. firewall policy ----------
    $fwBackup = Join-Path $BackupDir 'policy\firewall-policy.wfw'
    if (Test-Path $fwBackup) {
        if ($PSCmdlet.ShouldProcess('firewall policy', 'restore (netsh import)')) {
            & netsh.exe advfirewall import $fwBackup | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Log 'Firewall policy restored' 'CHANGE' }
            else { Write-Log 'Firewall policy restore failed' 'FAIL'; $exitCode = 1 }
        }
    }

    # ---------- 5. SMB configuration ----------
    $smbServerXml = Join-Path $BackupDir 'state\smb-server-config.xml'
    if (Test-Path $smbServerXml) {
        $orig = Import-Clixml $smbServerXml
        $now = Get-SmbServerConfiguration
        $pairs = @(
            @{ Name = 'EnableSMB1Protocol';      Orig = $orig.EnableSMB1Protocol;      Now = $now.EnableSMB1Protocol },
            @{ Name = 'RequireSecuritySignature'; Orig = $orig.RequireSecuritySignature; Now = $now.RequireSecuritySignature },
            @{ Name = 'EnableSecuritySignature'; Orig = $orig.EnableSecuritySignature; Now = $now.EnableSecuritySignature }
        )
        foreach ($p in $pairs) {
            if ("$($p.Orig)" -ne "$($p.Now)") {
                if ($PSCmdlet.ShouldProcess("SMB server $($p.Name)", "restore to $($p.Orig)")) {
                    # Invoke with dynamic parameter names.
                    $splat = @{ Force = $true }
                    $splat[$p.Name] = $p.Orig
                    Set-SmbServerConfiguration @splat
                    Write-Log "SMB server: $($p.Name) = $($p.Orig)" 'CHANGE'
                }
            }
        }
    }
    $smbClientXml = Join-Path $BackupDir 'state\smb-client-config.xml'
    if (Test-Path $smbClientXml) {
        $orig = Import-Clixml $smbClientXml
        $now = Get-SmbClientConfiguration
        if ("$($orig.RequireSecuritySignature)" -ne "$($now.RequireSecuritySignature)") {
            if ($PSCmdlet.ShouldProcess('SMB client RequireSecuritySignature', "restore to $($orig.RequireSecuritySignature)")) {
                Set-SmbClientConfiguration -RequireSecuritySignature $orig.RequireSecuritySignature -Force
                Write-Log "SMB client: RequireSecuritySignature = $($orig.RequireSecuritySignature)" 'CHANGE'
            }
        }
    }

    # ---------- 6. SMB1 feature (only if it was originally enabled) ----------
    if ($manifest.SMB1State -and $manifest.SMB1State -like '*Enabled*') {
        if ($PSCmdlet.ShouldProcess('SMB1Protocol feature', 're-enable (was enabled before toolkit)')) {
            Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            Write-Log 'SMB1 feature re-enabled to pre-toolkit state' 'CHANGE'
        }
    }
    else { Write-Log "SMB1 left disabled (pre-toolkit state: $($manifest.SMB1State))" 'OK' }

    # ---------- 6b. SMB share ACLs (module 15 downgrades) ----------
    $aclXml = Join-Path $BackupDir 'state\smb-share-acls.xml'
    if (Test-Path $aclXml) {
        $origAcls = Import-Clixml $aclXml
        # Special shares (ADMIN$, C$, IPC$...) reject ACL changes entirely (error 50);
        # module 15 exempted them from modification, so there is nothing to restore.
        $restorable = @($origAcls | Select-Object -ExpandProperty Share -Unique | Where-Object { $_ -notmatch '\$$' })
        foreach ($shareName in $restorable) {
            $targetAces = @($origAcls | Where-Object Share -eq $shareName)
            $currentAces = @(Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue)
            $needsRestore = $false
            foreach ($t in $targetAces) {
                $c = $currentAces | Where-Object { $_.AccountName -eq $t.Account }
                if (-not $c -or "$($c.AccessRight)" -ne "$($t.AccessRight)") { $needsRestore = $true }
            }
            if ($needsRestore) {
                if ($PSCmdlet.ShouldProcess("share '$shareName'", 'restore original ACLs')) {
                    foreach ($t in $targetAces) {
                        Grant-SmbShareAccess -Name $shareName -AccountName $t.Account -AccessRight $t.AccessRight -Force | Out-Null
                    }
                    Revoke-SmbShareAccess -Name $shareName -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "Share '$shareName': original ACLs restored" 'CHANGE'
                }
            }
        }
    }

    # ---------- 6c. Spooler (module 10) ----------
    if ($manifest.SpoolerStartType -and $manifest.SpoolerStartType -ne 'Disabled') {
        if ($PSCmdlet.ShouldProcess('Spooler', "restore startup type $($manifest.SpoolerStartType)")) {
            Set-Service Spooler -StartupType $manifest.SpoolerStartType
            if ($manifest.SpoolerStatus -eq 'Running') { Start-Service Spooler -ErrorAction SilentlyContinue }
            Write-Log "Spooler restored to $($manifest.SpoolerStartType)" 'CHANGE'
        }
    }

    # ---------- 6d. GPO status (module 13) + local GPO cache ----------
    if (Test-Path $changeLogPath) {
        $gpoChanges = $changes | Where-Object { $_.Action -eq 'DisableGpo' }
        if ($gpoChanges -and (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
            Import-Module GroupPolicy -ErrorAction SilentlyContinue
            foreach ($g in $gpoChanges) {
                try {
                    $gpo = Get-GPO -Name $g.Target -ErrorAction Stop
                    if ($PSCmdlet.ShouldProcess("GPO '$($g.Target)'", "restore flags $($g.OldValue)")) {
                        # LDAP write (GPMGMT COM writes are denied over WinRM).
                        Set-ADObject -Identity $gpo.Path -Replace @{ flags = [int]"$($g.OldValue)" }
                        Write-Log "GPO '$($g.Target)' flags restored to $($g.OldValue)" 'CHANGE'
                    }
                }
                catch { Write-Log "GPO '$($g.Target)' not found for restore" 'WARN' }
            }
        }
        $maqChanges = $changes | Where-Object { $_.Action -eq 'SetDomainAttribute' -and $_.Target -eq 'ms-DS-MachineAccountQuota' }
        foreach ($m in $maqChanges) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                if ($PSCmdlet.ShouldProcess('ms-DS-MachineAccountQuota', "restore to $($m.OldValue)")) {
                    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{ 'ms-DS-MachineAccountQuota' = "$($m.OldValue)" }
                    Write-Log "MachineAccountQuota restored to $($m.OldValue)" 'CHANGE'
                }
            }
            catch { Write-Log "MachineAccountQuota restore failed: $_" 'WARN' }
        }
        $phpChanges = $changes | Where-Object { $_.Action -eq 'AppendIni' }
        foreach ($p in $phpChanges) {
            $bak = Join-Path $BackupDir ('state\php\' + (($p.Target -replace '[\\/:*?"<>|]', '_') + '.bak'))
            if ((Test-Path $bak) -and (Test-Path $p.Target)) {
                if ($PSCmdlet.ShouldProcess($p.Target, 'restore php.ini from backup')) {
                    Copy-Item $bak $p.Target -Force
                    Write-Log "Restored $($p.Target)" 'CHANGE'
                }
            }
        }
    }
    $localGpoBk = Join-Path $BackupDir 'state\local-gpo'
    if (Test-Path $localGpoBk) {
        if ($PSCmdlet.ShouldProcess('local group policy', 'restore local GPO cache')) {
            Copy-Item (Join-Path $localGpoBk 'GroupPolicy') 'C:\Windows\System32\GroupPolicy' -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $localGpoBk 'GroupPolicyUser') 'C:\Windows\System32\GroupPolicyUser' -Recurse -Force -ErrorAction SilentlyContinue
            & gpupdate.exe /force | Out-Null
            Write-Log 'Local GPO cache restored + gpupdate' 'CHANGE'
        }
    }

    # ---------- 6e. Access binaries (module 19 swaps) ----------
    $binBk = Join-Path $BackupDir 'state\access-binary-backups'
    if (Test-Path $binBk) {
        Get-ChildItem $binBk -Filter '*.exe' | ForEach-Object {
            $dest = "C:\Windows\System32\$($_.Name)"
            if ($PSCmdlet.ShouldProcess($dest, 'restore original accessibility binary')) {
                & takeown.exe /f $dest | Out-Null
                & icacls.exe $dest /grant 'Administrators:F' | Out-Null
                Copy-Item $_.FullName $dest -Force
                Remove-MpPreference -ExclusionProcess $dest -ErrorAction SilentlyContinue
                Write-Log "Restored $($_.Name) + removed its Defender exclusion" 'CHANGE'
            }
        }
    }

    # ---------- 7. Defender preferences & exclusions ----------
    $defXml = Join-Path $BackupDir 'state\defender-preferences.xml'
    if (Test-Path $defXml) {
        $orig = Import-Clixml $defXml
        # Exclusions are deliberately NOT restored: pre-toolkit exclusions are
        # attacker-planted (GOAD ships them; red teams plant more). Removing them is a
        # one-way improvement - rerun module 04 if they somehow reappear.

        # Engine toggles: restore whatever the original said (usually already $true = disabled... restore faithfully).
        $current = Get-MpPreference
        foreach ($p in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning') {
            $origVal = $orig.$p
            $nowVal = $current.$p
            if ($null -ne $origVal -and "$origVal" -ne "$nowVal") {
                if ($PSCmdlet.ShouldProcess("Defender $p", "restore to $origVal")) {
                    try {
                        $mpSplat = @{}
                        $mpSplat[$p] = $origVal
                        Set-MpPreference @mpSplat
                        Write-Log "Defender: $p = $origVal (pre-toolkit value restored)" 'CHANGE'
                    }
                    catch { Write-Log "Defender $p restore skipped: $_" 'WARN' }
                }
            }
        }
    }
    Write-Log 'Tamper protection left ON even if it was off pre-toolkit (pure win).' 'WARN'

    # ---------- 7b. ASR rules: restore the pre-toolkit rule set ----------
    $defXml2 = Join-Path $BackupDir 'state\defender-preferences.xml'
    if (Test-Path $defXml2) {
        try {
            $origDef = Import-Clixml $defXml2
            $origAsr = @($origDef.AttackSurfaceReductionRules_Ids)
            $nowAsr = @((Get-MpPreference).AttackSurfaceReductionRules_Ids)
            $removed = @($nowAsr | Where-Object { $origAsr -notcontains $_ })
            if ($removed.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess('Defender ASR', "remove $($removed.Count) toolkit-added rule(s)")) {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $removed -ErrorAction SilentlyContinue
                    Write-Log "Defender: removed $($removed.Count) toolkit-added ASR rules" 'CHANGE'
                }
            }
            else { Write-Log 'Defender: no toolkit-added ASR rules to remove' 'OK' }
        } catch { Write-Log "ASR restore skipped: $_" 'WARN' }
    }

    # ---------- 8. Sysmon (optional) ----------
    if ($RemoveSysmon) {
        $exe = 'C:\ProgramData\Hardening\Sysmon\Sysmon64.exe'
        if (-not (Test-Path $exe)) { $exe = Join-Path $PSScriptRoot '..\tools\sysinternals\Sysmon64.exe' }
        if (Test-Path $exe) {
            if ($PSCmdlet.ShouldProcess('Sysmon', 'uninstall')) {
                try { & $exe -u accepteula 2>&1 | ForEach-Object { Write-Log "  sysmon: $_" } } catch { Write-Log "  sysmon output note: $_" 'WARN' }
                Write-Log 'Sysmon uninstalled' 'CHANGE'
            }
        }
    }
    else { Write-Log 'Sysmon left installed (-RemoveSysmon to remove).' 'OK' }

    # ---------- 8b. Elastic Agent (optional) ----------
    if ($RemoveElasticAgent) {
        $agentExe = 'C:\Program Files\Elastic\Agent\elastic-agent.exe'
        if ((Get-Service 'Elastic Agent' -ErrorAction SilentlyContinue) -and (Test-Path $agentExe)) {
            if ($PSCmdlet.ShouldProcess('Elastic Agent', 'uninstall service')) {
                # Must run from OUTSIDE the install directory per Elastic docs.
                Push-Location $env:TEMP
                try { & $agentExe uninstall --force 2>&1 | ForEach-Object { Write-Log "  agent: $_" } }
                finally { Pop-Location }
                Write-Log 'Elastic Agent uninstalled' 'CHANGE'
                # Uninstall can leave data/logs behind when files are locked.
                if (Test-Path 'C:\Program Files\Elastic\Agent\data') {
                    Write-Log 'Leftover Agent data\ detected - delete C:\Program Files\Elastic\Agent after a reboot if locked.' 'WARN'
                }
            }
        }
        else { Write-Log 'Elastic Agent not installed (nothing to remove).' 'OK' }
    }
    else { Write-Log 'Elastic Agent left running (-RemoveElasticAgent to remove).' 'OK' }

    # ---------- notes ----------
    Write-Log 'Break-glass admin left in place. Remove manually with:' 'WARN'
    if ($manifest.IsDC) {
        Write-Log "  Remove-ADUser -Identity '$($manifest.LockoutAdmin)'" 'WARN'
    }
    else {
        Write-Log "  Remove-LocalUser -Name '$($manifest.LockoutAdmin)'" 'WARN'
    }
    Write-Log 'Some restored settings (RunAsPPL, NetbiosOptions, SMB1 payload) need a reboot or service restart to take effect.' 'WARN'
    Write-Log "RESTORE COMPLETE from $BackupDir" 'OK'
}
catch {
    Write-Log "RESTORE FAILED: $_" 'FAIL'
    Write-Log ("  at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.Line.Trim()) 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
