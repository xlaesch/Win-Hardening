# Invoke-Preflight.ps1 - run this FIRST on every box.
# 1. Lockout guard: creates a fresh break-glass admin (local on members, domain on DCs)
#    so the team never loses access to its own machine.
# 2. Backs up everything the hardening modules may touch, so Invoke-Restore.ps1
#    can undo every change.
# 3. Snapshots system state (services, listening ports, shares) for before/after diffing.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$AdminUser = 'ccdc-admin',
    [switch]$SkipUserCreation
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\common.ps1"
Assert-Admin

$exitCode = 0
$null = Start-RunLog -Name 'preflight' -BackupRoot $BackupRoot
try {
    $isDC = Test-IsDomainController
    $domain = (Get-CimInstance Win32_ComputerSystem).Domain
    Write-Log "Preflight on $env:COMPUTERNAME ($([string]$domain)) - role: $(if ($isDC) {'Domain Controller'} else {'Member/Stand-alone'})"

    # ---------- 1. backup run directory ----------
    $runDir = New-BackupRun -BackupRoot $BackupRoot
    Write-Log "Backup run directory: $runDir" 'OK'
    $manifest = [pscustomobject]@{
        Created    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Computer   = $env:COMPUTERNAME
        Domain     = $domain
        IsDC       = $isDC
        LockoutAdmin = $null
        SMB1State  = $null
        RegistryKeys = @()
    }

    # ---------- 2. lockout guard ----------
    if (-not $SkipUserCreation) {
        $password = New-RandomPassword -Length 20   # CCDC rule: passwords max 24 chars
        if ($isDC) {
            # Domain controllers have no local SAM; create a domain account instead.
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $secure = ConvertTo-SecureString $password -AsPlainText -Force
                $existing = Get-ADUser -Filter "SamAccountName -eq '$AdminUser'" -ErrorAction SilentlyContinue
                if ($existing) {
                    Set-ADAccountPassword -Identity $AdminUser -NewPassword $secure -Reset
                    Write-Log "Reset password of existing domain account '$AdminUser'" 'CHANGE'
                } else {
                    New-ADUser -Name $AdminUser -SamAccountName $AdminUser -AccountPassword $secure `
                        -Enabled $true -PasswordNeverExpires $true -Description 'CCDC break-glass admin'
                    Write-Log "Created domain break-glass account '$AdminUser'" 'CHANGE'
                }
                Add-ADGroupMember -Identity 'Domain Admins' -Members $AdminUser -ErrorAction SilentlyContinue
                Write-Log "WARNING: '$AdminUser' is in Domain Admins - remove after the competition." 'WARN'
            } catch {
                Write-Log "Could not create domain break-glass account: $_" 'FAIL'
                $exitCode = 1
            }
        } else {
            try {
                $secure = ConvertTo-SecureString $password -AsPlainText -Force
                if (Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue) {
                    Set-LocalUser -Name $AdminUser -Password $secure -PasswordNeverExpires $true
                    Write-Log "Reset password of existing local user '$AdminUser'" 'CHANGE'
                } else {
                    # New-LocalUser takes -AccountNeverExpires (switch); -PasswordNeverExpires
                    # belongs to Set-LocalUser only.
                    New-LocalUser -Name $AdminUser -Password $secure -AccountNeverExpires `
                        -Description 'CCDC break-glass admin' | Out-Null
                    Write-Log "Created local break-glass account '$AdminUser'" 'CHANGE'
                }
                # SID lookup is locale-independent ('Administrators' is localized on some installs).
                $admins = Get-LocalGroup -SID 'S-1-5-32-544'
                Add-LocalGroupMember -Group $admins -Member $AdminUser -ErrorAction SilentlyContinue
                # CPP parity (Usr.ps1): break-glass admin must also reach the box
                # via RDP and WinRM, not just the console.
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $AdminUser -ErrorAction SilentlyContinue
                Add-LocalGroupMember -Group 'Remote Management Users' -Member $AdminUser -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Could not create local break-glass account: $_" 'FAIL'
                $exitCode = 1
            }
        }
        # Record the password encrypted with DPAPI (decryptable only by this admin on this box)
        # AND print it once - if the transcript is protected, the team still has the console copy.
        # DPAPI is unavailable in session-0/network logons (WinRM); the blob is best-effort.
        $encFile = Join-Path $runDir 'lockout-admin-credentials.dapi'
        try {
            ConvertTo-SecureString $password -AsPlainText -Force | ConvertFrom-SecureString | Set-Content $encFile
        }
        catch {
            Write-Log "DPAPI encryption unavailable in this session (password still shown once + in transcript): $_" 'WARN'
        }
        Write-Log "Break-glass admin '$AdminUser' password (record it now, shown once): $password" 'CHANGE'
        $manifest.LockoutAdmin = $AdminUser
    } else {
        Write-Log "Skipping break-glass account creation (-SkipUserCreation)" 'WARN'
    }

    # ---------- 3. security policy backups ----------
    $policyDir = Join-Path $runDir 'policy'

    & secedit.exe /export /cfg (Join-Path $policyDir 'secedit-export.inf') /quiet
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Backed up local security policy (secedit)"
    }
    else {
        # secedit export fails in session-0/network-logon contexts (WinRM: "extended error")
        # but works at console. Not fatal: every secedit-managed value this toolkit touches
        # is also covered by the registry backups below.
        Write-Log 'secedit export failed in this session (known WinRM limitation; registry backups still cover restore)' 'WARN'
    }

    & auditpol.exe /backup /file:"$(Join-Path $policyDir 'audit-policy.csv')"
    if ($LASTEXITCODE -eq 0) { Write-Log "Backed up audit policy (auditpol)" } else { Write-Log "auditpol backup failed" 'FAIL'; $exitCode = 1 }

    & netsh.exe advfirewall export (Join-Path $policyDir 'firewall-policy.wfw') | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Log "Backed up firewall policy (netsh)" } else { Write-Log "netsh firewall export failed" 'FAIL'; $exitCode = 1 }

    # Group policy backup only exists on DCs; harmless to attempt elsewhere.
    try {
        if (Get-Command Backup-GPO -ErrorAction SilentlyContinue) {
            New-Item -ItemType Directory -Path (Join-Path $runDir 'gpo') -Force | Out-Null
            Backup-GPO -All -Path (Join-Path $runDir 'gpo') | Out-Null
            Write-Log "Backed up all GPOs"
        }
    } catch { Write-Log "GPO backup skipped: $_" 'WARN' }

    # ---------- 4. registry backups (keys the modules touch) ----------
    $regKeys = @()
    foreach ($key in $script:RegistryKeysTouched) {
        $exported = Backup-RegistryKey -KeyPath $key -BackupDir $runDir
        $regKeys += [pscustomobject]@{ Path = $key; Exported = $exported }
    }
    $manifest.RegistryKeys = $regKeys

    # ---------- 5. component state backups ----------
    $stateDir = Join-Path $runDir 'state'

    try {
        $smbServer = Get-SmbServerConfiguration
        $smbServer | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, `
            EnableSecuritySignature, EncryptData, RejectUnencryptedAccess, EnableInsecureGuestLogons |
            Export-Clixml (Join-Path $stateDir 'smb-server-config.xml')
        Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature, `
            EnableInsecureGuestLogons | Export-Clixml (Join-Path $stateDir 'smb-client-config.xml')
        Write-Log "Backed up SMB server/client configuration"
    } catch { Write-Log "SMB configuration backup failed: $_" 'WARN' }

    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $manifest.SMB1State = $smb1.State
        Write-Log "SMB1 feature current state: $($smb1.State)"
    } catch { Write-Log "Could not query SMB1 feature state: $_" 'WARN' }

    try {
        $mp = Get-MpPreference
        $mp | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, `
            DisableScriptScanning, DisableTamperProtection, AttackSurfaceReductionRules_Ids, `
            AttackSurfaceReductionOnlyExclusions, ExclusionPath, ExclusionExtension, `
            ExclusionProcess, ExclusionIpAddress | Export-Clixml (Join-Path $stateDir 'defender-preferences.xml')
        Write-Log "Backed up Defender preferences (incl. exclusions + ASR rules)"
    } catch { Write-Log "Defender preference backup skipped: $_" 'WARN' }

    # Share ACLs (module 15 sets non-exempt shares to read-only; restore needs the original ACEs).
    try {
        $shareAcls = foreach ($s in (Get-SmbShare)) {
            foreach ($ace in (Get-SmbShareAccess -Name $s.Name)) {
                [pscustomobject]@{ Share = $s.Name; Account = $ace.AccountName; AccessRight = $ace.AccessRight; AccessControlType = $ace.AccessControlType }
            }
        }
        $shareAcls | Export-Clixml (Join-Path $stateDir 'smb-share-acls.xml')
        Write-Log "Backed up SMB share ACLs"
    } catch { Write-Log "SMB share ACL backup skipped: $_" 'WARN' }

    # Spooler state (module 10 disables it; restore re-enables).
    try {
        $spooler = Get-Service Spooler -ErrorAction Stop
        $manifest | Add-Member -NotePropertyName SpoolerStartType -NotePropertyValue $spooler.StartType
        $manifest | Add-Member -NotePropertyName SpoolerStatus -NotePropertyValue $spooler.Status
    } catch { Write-Log "Spooler state not recorded: $_" 'WARN' }

    # Local group policy cache (module 13 resets it on non-DCs).
    try {
        $localGpoSrc = 'C:\Windows\System32\GroupPolicy', 'C:\Windows\System32\GroupPolicyUser'
        $localGpoDest = Join-Path $runDir 'state\local-gpo'
        New-Item -ItemType Directory -Path $localGpoDest -Force | Out-Null
        foreach ($src in $localGpoSrc) {
            if (Test-Path $src) { Copy-Item $src -Destination $localGpoDest -Recurse -Force }
        }
        Write-Log "Backed up local Group Policy cache"
    } catch { Write-Log "Local GPO backup skipped: $_" 'WARN' }

    # ---------- 6. system inventory snapshot (for before/after diffing) ----------
    $invDir = Join-Path $runDir 'inventory'
    try {
        Get-Service | Select-Object Name, DisplayName, Status, StartType |
            Export-Csv (Join-Path $invDir 'services.csv') -NoTypeInformation
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
            Export-Csv (Join-Path $invDir 'listening-ports.csv') -NoTypeInformation
        Get-SmbShare | Select-Object Name, Path, Description |
            Export-Csv (Join-Path $invDir 'shares.csv') -NoTypeInformation
        Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon |
            Export-Csv (Join-Path $invDir 'local-users.csv') -NoTypeInformation
        Write-Log "Inventory snapshot saved (services, ports, shares, users)"
    } catch { Write-Log "Inventory snapshot failed: $_" 'WARN' }

    Save-Manifest -BackupDir $runDir -Manifest $manifest
    Write-Log "PREFLIGHT COMPLETE - backups in $runDir. Safe to run Invoke-Harden.ps1." 'OK'
    if (-not $SkipUserCreation) {
        Write-Log "Recorded break-glass credentials: see console above and $runDir\lockout-admin-credentials.dapi" 'WARN'
    }
}
catch {
    Write-Log "PREFLIGHT FAILED: $_" 'FAIL'
    Write-Log ("  at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.Line.Trim()) 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
