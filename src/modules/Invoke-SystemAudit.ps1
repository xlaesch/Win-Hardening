# Invoke-SystemAudit.ps1
# Captures a comprehensive pre-hardening system state snapshot.
# Saves to a timestamped file under logs/ for competition inject use.
# Covers: local users/groups, processes, services, scheduled tasks,
# network connections, firewall rules, installed software, registry
# autoruns, shares, DNS, and basic threat-hunting checks.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

$ScriptRoot = (Resolve-Path "$PSScriptRoot/../..").Path
$AuditDir   = Join-Path $ScriptRoot "logs"
if (-not (Test-Path $AuditDir)) { New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null }

$AuditFile = Join-Path $AuditDir "system_audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt"

Write-Log -Message "Starting pre-hardening system audit snapshot -> $AuditFile" -Level "INFO" -LogFile $LogFile

function Write-Section {
    param([string]$Title, [scriptblock]$Block)
    $banner = "`n" + ("=" * 80) + "`n  $Title`n" + ("=" * 80) + "`n"
    Add-Content -Path $AuditFile -Value $banner
    try {
        $output = & $Block 2>&1 | Out-String
        Add-Content -Path $AuditFile -Value $output
    } catch {
        Add-Content -Path $AuditFile -Value "ERROR: $_"
    }
}

# ── Header ────────────────────────────────────────────────────────────────────
$header = @"
SYSTEM AUDIT SNAPSHOT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Hostname:  $env:COMPUTERNAME
Domain:    $env:USERDOMAIN
User:      $env:USERNAME
OS:        $((Get-CimInstance Win32_OperatingSystem).Caption)
DC:        $IsDomainController
"@
Set-Content -Path $AuditFile -Value $header

# ── Local Users & Groups ─────────────────────────────────────────────────────
Write-Section "LOCAL USERS" {
    Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, Description -AutoSize
}
Write-Section "LOCAL GROUPS & MEMBERS" {
    foreach ($g in Get-LocalGroup) {
        Write-Output "--- $($g.Name) ---"
        Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue |
            Format-Table Name, ObjectClass, PrincipalSource -AutoSize
    }
}

# ── Administrators ────────────────────────────────────────────────────────────
Write-Section "LOCAL ADMINISTRATORS" {
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Format-Table Name, ObjectClass, PrincipalSource -AutoSize
}

# ── Running Processes ─────────────────────────────────────────────────────────
Write-Section "RUNNING PROCESSES" {
    Get-Process | Sort-Object CPU -Descending |
        Select-Object Id, ProcessName, Path,
            @{N='CPU(s)';E={[math]::Round($_.CPU,2)}},
            @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} |
        Format-Table -AutoSize
}

# ── Services ──────────────────────────────────────────────────────────────────
Write-Section "ALL SERVICES" {
    Get-Service | Sort-Object Status, DisplayName |
        Select-Object Status, StartType, Name, DisplayName |
        Format-Table -AutoSize
}
Write-Section "NON-DEFAULT (RUNNING) SERVICES" {
    Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, StartMode, PathName, StartName |
        Sort-Object Name | Format-Table -AutoSize
}

# ── Scheduled Tasks ───────────────────────────────────────────────────────────
Write-Section "SCHEDULED TASKS (non-Microsoft)" {
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskName, TaskPath, State,
            @{N='Actions';E={ ($_.Actions | ForEach-Object { $_.Execute }) -join '; ' }} |
        Format-Table -AutoSize
}

# ── Network Connections ───────────────────────────────────────────────────────
Write-Section "NETWORK CONNECTIONS (ESTABLISHED + LISTENING)" {
    Get-NetTCPConnection | Where-Object { $_.State -in 'Established','Listen' } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Sort-Object State, LocalPort | Format-Table -AutoSize
}
Write-Section "UDP LISTENERS" {
    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
        Sort-Object LocalPort | Format-Table -AutoSize
}

# ── Firewall Rules ────────────────────────────────────────────────────────────
Write-Section "FIREWALL PROFILES" {
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
}
Write-Section "FIREWALL RULES (ENABLED)" {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
        Select-Object DisplayName, Direction, Action, Profile |
        Sort-Object Direction, DisplayName | Format-Table -AutoSize
}

# ── Shares ────────────────────────────────────────────────────────────────────
Write-Section "NETWORK SHARES" {
    Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize
}

# ── Installed Software ───────────────────────────────────────────────────────
Write-Section "INSTALLED SOFTWARE (REGISTRY)" {
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName | Format-Table -AutoSize
}

# ── Registry Autoruns ─────────────────────────────────────────────────────────
Write-Section "REGISTRY AUTORUNS" {
    $autorunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $autorunKeys) {
        if (Test-Path $key) {
            Write-Output "--- $key ---"
            Get-ItemProperty $key -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' } |
                        ForEach-Object { "  $($_.Name) = $($_.Value)" }
                }
        }
    }
}

# ── Startup Folder Contents ──────────────────────────────────────────────────
Write-Section "STARTUP FOLDER CONTENTS" {
    $startupPaths = @(
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $startupPaths) {
        Write-Output "--- $p ---"
        if (Test-Path $p) {
            Get-ChildItem $p -Force | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize
        } else { Write-Output "  (not found)" }
    }
}

# ── DNS Configuration ────────────────────────────────────────────────────────
Write-Section "DNS CLIENT CONFIGURATION" {
    Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
        Format-Table -AutoSize
}
Write-Section "HOSTS FILE" {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        Get-Content $hostsPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    }
}

# ── Audit Policy ──────────────────────────────────────────────────────────────
Write-Section "CURRENT AUDIT POLICY" {
    auditpol /get /category:*
}

# ── Local Security Policy Exports ────────────────────────────────────────────
Write-Section "LOCAL SECURITY POLICY (password/lockout)" {
    net accounts
}

# ── Open File Handles (Sysmon-style) ─────────────────────────────────────────
Write-Section "NAMED PIPES" {
    Get-ChildItem "\\.\pipe\" -ErrorAction SilentlyContinue |
        Select-Object Name | Sort-Object Name | Format-Table -AutoSize
}

# ── Threat Hunting ────────────────────────────────────────────────────────────
Write-Section "SUSPICIOUS PROCESSES (unsigned or odd paths)" {
    Get-Process | ForEach-Object {
        $proc = $_
        $path = $proc.Path
        if ($path) {
            $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') {
                [PSCustomObject]@{
                    PID   = $proc.Id
                    Name  = $proc.ProcessName
                    Path  = $path
                    SigStatus = $sig.Status
                }
            }
        }
    } | Format-Table -AutoSize
}

Write-Section "RECENTLY MODIFIED EXECUTABLES IN SYSTEM DIRS (last 3 days)" {
    $cutoff = (Get-Date).AddDays(-3)
    $systemDirs = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\Temp")
    foreach ($dir in $systemDirs) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Filter *.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff } |
                Select-Object FullName, LastWriteTime, Length
        }
    } | Format-Table -AutoSize
}

Write-Section "USERS WITH SID >= 1000 (potential hidden accounts)" {
    Get-LocalUser | Where-Object {
        $_.SID.Value -match 'S-1-5-21-.*-(\d+)$' -and [int]$Matches[1] -ge 1000
    } | Format-Table Name, Enabled, SID -AutoSize
}

# ── Domain Controller specific ────────────────────────────────────────────────
if ($IsDomainController) {
    Write-Section "AD DOMAIN ADMINS" {
        Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction SilentlyContinue |
            Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
    }
    Write-Section "AD ENTERPRISE ADMINS" {
        Get-ADGroupMember "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue |
            Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
    }
    Write-Section "AD USERS (enabled)" {
        Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate, PasswordLastSet |
            Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet |
            Sort-Object Name | Format-Table -AutoSize
    }
    Write-Section "GROUP POLICY OBJECTS" {
        Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime |
            Sort-Object DisplayName | Format-Table -AutoSize
    }
    Write-Section "DSQUERY TRUSTS" {
        nltest /domain_trusts 2>&1
    }
    Write-Section "REPLICATION STATUS" {
        repadmin /replsummary 2>&1
    }
}

Write-Log -Message "System audit snapshot saved to $AuditFile" -Level "SUCCESS" -LogFile $LogFile
Write-Host "System audit saved to: $AuditFile" -ForegroundColor Green
