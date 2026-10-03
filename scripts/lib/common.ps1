# common.ps1 - shared helpers for the Win-Hardening toolkit.
# Loaded (dot-sourced) by every script. Plain PowerShell 5.1, no dependencies.

$script:DefaultBackupRoot = 'C:\HardeningBackups'

# Registry keys any module in this toolkit may modify. Invoke-Preflight.ps1 backs
# all of them up; Invoke-Restore.ps1 re-imports them. Keep this list in sync with
# the modules - a key touched by a module but missing here cannot be restored.
$script:RegistryKeysTouched = @(
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
    'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces',
    # Cal Poly Pomona parity set:
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP',
    'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
    'HKLM\SYSTEM\CurrentControlSet\Services\LDAP',
    'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
    'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
)

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        throw 'This script must be run as Administrator.'
    }
}

function Test-IsDomainController {
    (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
}

function New-RandomPassword {
    # Crypto-RNG password with at least one of each character category
    # (Windows account policy requires 3+ categories).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([int]$Length = 20)
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digit = '23456789'
    $special = '!@#$%^&*()-_=+'
    $all = $lower + $upper + $digit + $special
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object 'byte[]' $Length
    $rng.GetBytes($bytes)
    $chars = @(
        $lower[$bytes[0] % $lower.Length]
        $upper[$bytes[1] % $upper.Length]
        $digit[$bytes[2] % $digit.Length]
        $special[$bytes[3] % $special.Length]
    )
    for ($i = 4; $i -lt $Length; $i++) {
        $chars += $all[$bytes[$i] % $all.Length]
    }
    # Shuffle so the guaranteed categories are not always the first four chars.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = $bytes[($i * 7 + 13) % $Length] % ($i + 1)
        $tmpChar = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmpChar
    }
    $rng.Dispose()
    -join $chars
}

function Write-Log {
    # Single logging path; Start-RunLog transcripts capture everything to file.
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'CHANGE', 'WARN', 'FAIL')][string]$Level = 'INFO'
    )
    $color = switch ($Level) {
        'OK'     { 'Green' }
        'CHANGE' { 'Yellow' }
        'WARN'   { 'DarkYellow' }
        'FAIL'   { 'Red' }
        default  { 'Gray' }
    }
    Write-Host ("[{0}] [{1,-6}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function Start-RunLog {
    # Logs are always written, even under -WhatIf: operators need the record of what
    # was (or would have been) done, so ShouldProcess is intentionally not used here.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([string]$Name, [string]$BackupRoot = $script:DefaultBackupRoot)
    $logDir = Join-Path $BackupRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $logFile = Join-Path $logDir ("{0}_{1}_{2}.log" -f $stamp, $env:COMPUTERNAME, $Name)
    try { Start-Transcript -Path $logFile -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript unavailable: $_" 'WARN' }
    return $logFile
}

function Stop-RunLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param()
    try { Stop-Transcript | Out-Null } catch { }
}

# ---------- backup run management ----------

function New-BackupRun {
    # Called only by Invoke-Preflight.ps1 (which carries the ShouldProcess decisions).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([string]$BackupRoot = $script:DefaultBackupRoot)
    $runDir = Join-Path $BackupRoot (Get-Date -Format 'yyyyMMdd-HHmmss')
    foreach ($sub in 'registry', 'policy', 'state', 'inventory') {
        New-Item -ItemType Directory -Path (Join-Path $runDir $sub) -Force | Out-Null
    }
    return $runDir
}

function Get-LatestBackupRun {
    param([string]$BackupRoot = $script:DefaultBackupRoot)
    if (-not (Test-Path $BackupRoot)) { return $null }
    $latest = Get-ChildItem -Path $BackupRoot -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'backup-manifest.json') } |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($latest) { return $latest.FullName } else { return $null }
}

function Get-Manifest {
    param([Parameter(Mandatory)][string]$BackupDir)
    $path = Join-Path $BackupDir 'backup-manifest.json'
    if (Test-Path $path) {
        return Get-Content $path -Raw | ConvertFrom-Json
    }
    return $null
}

function Save-Manifest {
    param([Parameter(Mandatory)][string]$BackupDir, [Parameter(Mandatory)]$Manifest)
    $Manifest | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $BackupDir 'backup-manifest.json') -Encoding UTF8
}

function Backup-RegistryKey {
    # Exports a registry key to <BackupDir>\registry\<safe-name>.reg.
    # Returns $true if the key existed (and was exported), $false if not.
    param(
        [Parameter(Mandatory)][string]$KeyPath,   # e.g. 'HKLM\SYSTEM\...\Lsa'
        [Parameter(Mandatory)][string]$BackupDir
    )
    # Absent keys must not throw: under $ErrorActionPreference=Stop the redirected
    # stderr of reg.exe ('unable to find the key') would otherwise abort the caller.
    $psPath = ($KeyPath -replace '^HKLM\\', 'HKLM:\') -replace '^HKCU\\', 'HKCU:\'
    if (-not (Test-Path $psPath)) {
        Write-Log "Registry key not present (nothing to back up): $KeyPath" 'WARN'
        return $false
    }
    $safeName = ($KeyPath -replace '[\\/:*?"<>|]', '_') + '.reg'
    $outFile = Join-Path $BackupDir ("registry\{0}" -f $safeName)
    try {
        $null = & reg.exe export $KeyPath $outFile /y 2>&1
    }
    catch { }
    if ($LASTEXITCODE -eq 0 -and (Test-Path $outFile)) {
        Write-Log "Backed up registry key: $KeyPath"
        return $true
    }
    Write-Log "Registry backup failed for $KeyPath" 'WARN'
    return $false
}

# ---------- change tracking ----------

function Add-ChangeRecord {
    # Appends a record to <BackupDir>\change-log.json so humans (and Invoke-Restore)
    # can see exactly what changed. oldValue is omitted for values that did not exist.
    param(
        [Parameter(Mandatory)][string]$BackupDir,
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        $NewValue,
        $OldValue = $null,
        [switch]$WasAdded
    )
    $logPath = Join-Path $BackupDir 'change-log.json'
    $entries = @()
    if (Test-Path $logPath) {
        try { $entries = @(Get-Content $logPath -Raw | ConvertFrom-Json) } catch { $entries = @() }
    }
    $entries += [pscustomobject]@{
        Time     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Module   = $Module
        Action   = $Action
        Target   = $Target
        NewValue = $NewValue
        OldValue = $OldValue
        WasAdded = [bool]$WasAdded
    }
    $entries | ConvertTo-Json -Depth 4 | Set-Content $logPath -Encoding UTF8
}

# ---------- idempotent setters ----------

function Set-RegistryValue {
    # Check-then-set for a single registry value. Idempotent, WhatIf-aware,
    # records the change. Returns $true if a change was (or would be) made.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type,   # DWord, String, QWord...
        [Parameter(Mandatory)]$Value,
        [string]$Module = 'unknown',
        [string]$BackupDir
    )
    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'create key')) {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $current.$Name -and $current.$Name -eq $Value) {
        Write-Log "$Path\$Name already set to $Value (no change)" 'OK'
        return $false
    }
    $oldValue = $null
    $wasAdded = $false
    if ($null -ne $current.$Name) { $oldValue = $current.$Name } else { $wasAdded = $true }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "set $Type = $Value (was: $(if ($wasAdded) {'<absent>'} else {$oldValue}))")) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Write-Log "$Path\$Name = $Value" 'CHANGE'
        if ($BackupDir) {
            Add-ChangeRecord -BackupDir $BackupDir -Module $Module -Action 'SetRegistryValue' `
                -Target "$Path\$Name" -NewValue $Value -OldValue $oldValue -WasAdded:$wasAdded
        }
        return $true
    }
    return $false
}

function Get-LatestBackupOrThrow {
    # Safety rail: modules refuse to run without a preflight backup unless forced.
    param([string]$BackupRoot = $script:DefaultBackupRoot, [switch]$Force)
    $latest = Get-LatestBackupRun -BackupRoot $BackupRoot
    if (-not $latest -and -not $Force) {
        throw "No preflight backup found under $BackupRoot. Run Invoke-Preflight.ps1 first, or pass -Force to run without a safety net."
    }
    if ($latest) { return $latest } else { return $null }
}

# ---------- Elastic Agent helpers (module 21; pure logic, unit-testable) ----------

function Get-ElasticAgentConfig {
    # Merges connection settings: explicit params > elastic-config.json > example defaults.
    # Returns $null when nothing real is configured (module should skip with a warning).
    param(
        [string]$ConfigDir,                  # scripts\files
        [string]$ElasticUrl,
        [string]$Username,
        [string]$Password,
        [string]$ApiKey,
        [string]$FleetUrl,
        [string]$EnrollmentToken
    )
    $cfg = $null
    foreach ($name in 'elastic-config.json', 'elastic-config.example.json') {
        $path = Join-Path $ConfigDir $name
        if (Test-Path $path) {
            try { $cfg = Get-Content $path -Raw | ConvertFrom-Json } catch { $cfg = $null }
            if ($cfg) { break }
        }
    }
    if (-not $cfg) { return $null }
    $merged = [pscustomobject]@{
        ElasticUrl     = if ($ElasticUrl)     { $ElasticUrl }     else { $cfg.ElasticUrl }
        Username       = if ($Username)       { $Username }       else { $cfg.Username }
        Password       = if ($Password)       { $Password }       else { $cfg.Password }
        ApiKey         = if ($ApiKey)         { $ApiKey }         else { $cfg.ApiKey }
        FleetUrl       = if ($FleetUrl)       { $FleetUrl }       else { $cfg.FleetUrl }
        EnrollmentToken = if ($EnrollmentToken) { $EnrollmentToken } else { $cfg.EnrollmentToken }
    }
    # Fleet mode is complete with just these two keys.
    if ($merged.FleetUrl -and $merged.EnrollmentToken) {
        if ("$($merged.FleetUrl)" -like '*YOUR-FLEET*') { return $null }
        return $merged
    }
    # Placeholder values from the example file mean "not configured" (standalone mode).
    foreach ($p in 'ElasticUrl', 'Password') {
        $v = [string]$merged.$p
        if ([string]::IsNullOrWhiteSpace($v)) { return $null }
        if ($v -like '*YOUR-ES*' -or $v -like '*CHANGE-ME*') { return $null }
    }
    return $merged
}

function New-ElasticAgentYml {
    # Builds a standalone (Fleet-less) elastic-agent.yml. $Channels maps channel
    # name -> data-set name; only channels present on this host should be passed.
    param(
        [Parameter(Mandatory)][string]$ElasticUrl,
        [string]$Username,
        [string]$Password,
        [string]$ApiKey,
        [string[]]$WinlogChannels = @('Security'),
        # Security -> system.security: that dataset carries the Elastic System
        # integration pipeline (installed by infra/elastic setup) producing the ECS
        # fields the polished detection rules query. Defender feeds the AV-detection rule.
        [hashtable]$DatasetMap = @{
            'Security'                                        = 'system.security'
            'System'                                          = 'windows.system'
            'Microsoft-Windows-Sysmon/Operational'            = 'windows.sysmon_operational'
            'Windows PowerShell'                              = 'windows.powershell'
            'Microsoft-Windows-PowerShell/Operational'        = 'windows.powershell_operational'
            'Microsoft-Windows-Windows Defender/Operational'  = 'windows.defender'
        },
        [switch]$IncludeMetrics
    )
    # Single-quote YAML scalars; escape embedded single quotes by doubling.
    function Format-YamlString([string]$s) { return "'{0}'" -f ($s -replace "'", "''") }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Generated by Win-Hardening 21-ElasticAgent - standalone (Fleet-less) configuration.')
    [void]$sb.AppendLine('outputs:')
    [void]$sb.AppendLine('  default:')
    [void]$sb.AppendLine('    type: elasticsearch')
    [void]$sb.AppendLine('    hosts:')
    [void]$sb.AppendLine("      - $(Format-YamlString $ElasticUrl)")
    if ($ApiKey) {
        [void]$sb.AppendLine("    api_key: $(Format-YamlString $ApiKey)")
    }
    else {
        [void]$sb.AppendLine("    username: $(Format-YamlString $Username)")
        [void]$sb.AppendLine("    password: $(Format-YamlString $Password)")
    }
    [void]$sb.AppendLine('agent.monitoring:')
    [void]$sb.AppendLine('  enabled: false')
    [void]$sb.AppendLine('inputs:')
    if ($WinlogChannels.Count -gt 0) {
        [void]$sb.AppendLine('  - id: winlog-input')
        [void]$sb.AppendLine('    type: winlog')
        [void]$sb.AppendLine('    use_output: default')
        [void]$sb.AppendLine('    data_stream:')
        [void]$sb.AppendLine('      namespace: default')
        [void]$sb.AppendLine('    streams:')
        foreach ($ch in $WinlogChannels) {
            $dataset = if ($DatasetMap[$ch]) { $DatasetMap[$ch] } else { 'windows.generic' }
            [void]$sb.AppendLine('      - data_stream:')
            [void]$sb.AppendLine("          dataset: $dataset")
            [void]$sb.AppendLine('          type: logs')
            [void]$sb.AppendLine("        name: $(Format-YamlString $ch)")
        }
    }
    if ($IncludeMetrics) {
        [void]$sb.AppendLine('  - id: system-metrics')
        [void]$sb.AppendLine('    type: system/metrics')
        [void]$sb.AppendLine('    use_output: default')
        [void]$sb.AppendLine('    data_stream:')
        [void]$sb.AppendLine('      namespace: default')
        [void]$sb.AppendLine('    streams:')
        foreach ($m in 'cpu', 'memory', 'network', 'filesystem') {
            [void]$sb.AppendLine('      - data_stream:')
            [void]$sb.AppendLine("          dataset: system.$m")
            [void]$sb.AppendLine('          type: metrics')
            [void]$sb.AppendLine('        metricsets:')
            [void]$sb.AppendLine("          - $m")
        }
    }
    return $sb.ToString()
}
