# Invoke-Harden.ps1 - master runner for the hardening modules.
# Runs modules in numeric order, requires a preflight backup unless forced,
# and reports a pass/fail summary. Run Invoke-Verify.ps1 afterwards.
#
#   .\Invoke-Harden.ps1 -List
#   .\Invoke-Harden.ps1 -All
#   .\Invoke-Harden.ps1 -Modules Firewall,Defender
#   .\Invoke-Harden.ps1 -All -WhatIf        # show every change without applying
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$All,
    [string[]]$Modules,
    [switch]$List,
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\common.ps1"
Assert-Admin

# ---------- discover modules ----------
$moduleFiles = Get-ChildItem (Join-Path $PSScriptRoot 'modules') -Filter '*.ps1' | Sort-Object Name
if ($List) {
    Write-Host 'Available modules (run in this order with -All):'
    $moduleFiles | ForEach-Object {
        $name = $_.BaseName -replace '^\d+-', ''
        Write-Host ("  {0,-24} {1}" -f $name, $_.Name)
    }
    exit 0
}

if (-not $All -and -not $Modules) {
    throw 'Specify -All, -Modules <name>[,<name>...] or -List.'
}

# ---------- selection ----------
$selected = @()
if ($All) {
    $selected = $moduleFiles
}
else {
    foreach ($wanted in $Modules) {
        $match = $moduleFiles | Where-Object { $_.BaseName -like "$wanted" -or $_.BaseName -like "$wanted*" -or $_.BaseName -like "*$wanted*" } |
            Select-Object -First 1
        if ($match) { $selected += $match }
        else { Write-Log "No module matches '$wanted' (use -List to see names)" 'FAIL'; exit 1 }
    }
}

# ---------- safety rail: preflight backup ----------
if (-not $BackupDir) {
    $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force
}
if ($BackupDir) {
    Write-Log "Using preflight backup: $BackupDir"
}
else {
    Write-Log 'Running WITHOUT backup (-Force). Invoke-Restore.ps1 will have nothing to restore.' 'WARN'
}

# ---------- run ----------
$results = @()
foreach ($m in $selected) {
    Write-Log "===== module: $($m.BaseName) =====" 'INFO'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $m.FullName -BackupRoot $BackupRoot -BackupDir $BackupDir -Force:$Force -WhatIf:$WhatIfPreference
    $code = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }
    $sw.Stop()
    $results += [pscustomobject]@{
        Module = $m.BaseName
        Result = if ($code -eq 0) { 'PASS' } else { 'FAIL' }
        Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

# ---------- summary ----------
Write-Log '===== summary ====='
$results | Format-Table -AutoSize | Out-String -Stream | Write-Host
$failed = @($results | Where-Object Result -eq 'FAIL').Count
if ($failed -gt 0) {
    Write-Log "$failed module(s) failed - check logs under $BackupRoot\logs" 'FAIL'
    exit 1
}
Write-Log 'All modules completed. Run .\Invoke-Verify.ps1 to confirm services are healthy.' 'OK'
exit 0
