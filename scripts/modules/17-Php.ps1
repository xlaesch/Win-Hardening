# 17-Php.ps1 - PHP hardening where PHP exists.
# CPP php.ps1 parity: locate every php.ini actually loaded (via php --ini),
# then disable dangerous process-execution functions and file uploads.
# GOAD-Light has no PHP, but CCDC scenarios regularly do (WordPress etc.).
# NOTE: file_uploads=off breaks scored apps that accept uploads - pass
# -KeepUploads if the inject/scenario requires uploads to work.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$KeepUploads
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'php' -BackupRoot $BackupRoot
$disableLine = 'disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source'
$uploadLine = 'file_uploads=off'

function Find-PhpIni {
    # Prefer PATH, fall back to a filesystem sweep of common roots.
    $exes = @()
    $inPath = Get-Command php.exe -ErrorAction SilentlyContinue
    if ($inPath) { $exes += $inPath.Source }
    $exes += (Get-ChildItem 'C:\php*', 'C:\inetpub', 'C:\Program Files*', 'C:\xampp', 'C:\tools' -Recurse -Filter php.exe -Depth 4 -ErrorAction SilentlyContinue).FullName
    $inis = @()
    foreach ($exe in ($exes | Select-Object -Unique)) {
        if (-not $exe -or -not (Test-Path $exe)) { continue }
        # `php --ini` prints "Loaded Configuration File: <path>"
        $out = & $exe --ini 2>$null
        foreach ($line in $out) {
            if ($line -match 'Loaded Configuration File:\s*(.+)') {
                $p = $Matches[1].Trim()
                if ((Test-Path $p) -and $inis -notcontains $p) { $inis += $p }
            }
        }
    }
    return $inis
}

try {
    $inis = Find-PhpIni
    if ($inis.Count -eq 0) {
        Write-Log 'No PHP installations found - nothing to do.' 'OK'
        exit 0
    }
    Write-Log "Found $($inis.Count) php.ini file(s): $($inis -join '; ')"

    $iniBackups = Join-Path $BackupDir 'state\php'
    New-Item -ItemType Directory -Path $iniBackups -Force | Out-Null

    foreach ($ini in $inis) {
        $content = Get-Content $ini -Raw -ErrorAction Stop
        # Backup name = sanitized full path so Invoke-Restore can map it back.
        $bakName = ($ini -replace '[\\/:*?"<>|]', '_') + '.bak'
        Copy-Item $ini (Join-Path $iniBackups $bakName) -Force
        $changed = $false
        # Idempotency: PHP honors the LAST occurrence, but skip if already hardened.
        if ($content -match '(?m)^;\s*disable_functions\s*=' -or $content -match '(?m)^disable_functions=exec,') {
            Write-Log "$ini : disable_functions already present" 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess($ini, 'append disable_functions')) {
            Add-Content -Path $ini -Value $disableLine
            Write-Log "$ini : dangerous PHP functions disabled" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Php' -Action 'AppendIni' -Target $ini -NewValue 'disable_functions'
            $changed = $true
        }
        if ($KeepUploads) {
            Write-Log "$ini : file_uploads left enabled (-KeepUploads)" 'WARN'
        }
        elseif ($content -match '(?m)^file_uploads\s*=\s*off') {
            Write-Log "$ini : file_uploads already off" 'OK'
        }
        elseif ($PSCmdlet.ShouldProcess($ini, 'append file_uploads=off')) {
            Add-Content -Path $ini -Value $uploadLine
            Write-Log "$ini : file uploads disabled" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'Php' -Action 'AppendIni' -Target $ini -NewValue 'file_uploads=off'
            $changed = $true
        }
        if ($changed) {
            Write-Log "$ini : restart the app pool / web service to load new settings" 'WARN'
        }
    }
    Write-Log 'Php module complete.' 'OK'
}
catch {
    Write-Log "Php module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
