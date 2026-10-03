# Dev-only: parse-check all toolkit scripts. Run from repo root with pwsh.
# (Not part of the hardening toolkit; runs on the Linux dev machine.)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$files = Get-ChildItem -Path $root -Recurse -Filter '*.ps1' | Where-Object FullName -notmatch 'parse-check'
$failed = 0
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $failed++
        Write-Host "FAIL $($f.FullName)" -ForegroundColor Red
        foreach ($e in $errors) {
            Write-Host ("  line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message)
        }
    }
    else {
        Write-Host "PASS $($f.Name)"
    }
}
if ($failed -gt 0) { exit 1 } else { Write-Host 'All scripts parse cleanly.' -ForegroundColor Green; exit 0 }
