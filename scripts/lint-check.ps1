# Dev-only: PSScriptAnalyzer lint with PowerShell 5.1 compatibility syntax check.
# Run from repo root with pwsh. (Not part of the hardening toolkit.)
$ErrorActionPreference = 'Stop'
Import-Module /tmp/psa/PSScriptAnalyzer -Force

$settings = @{
    Rules    = @{
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
    Severity = @('Error', 'Warning')
}

$files = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1' |
    Where-Object FullName -notmatch 'lint-check|parse-check'
$findings = foreach ($f in $files) { Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings }
$findings | Format-Table ScriptName, Line, RuleName, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Host
$errors = @($findings | Where-Object Severity -eq 'Error')
$warnings = @($findings | Where-Object Severity -eq 'Warning')
Write-Host ("{0} error(s), {1} warning(s)" -f $errors.Count, $warnings.Count)
if ($errors.Count -gt 0) { exit 1 } else { exit 0 }
