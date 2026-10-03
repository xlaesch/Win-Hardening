# Invoke-Hunt.ps1 - active-threat hunting (read-only).
# CPP parity: Webshell_Hunter.ps1 (cmd/powershell spawned by web workers) and
# Comp.ps1 event sweeps (7045 service creation, 4742 machine password change,
# 5140 IPC$ share access), plus Defender detection history.
#
#   .\Invoke-Hunt.ps1                  # one sweep, last 24h of events
#   .\Invoke-Hunt.ps1 -Hours 8
#   .\Invoke-Hunt.ps1 -Loop            # continuous webshell watch (Ctrl+C to stop)
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [switch]$Loop
)

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\common.ps1"
$null = Start-RunLog -Name 'hunt' -BackupRoot 'C:\HardeningBackups'
$exitCode = 0
$since = (Get-Date).AddHours(-$Hours)

function Get-ParentChain {
    param([int]$ProcessId)
    $names = @()
    $seen = @{}
    while ($ProcessId -and $ProcessId -ne 0 -and $ProcessId -ne 4 -and -not $seen[$ProcessId]) {
        $seen[$ProcessId] = $true
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if (-not $proc) { break }
        $names += $proc.Name
        $ProcessId = $proc.ParentProcessId
    }
    return $names
}

function Find-Webshells {
    # cmd.exe / powershell.exe whose ancestry includes a web worker = classic webshell.
    Write-Log "--- webshell scan (cmd/powershell under web workers) ---"
    $found = 0
    $webWorkers = 'w3wp.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe', 'tomcat*.exe'
    foreach ($p in (Get-CimInstance Win32_Process -Filter "name='cmd.exe' OR name='powershell.exe' OR name='pwsh.exe'")) {
        $chain = Get-ParentChain -ProcessId $p.ParentProcessId
        $hit = $false
        foreach ($w in $webWorkers) { if ($chain -like $w) { $hit = $true } }
        if ($hit) {
            $found++
            Write-Log ("WEBSHELL SUSPECT: PID {0} {1} <- {2}  cmdline: {3}" -f `
                $p.ProcessId, $p.Name, ($chain -join ' <- '), $p.CommandLine) 'FAIL'
        }
    }
    if ($found -eq 0) { Write-Log 'No webshell-suspect process trees.' 'OK' }
    return $found
}

try {
    do {
        $suspects = Find-Webshells

        Write-Log "--- event 7045: service installs (last $Hours h) ---"
        $svc = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -ErrorAction SilentlyContinue
        if ($svc) {
            foreach ($e in $svc) {
                Write-Log ("  {0}  svc='{1}' path='{2}' by {3}" -f `
                    $e.TimeCreated, $e.Properties[0].Value, $e.Properties[1].Value, $e.Properties[4].Value) 'WARN'
            }
        }
        else { Write-Log '  (none)' }

        Write-Log "--- event 4742: computer account password changes (last $Hours h) ---"
        $pwchg = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4742; StartTime = $since } -ErrorAction SilentlyContinue
        if ($pwchg) {
            foreach ($e in $pwchg) {
                Write-Log ("  {0}  computer={1} user={2}" -f `
                    $e.TimeCreated, $e.Properties[1].Value, $e.Properties[5].Value) 'WARN'
            }
        }
        else { Write-Log '  (none)' }

        Write-Log "--- event 5140: IPC$ share accesses (last $Hours h) ---"
        $ipc = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5140; StartTime = $since } -ErrorAction SilentlyContinue
        if ($ipc) {
            foreach ($e in $ipc) {
                $share = [string]$e.Properties[7].Value
                if ($share -match 'IPC') {
                    Write-Log ("  {0}  share={1} account={2} src={3}" -f `
                        $e.TimeCreated, $share, $e.Properties[1].Value, $e.Properties[5].Value) 'WARN'
                }
            }
        }
        else { Write-Log '  (none)' }

        Write-Log "--- Defender detections ---"
        try {
            $threats = Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $since }
            if ($threats) {
                foreach ($t in $threats) {
                    Write-Log ("  {0}  {1}  resources: {2}" -f `
                        $t.InitialDetectionTime, $t.ThreatID, (($t.Resources | Select-Object -First 3) -join '; ')) 'WARN'
                }
            }
            else { Write-Log '  (none)' }
        }
        catch { Write-Log "  Defender status unavailable: $_" }

        if ($Loop) {
            Write-Log "Loop mode: next sweep in 60s (Ctrl+C to stop)."
            Start-Sleep -Seconds 60
        }
    } while ($Loop)

    if ($suspects -gt 0) { $exitCode = 1 }
    Write-Log "Hunt complete ($($suspects) webshell suspect(s))." 'OK'
}
catch {
    Write-Log "Hunt FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
