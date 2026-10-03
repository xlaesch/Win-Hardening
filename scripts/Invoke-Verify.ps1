# Invoke-Verify.ps1 - prove scored services survived the hardening.
# Auto-detects the box's role (DC / IIS / MSSQL / member) and checks each service,
# plus the hardening state itself. Run after every module or full -All run.
#
#   .\Invoke-Verify.ps1
#   .\Invoke-Verify.ps1 -Json verify-after.json
[CmdletBinding()]
param(
    [string]$Json   # optional output file (path on this host) for before/after diffs
)

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\lib\common.ps1"

$exitCode = 0
$null = Start-RunLog -Name 'verify' -BackupRoot 'C:\HardeningBackups'
$results = @()

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail = '')
    $script:results += [pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail }
    $level = if ($Status -eq 'PASS') { 'OK' } elseif ($Status -eq 'FAIL') { 'FAIL' } else { 'WARN' }
    Write-Log ("{0,-28} {1,-5} {2}" -f $Check, $Status, $Detail) $level
    if ($Status -eq 'FAIL') { $script:exitCode = 1 }
}

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $domain = $cs.Domain
    $isDC = Test-IsDomainController
    $isDomainJoined = $cs.PartOfDomain
    Write-Log "Verifying $env:COMPUTERNAME (domain: $domain, DC: $isDC)"

    # ---------- role detection ----------
    $services = Get-Service
    $svcDNS = $services | Where-Object Name -eq 'DNS'
    $svcADWS = $services | Where-Object Name -eq 'ADWS'
    $svcNTDS = $services | Where-Object Name -eq 'NTDS'
    $svcIIS = $services | Where-Object Name -eq 'W3SVC'
    $svcSQL = $services | Where-Object { $_.Name -like 'MSSQL*' -and $_.Name -ne 'SQLSERVERAGENT' }

    # ---------- hardening state ----------
    foreach ($p in (Get-NetFirewallProfile)) {
        Add-Result "Firewall: $($p.Name)" $(if ($p.Enabled) { 'PASS' } else { 'FAIL' }) "Enabled=$($p.Enabled)"
    }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    Add-Result 'LmCompatibilityLevel' $(if ($lsa.LmCompatibilityLevel -eq 5) { 'PASS' } else { 'WARN' }) "value=$($lsa.LmCompatibilityLevel) (want 5)"
    Add-Result 'NoLMHash' $(if ($lsa.NoLMHash -eq 1) { 'PASS' } else { 'WARN' }) "value=$($lsa.NoLMHash) (want 1)"
    $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
    Add-Result 'WDigest off' $(if ($wdigest -eq 0) { 'PASS' } else { 'WARN' }) "UseLogonCredential=$wdigest (want 0)"
    $svcSysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    Add-Result 'Sysmon' $(if ($svcSysmon -and $svcSysmon.Status -eq 'Running') { 'PASS' } else { 'WARN' }) "service=$($svcSysmon.Status)"
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($mp) {
        Add-Result 'Defender realtime' $(if ($mp.RealTimeProtectionEnabled) { 'PASS' } else { 'FAIL' }) "enabled=$($mp.RealTimeProtectionEnabled)"
    }

    # ---------- management plane ----------
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    Add-Result 'WinRM service' $(if ($winrm -and $winrm.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) "status=$($winrm.Status)"
    try {
        $null = Test-WSMan -ErrorAction Stop
        Add-Result 'WinRM listener' 'PASS' 'responding'
    } catch { Add-Result 'WinRM listener' 'FAIL' $_.Exception.Message }
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
    Add-Result 'RDP' $(if ($rdp -eq 0) { 'PASS' } else { 'WARN' }) "fDenyTSConnections=$rdp (0 = enabled)"

    # ---------- central logging ----------
    $svcEA = Get-Service 'Elastic Agent' -ErrorAction SilentlyContinue
    if ($svcEA) {
        Add-Result 'Elastic Agent' $(if ($svcEA.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) "status=$($svcEA.Status)"
        $eaCfg = Get-ElasticAgentConfig -ConfigDir (Join-Path $PSScriptRoot 'files')
        if ($eaCfg) {
            try {
                $u = [uri]$eaCfg.ElasticUrl
                $p = if ($u.Port) { $u.Port } else { 9200 }
                $t = Test-NetConnection -ComputerName $u.Host -Port $p -WarningAction SilentlyContinue
                Add-Result 'Elasticsearch endpoint' $(if ($t.TcpTestSucceeded) { 'PASS' } else { 'WARN' }) "$($u.Host):$p reachable=$($t.TcpTestSucceeded) (queues locally if not)"
            } catch { Add-Result 'Elasticsearch endpoint' 'WARN' "untestable: $($_.Exception.Message)" }
        }
    }
    else { Add-Result 'Elastic Agent' 'WARN' 'not installed (run 21-ElasticAgent once configured)' }

    # ---------- DNS ----------
    if ($svcDNS -and $svcDNS.Status -eq 'Running') {
        try {
            $null = Resolve-DnsName $domain -Server localhost -ErrorAction Stop
            Add-Result 'DNS service' 'PASS' "resolved $domain via localhost"
        } catch { Add-Result 'DNS service' 'FAIL' "DNS running but query failed: $($_.Exception.Message)" }
    }
    else { Add-Result 'DNS service' 'WARN' 'not running on this host' }

    # ---------- Active Directory ----------
    if ($isDC) {
        Add-Result 'AD: NTDS' $(if ($svcNTDS.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) "status=$($svcNTDS.Status)"
        Add-Result 'AD: ADWS' $(if ($svcADWS -and $svcADWS.Status -eq 'Running') { 'PASS' } else { 'WARN' }) "status=$($svcADWS.Status)"
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        Add-Result 'AD: SYSVOL share' $(if ($shares.Name -contains 'SYSVOL') { 'PASS' } else { 'FAIL' }) ($(if ($shares.Name -contains 'SYSVOL') { 'present' } else { 'MISSING' }))
        Add-Result 'AD: NETLOGON share' $(if ($shares.Name -contains 'NETLOGON') { 'PASS' } else { 'FAIL' }) ($(if ($shares.Name -contains 'NETLOGON') { 'present' } else { 'MISSING' }))
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $u = Get-ADUser -Filter "SamAccountName -eq 'Administrator'" -ErrorAction Stop
            Add-Result 'AD: directory query' $(if ($u) { 'PASS' } else { 'FAIL' }) 'Get-ADUser responded'
        } catch { Add-Result 'AD: directory query' 'FAIL' $_.Exception.Message }
    }
    elseif ($isDomainJoined) {
        try { $nl = & nltest.exe /sc_verify:$domain 2>&1 | Out-String } catch { $nl = "$_" }
        Add-Result 'Domain: secure channel' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }) ($nl -replace '\s+', ' ').Trim()
    }

    # ---------- IIS ----------
    if ($svcIIS) {
        Add-Result 'IIS: W3SVC' $(if ($svcIIS.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) "status=$($svcIIS.Status)"
        if ($svcIIS.Status -eq 'Running') {
            try {
                $resp = Invoke-WebRequest -Uri 'http://localhost' -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                Add-Result 'IIS: local page' $(if ($resp.StatusCode -eq 200) { 'PASS' } else { 'FAIL' }) "HTTP $($resp.StatusCode)"
            } catch { Add-Result 'IIS: local page' 'FAIL' $_.Exception.Message }
        }
    }

    # ---------- MSSQL ----------
    if ($svcSQL) {
        $running = @($svcSQL | Where-Object Status -eq 'Running').Count
        Add-Result 'MSSQL service' $(if ($running -gt 0) { 'PASS' } else { 'FAIL' }) "$running of $($svcSQL.Count) instance(s) running"
        if ($running -gt 0) {
            $tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port 1433 -WarningAction SilentlyContinue
            Add-Result 'MSSQL port 1433' $(if ($tcp.TcpTestSucceeded) { 'PASS' } else { 'WARN' }) "listening=$($tcp.TcpTestSucceeded) (named instances use other ports)"
        }
    }

    # ---------- summary ----------
    Write-Log '===== verify summary ====='
    $results | Format-Table -AutoSize | Out-String -Stream | Where-Object { $_ } | Write-Host
    $fails = @($results | Where-Object Status -eq 'FAIL').Count
    if ($fails -gt 0) { Write-Log "$fails check(s) FAILED - investigate before the next scoring cycle." 'FAIL' }
    else { Write-Log 'All checks passed.' 'OK' }

    if ($Json) {
        [pscustomobject]@{
            Computer = $env:COMPUTERNAME
            Time     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Results  = $results
        } | ConvertTo-Json -Depth 4 | Set-Content $Json -Encoding UTF8
        Write-Log "Results written to $Json"
    }
}
catch {
    Write-Log "Verify FAILED to complete: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
