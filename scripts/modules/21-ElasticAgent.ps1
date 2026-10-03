# 21-ElasticAgent.ps1 - central logging via Elastic Agent (standalone, Fleet-less).
# Ships Security/Sysmon/PowerShell event channels + system metrics to the team's
# Elasticsearch server - the dashboards that answer inject questions ("top failed
# logins", "weird processes") and feed incident reports. CPP ran Elastic Stack at
# NCCDC 2024 for exactly this. Binaries are vendored in tools\elastic\ so the
# target needs NO internet; the winlog input works fully offline.
#
# Two modes:
#   FLEET (preferred): -FleetUrl http://<stack>:8220 -EnrollmentToken <tok> (or the
#     same keys in elastic-config.json) - agents get the team policy: integration
#     pipelines, dashboards, and Elastic's polished detection rules work.
#   STANDALONE (fallback): ElasticUrl + credentials only.
# Configure once: copy scripts\files\elastic-config.example.json to
# elastic-config.json and fill in the mode's keys (file is gitignored).
# Without a real config this module SKIPS with a warning (safe under -All).
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [string]$ElasticUrl,
    [string]$Username,
    [string]$Password,
    [string]$ApiKey,
    [string]$FleetUrl,
    [string]$EnrollmentToken,
    [string]$ZipPath,
    [switch]$SkipMetrics
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'elasticagent' -BackupRoot $BackupRoot
$serviceName = 'Elastic Agent'
$stagingRoot = 'C:\ProgramData\Hardening\ElasticAgent'
$installDir = 'C:\Program Files\Elastic\Agent'

try {
    # ---------- 1. connection config ----------
    $cfg = Get-ElasticAgentConfig -ConfigDir (Join-Path $PSScriptRoot '..\files') `
        -ElasticUrl $ElasticUrl -Username $Username -Password $Password -ApiKey $ApiKey `
        -FleetUrl $FleetUrl -EnrollmentToken $EnrollmentToken
    $fleetMode = $cfg -and $cfg.FleetUrl -and $cfg.EnrollmentToken
    if (-not $cfg) {
        Write-Log 'ElasticAgent SKIPPED: no real connection config.' 'WARN'
        Write-Log 'Copy scripts\files\elastic-config.example.json -> elastic-config.json and set ElasticUrl/Password,' 'WARN'
        Write-Log 'or pass -ElasticUrl/-Password (or -ApiKey). Then re-run this module.' 'WARN'
        exit 0
    }
    if ($fleetMode) { Write-Log "FLEET mode: enrolling against $($cfg.FleetUrl)" } else { Write-Log "Elasticsearch endpoint: $($cfg.ElasticUrl) $(if ($cfg.ApiKey) {'(API key auth)'} else {"(user: $($cfg.Username))"})" }

    # ---------- 2. vendored zip + integrity ----------
    if (-not $ZipPath) {
        $ZipPath = Get-ChildItem (Join-Path $PSScriptRoot '..\..\tools\elastic') -Filter 'elastic-agent-*-windows-x86_64.zip' -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $ZipPath -or -not (Test-Path $ZipPath)) {
        throw "Elastic Agent zip not found. Place it in tools\elastic\ or pass -ZipPath."
    }
    $shaFile = "$ZipPath.sha512"
    if (Test-Path $shaFile) {
        $expected = ((Get-Content $shaFile -First 1) -split '\s+')[0].Trim().ToUpper()
        $actual = (Get-FileHash $ZipPath -Algorithm SHA512).Hash.ToUpper()
        if ($expected -ne $actual) { throw "SHA512 mismatch on $ZipPath - do not deploy this zip." }
        Write-Log "Zip integrity verified (sha512 ok): $(Split-Path $ZipPath -Leaf)" 'OK'
    }
    else {
        Write-Log 'No .sha512 sidecar next to the zip - integrity check skipped.' 'WARN'
    }

    # ---------- 3. channels that exist on THIS box (Sysmon only after module 07) ----------
    $allChannels = 'Security', 'System', 'Microsoft-Windows-Sysmon/Operational',
        'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    $present = @($allChannels | Where-Object { Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue })
    if ($present.Count -eq 0) { $present = @('Security') }   # never ship nothing
    Write-Log "Winlog channels on this host: $($present -join ', ')"

    # ---------- 4. build the standalone configuration ----------
    $yml = New-ElasticAgentYml -ElasticUrl $cfg.ElasticUrl -Username $cfg.Username `
        -Password $cfg.Password -ApiKey $cfg.ApiKey -WinlogChannels $present `
        -IncludeMetrics:(-not $SkipMetrics)

    # ---------- 5. install or update ----------
    $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
    # Mode switches require uninstall first (output config is baked at install):
    # fleet-installed -> standalone, or standalone -> fleet.
    $installedAsFleet = Test-Path 'C:\Program Files\Elastic\Agent\fleet.enc'
    if ($svc -and ($installedAsFleet -ne $fleetMode)) {
        if ($PSCmdlet.ShouldProcess('standalone agent', 'uninstall before fleet enrollment')) {
            Push-Location $env:TEMP
            try { & 'C:\Program Files\Elastic\Agent\elastic-agent.exe' uninstall --force 2>&1 | ForEach-Object { Write-Log "  agent: $_" } } catch { Write-Log "  uninstall note: $_" 'WARN' }
            finally { Pop-Location }
            Start-Sleep -Seconds 5
            $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
            if ($svc) { Write-Log 'Standalone agent still present after uninstall - aborting fleet enroll' 'FAIL'; exit 1 }
        }
    }
    if (-not $svc) {
        $zipName = [IO.Path]::GetFileNameWithoutExtension($ZipPath)
        $stageDir = Join-Path $stagingRoot $zipName
        if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
        New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
        Write-Log "Extracting $(Split-Path $ZipPath -Leaf) (this can take a minute)..."
        Expand-Archive -Path $ZipPath -DestinationPath $stageDir -Force
        $agentDir = (Get-ChildItem $stageDir -Directory | Where-Object Name -like 'elastic-agent-*' | Select-Object -First 1).FullName
        if (-not $agentDir) { throw 'Extracted zip did not contain an elastic-agent-* folder.' }
        # Config must exist in the extracted folder BEFORE install copies it to Program Files.
        $yml | Set-Content (Join-Path $agentDir 'elastic-agent.yml') -Encoding UTF8
        if ($PSCmdlet.ShouldProcess('Elastic Agent', 'install as Windows service')) {
            Push-Location $agentDir
            try {
                $agentArgs = if ($fleetMode) { @('install', '--url', $cfg.FleetUrl, '--enrollment-token', $cfg.EnrollmentToken, '--force') } else { @('install', '--force') }
                try { & .\elastic-agent.exe @agentArgs 2>&1 | ForEach-Object { Write-Log "  agent: $_" } } catch { Write-Log "  agent output note: $_" 'WARN' }
            }
            finally { Pop-Location }
            Start-Sleep -Seconds 5
            $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
            if (-not $svc) { throw 'elastic-agent install did not create the service. See output above.' }
            Write-Log "Elastic Agent installed (service '$serviceName')" 'CHANGE'
            Add-ChangeRecord -BackupDir $BackupDir -Module 'ElasticAgent' -Action 'Install' `
                -Target $serviceName -NewValue "Installed -> $($cfg.ElasticUrl)" -WasAdded
        }
    }
    else {
        Write-Log "Elastic Agent already installed (service $($svc.Status))" 'OK'
        $installedYml = Join-Path $installDir 'elastic-agent.yml'
        if ((Test-Path $installedYml) -and ((Get-Content $installedYml -Raw) -ne $yml)) {
            if ($PSCmdlet.ShouldProcess($installedYml, 'update configuration + restart service')) {
                $yml | Set-Content $installedYml -Encoding UTF8
                Restart-Service $serviceName -Force
                Write-Log 'Elastic Agent configuration updated, service restarted' 'CHANGE'
                Add-ChangeRecord -BackupDir $BackupDir -Module 'ElasticAgent' -Action 'UpdateConfig' -Target $installedYml
            }
        }
        elseif (-not (Test-Path $installedYml)) {
            Write-Log "Installed config not found at $installedYml - leaving as-is" 'WARN'
        }
        else { Write-Log 'Elastic Agent configuration already current' 'OK' }
    }

    # ---------- 6. verify ----------
    Write-Log '--- verify ---'
    $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Write-Log "Service '$serviceName': Running" 'OK' }
    else { Write-Log "Service '$serviceName': $($svc.Status)" 'FAIL'; $exitCode = 1 }

    try {
        $uri = [uri]$cfg.ElasticUrl
        $port = if ($uri.Port) { $uri.Port } else { 9200 }
        $tcp = Test-NetConnection -ComputerName $uri.Host -Port $port -WarningAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) { Write-Log "Elasticsearch reachable at $($uri.Host):$port" 'OK' }
        else { Write-Log "Elasticsearch NOT reachable at $($uri.Host):$port - events queue locally until it is" 'WARN' }
    } catch { Write-Log "Could not test endpoint reachability: $_" 'WARN' }

    Write-Log 'Kibana: create a data view for logs-* (one-time) to see agent data in Discover.' 'INFO'
    Write-Log 'ElasticAgent module complete.' 'OK'
}
catch {
    Write-Log "ElasticAgent module FAILED: $_" 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
