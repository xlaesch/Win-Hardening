# Invoke-NmapRuleCreator.ps1
# Waits for a background nmap scan to finish, parses the XML output,
# displays discovered open ports, and prompts the user to select which
# services should receive inbound allow firewall rules.

param(
    [Parameter(Mandatory = $true)]
    [string]$XmlPath,

    [Parameter()]
    $TrustedNetwork,

    [Parameter(Mandatory = $true)]
    [string]$LogFile,

    [int]$TimeoutSeconds = 1200
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/Write-Log.ps1"
}

# --- Helper: Add firewall rule (embedded copy for standalone use) ---
function Add-NmapFirewallRule {
    param(
        [string]$DisplayName,
        [string]$Direction,
        [string]$Protocol,
        [string]$LocalPort,
        [string]$RemoteAddress,
        [string]$Action = "Allow"
    )

    try {
        $params = @{
            DisplayName = $DisplayName
            Direction   = $Direction
            Action      = $Action
            Profile     = "Any"
        }
        if ($Protocol)      { $params.Add("Protocol", $Protocol) }
        if ($LocalPort)     { $params.Add("LocalPort", $LocalPort) }
        if ($RemoteAddress) { $params.Add("RemoteAddress", $RemoteAddress) }

        if (-not (Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule @params | Out-Null
            Write-Log -Message "Added Firewall Rule: $DisplayName" -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Firewall Rule already exists: $DisplayName" -Level "INFO" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to add rule '$DisplayName': $_" -Level "ERROR" -LogFile $LogFile
    }
}

function Test-NmapXmlComplete {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return $false
    }

    try {
        # Avoid loading large XML repeatedly; check tail for closing root tag.
        $tail = Get-Content -Path $Path -Tail 80 -ErrorAction Stop
        return (($tail -join "`n") -match '</nmaprun>')
    } catch {
        return $false
    }
}

# --- Wait for nmap XML output ---
Write-Host ""
Write-Host "Waiting for background nmap scan to complete..." -ForegroundColor Yellow
$elapsed = 0
$interval = 5
$xmlComplete = $false
$launcherPid = $global:NmapScanHostPid
while ($elapsed -lt $TimeoutSeconds) {
    # Check for error sidecar first so failures surface quickly.
    if (Test-Path "$XmlPath.err") {
        break
    }

    $xmlExists = Test-Path $XmlPath
    $xmlComplete = $xmlExists -and (Test-NmapXmlComplete -Path $XmlPath)
    $scanStillRunning = $false
    if ($launcherPid) {
        $scanStillRunning = $null -ne (Get-Process -Id $launcherPid -ErrorAction SilentlyContinue)
    }

    if ($xmlComplete -and (-not $launcherPid -or -not $scanStillRunning)) {
        break
    }

    Start-Sleep -Seconds $interval
    $elapsed += $interval
    if ($elapsed % 30 -eq 0) {
        Write-Host "  Still scanning... ($elapsed seconds elapsed)" -ForegroundColor DarkGray
    }
}

# Check for error sidecar
if (Test-Path "$XmlPath.err") {
    $errMsg = Get-Content "$XmlPath.err" -Raw
    Write-Log -Message "Nmap scan failed: $errMsg" -Level "ERROR" -LogFile $LogFile
    Write-Host "Nmap scan encountered an error. Check log for details." -ForegroundColor Red
    Remove-Item "$XmlPath.err" -Force -ErrorAction SilentlyContinue
    return
}

if (-not (Test-Path $XmlPath)) {
    Write-Log -Message "Nmap scan timed out after $TimeoutSeconds seconds." -Level "WARNING" -LogFile $LogFile
    Write-Host "Nmap scan timed out. Skipping dynamic rule creation." -ForegroundColor Red
    return
}

if (-not (Test-NmapXmlComplete -Path $XmlPath)) {
    Write-Log -Message "Nmap XML appears incomplete after $TimeoutSeconds seconds (missing </nmaprun>). Skipping dynamic rule creation." -Level "WARNING" -LogFile $LogFile
    Write-Host "Nmap output was incomplete. Skipping dynamic rule creation." -ForegroundColor Red
    return
}

Write-Log -Message "Nmap scan complete. Parsing results..." -Level "INFO" -LogFile $LogFile

# --- Parse nmap XML ---
$nmapXml = $null
$parseError = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        [xml]$nmapXml = Get-Content $XmlPath -Raw -ErrorAction Stop
        $parseError = $null
        break
    } catch {
        $parseError = $_.Exception.Message
        if ($attempt -lt 3) {
            Start-Sleep -Seconds 2
        }
    }
}
if (-not $nmapXml) {
    Write-Log -Message "Failed to parse nmap XML from '$XmlPath': $parseError" -Level "ERROR" -LogFile $LogFile
    Write-Host "Failed to parse nmap output." -ForegroundColor Red
    return
}

$openPorts = @()
$hosts = $nmapXml.nmaprun.host
if (-not $hosts) {
    Write-Log -Message "No hosts found in nmap output." -Level "WARNING" -LogFile $LogFile
    Write-Host "No hosts found in scan results." -ForegroundColor Yellow
    return
}

# Handle single host (not an array)
if ($hosts -isnot [array]) { $hosts = @($hosts) }

foreach ($h in $hosts) {
    $ports = $h.ports.port
    if (-not $ports) { continue }
    if ($ports -isnot [array]) { $ports = @($ports) }

    foreach ($p in $ports) {
        if ($p.state.state -eq "open") {
            $openPorts += [PSCustomObject]@{
                Port     = $p.portid
                Protocol = $p.protocol.ToUpper()
                Service  = if ($p.service.name) { $p.service.name } else { "unknown" }
            }
        }
    }
}

if ($openPorts.Count -eq 0) {
    Write-Log -Message "No open ports discovered by nmap." -Level "INFO" -LogFile $LogFile
    Write-Host "No open ports discovered." -ForegroundColor Yellow
    # Cleanup
    Remove-Item $XmlPath -Force -ErrorAction SilentlyContinue
    return
}

# Deduplicate and sort
$openPorts = $openPorts | Sort-Object { [int]$_.Port }, Protocol -Unique

Write-Log -Message "Discovered $($openPorts.Count) open port(s)." -Level "INFO" -LogFile $LogFile

# --- Display discovered services ---
Write-Host ""
Write-Host "=== Nmap Discovered Open Ports ===" -ForegroundColor Cyan
Write-Host ("{0,-5} {1,-8} {2,-6} {3}" -f "[#]", "Port", "Proto", "Service") -ForegroundColor White
Write-Host ("-" * 40) -ForegroundColor DarkGray

for ($i = 0; $i -lt $openPorts.Count; $i++) {
    $entry = $openPorts[$i]
    Write-Host ("{0,-5} {1,-8} {2,-6} {3}" -f "[$($i + 1)]", $entry.Port, $entry.Protocol, $entry.Service)
}

Write-Host ""

# --- Prompt for selection ---
while ($true) {
    $selection = Read-Host "Select rules to add (comma-separated numbers, 'all', or 'q' to skip)"

    if ($selection -match '^\s*(q|quit|skip)\s*$') {
        Write-Log -Message "User skipped dynamic rule creation." -Level "INFO" -LogFile $LogFile
        Write-Host "Skipped dynamic rule creation." -ForegroundColor Yellow
        break
    }

    if ($selection -match '^\s*all\s*$') {
        $selectedPorts = $openPorts
    } else {
        $indices = $selection -split "[,\s]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ - 1 } |
            Where-Object { $_ -ge 0 -and $_ -lt $openPorts.Count } |
            Sort-Object -Unique

        if ($indices.Count -eq 0) {
            Write-Warning "Invalid selection. Enter numbers from 1 to $($openPorts.Count), 'all', or 'q'."
            continue
        }

        $selectedPorts = $indices | ForEach-Object { $openPorts[$_] }
    }

    # Create firewall rules for selected ports
    $rulesCreated = 0
    foreach ($port in $selectedPorts) {
        $ruleName = "Nmap: $($port.Service) ($($port.Port)/$($port.Protocol))"
        Add-NmapFirewallRule `
            -DisplayName $ruleName `
            -Direction "Inbound" `
            -Protocol $port.Protocol `
            -LocalPort $port.Port `
            -RemoteAddress $TrustedNetwork
        $rulesCreated++
    }

    Write-Log -Message "Created $rulesCreated dynamic firewall rule(s) from nmap scan." -Level "SUCCESS" -LogFile $LogFile
    Write-Host "$rulesCreated rule(s) created." -ForegroundColor Green
    break
}

# --- Cleanup temp files ---
Remove-Item $XmlPath -Force -ErrorAction SilentlyContinue
Remove-Item "$XmlPath.err" -Force -ErrorAction SilentlyContinue
Write-Log -Message "Nmap temp files cleaned up." -Level "INFO" -LogFile $LogFile
