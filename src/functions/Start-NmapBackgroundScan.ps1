# Start-NmapBackgroundScan.ps1
# Uses bundled tools.zip nmap.exe (preferred), then launches a full nmap scan
# of localhost in a background process. Sets $global:NmapScanXmlPath
# so the caller can later invoke Invoke-NmapRuleCreator.ps1.
#
# Safe to call multiple times -- skips if a scan is already running.

param(
    [Parameter(Mandatory = $true)]
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/Write-Log.ps1"
}

# Guard: don't launch if nmap is already running
$existingNmap = Get-Process -Name "nmap" -ErrorAction SilentlyContinue
if ($existingNmap) {
    Write-Log -Message "Nmap process already running (PID: $($existingNmap.Id -join ', ')). Skipping duplicate launch." -Level "INFO" -LogFile $LogFile
    return
}

Write-Log -Message "=== Dynamic Service Discovery (Nmap) ===" -Level "INFO" -LogFile $LogFile

# --- Locate nmap (prefer bundled tools.zip binary) ---
$nmapExe = $null
$nmapDataDir = $null
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolsDir = Join-Path $projectRoot "tools"
$toolsZip = Join-Path $projectRoot "tools.zip"
$preferredBundledNmap = Join-Path $toolsDir "nmap\nmap.exe"

if (Test-Path $toolsDir) {
    if (Test-Path $preferredBundledNmap) {
        $nmapExe = $preferredBundledNmap
        $nmapDataDir = Split-Path -Parent $preferredBundledNmap
        Write-Log -Message "Using bundled nmap package: $nmapExe" -Level "INFO" -LogFile $LogFile
    } else {
        $bundledNmap = Get-ChildItem -Path $toolsDir -Filter "nmap.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bundledNmap) {
            $nmapExe = $bundledNmap.FullName
            Write-Log -Message "Using bundled nmap binary: $nmapExe" -Level "INFO" -LogFile $LogFile
        }
    }
}

if (-not $nmapExe -and (Test-Path $toolsZip)) {
    if (-not (Test-Path $toolsDir)) {
        New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null
    }

    Write-Log -Message "Extracting tools.zip to locate bundled nmap.exe..." -Level "INFO" -LogFile $LogFile
    try {
        Expand-Archive -Path $toolsZip -DestinationPath $toolsDir -Force
        Write-Log -Message "tools.zip extracted to $toolsDir" -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to extract tools.zip: $_" -Level "ERROR" -LogFile $LogFile
    }

    if (Test-Path $preferredBundledNmap) {
        $nmapExe = $preferredBundledNmap
        $nmapDataDir = Split-Path -Parent $preferredBundledNmap
        Write-Log -Message "Using bundled nmap package after extraction: $nmapExe" -Level "INFO" -LogFile $LogFile
    } else {
        $bundledNmap = Get-ChildItem -Path $toolsDir -Filter "nmap.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bundledNmap) {
            $nmapExe = $bundledNmap.FullName
            Write-Log -Message "Using bundled nmap binary after extraction: $nmapExe" -Level "INFO" -LogFile $LogFile
        } else {
            Write-Log -Message "Bundled nmap.exe was not found after extracting tools.zip." -Level "WARNING" -LogFile $LogFile
        }
    }
} else {
    if (-not (Test-Path $toolsZip)) {
        Write-Log -Message "tools.zip not found at $toolsZip." -Level "WARNING" -LogFile $LogFile
    }
}

# Fallback: use existing local nmap install if bundled binary is unavailable.
if (-not $nmapExe) {
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        $nmapExe = (Get-Command nmap).Source
        Write-Log -Message "Using nmap from PATH: $nmapExe" -Level "INFO" -LogFile $LogFile
    } elseif (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe") {
        $nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"
        Write-Log -Message "Using nmap from default install path: $nmapExe" -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "No usable nmap executable found (bundled or local). Skipping dynamic scan." -Level "WARNING" -LogFile $LogFile
    }
}

if ($nmapExe -and -not (Test-Path $nmapExe)) {
    Write-Log -Message "Resolved nmap path does not exist: $nmapExe" -Level "ERROR" -LogFile $LogFile
    $nmapExe = $null
}

# Determine nmap data directory for portable runs.
if ($nmapExe -and -not $nmapDataDir) {
    $exeDir = Split-Path -Parent $nmapExe
    if (Test-Path (Join-Path $exeDir "nmap-services")) {
        $nmapDataDir = $exeDir
    } else {
        $knownBundledDataDir = Join-Path $toolsDir "nmap"
        if (Test-Path (Join-Path $knownBundledDataDir "nmap-services")) {
            $nmapDataDir = $knownBundledDataDir
        }
    }
}

# --- Launch background scan ---
if ($nmapExe) {
    $global:NmapScanXmlPath = Join-Path $env:TEMP "nmap_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    # Faster default profile: full TCP port sweep with service detection.
    $includeUdp = $false
    $udpPrompt = $null
    while ($udpPrompt -notmatch '^[YyNn]$') {
        $udpPrompt = Read-Host "Include UDP scan (top 200 ports)? [y/n]"
    }
    if ($udpPrompt -match '^[Yy]$') {
        $includeUdp = $true
    }

    $scanArgs = @("-sT", "-sV", "-T4", "-v", "--open", "-p-")
    if ($includeUdp) {
        $scanArgs += @("-sU", "--top-ports", "200")
        Write-Log -Message "UDP scan enabled by user prompt. Adding UDP scan for top 200 ports (this can increase runtime)." -Level "INFO" -LogFile $LogFile
    }
    $scanArgs += @("-oX", $global:NmapScanXmlPath, "localhost")

    $dataProbeDir = if ($nmapDataDir) { $nmapDataDir } else { Split-Path -Parent $nmapExe }
    $hasServiceProbes = Test-Path (Join-Path $dataProbeDir "nmap-service-probes")
    $hasPayloads = Test-Path (Join-Path $dataProbeDir "nmap-payloads")
    $hasServices = Test-Path (Join-Path $dataProbeDir "nmap-services")

    if (-not $hasServiceProbes) {
        $scanArgs = $scanArgs | Where-Object { $_ -ne "-sV" }
        Write-Log -Message "nmap-service-probes not found in '$dataProbeDir'. Disabling version scan (-sV)." -Level "WARNING" -LogFile $LogFile
    }
    if ($includeUdp -and -not $hasPayloads) {
        Write-Log -Message "nmap-payloads not found in '$dataProbeDir'. UDP payload matching may be limited." -Level "WARNING" -LogFile $LogFile
    }
    if (-not $hasServices) {
        Write-Log -Message "nmap-services not found in '$dataProbeDir'. Port/service mapping may be limited." -Level "WARNING" -LogFile $LogFile
    }
    if ($nmapDataDir) {
        $scanArgs = @("--datadir", $nmapDataDir) + $scanArgs
    }
    $scanArgsLiteral = "@(" + (($scanArgs | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ", ") + ")"

    $scanScript = @"
`$Host.UI.RawUI.WindowTitle = 'Nmap Scan -- localhost (all ports)'
try {
    `$nmapArgs = $scanArgsLiteral
    Write-Host 'Starting nmap scan...' -ForegroundColor Cyan
    Write-Host "Command: '$nmapExe' `$(`$nmapArgs -join ' ')" -ForegroundColor DarkGray
    & '$nmapExe' @nmapArgs
    `$exitCode = `$LASTEXITCODE
    if (`$exitCode -ne 0) {
        Write-Host "``nNmap exited with code `$exitCode" -ForegroundColor Red
        Write-Host 'Press any key to close...' -ForegroundColor Yellow
        `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }
} catch {
    `$_ | Out-File '$($global:NmapScanXmlPath).err'
    Write-Host "``nNmap error: `$_" -ForegroundColor Red
    Write-Host 'Press any key to close...' -ForegroundColor Yellow
    `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}
Write-Host '`nNmap scan complete. This window will close in 10 seconds...' -ForegroundColor Green
Start-Sleep -Seconds 10
"@

    Write-Log -Message "Launching nmap scan -> $($global:NmapScanXmlPath)" -Level "INFO" -LogFile $LogFile
    if ($nmapDataDir) {
        Write-Log -Message "Using nmap data directory: $nmapDataDir" -Level "INFO" -LogFile $LogFile
    }
    $scanLauncher = Start-Process powershell.exe -WorkingDirectory (Split-Path -Parent $nmapExe) -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $scanScript -WindowStyle Normal -PassThru
    $global:NmapScanHostPid = $scanLauncher.Id
    Write-Log -Message "Nmap scan launcher started (PID: $($global:NmapScanHostPid))." -Level "INFO" -LogFile $LogFile
    Write-Log -Message "Nmap scan running in visible window (all ports, high-verbosity profile). Results will be processed after all modules complete." -Level "INFO" -LogFile $LogFile
} else {
    Write-Log -Message "Nmap not available -- skipping dynamic service discovery." -Level "WARNING" -LogFile $LogFile
}
