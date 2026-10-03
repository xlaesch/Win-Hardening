# download-tools.ps1 - fetch the large elastic binaries from GitHub Releases.
# Run once on the Ansible controller / toolkit staging host before deploying.
# The files land in tools\elastic\ and tools\elastic\win\ (gitignored).
#
#   .\scripts\download-tools.ps1
#   .\scripts\download-tools.ps1 -GitHubToken $env:GH_TOKEN   # private repo
[CmdletBinding()]
param(
    [string]$ReleaseTag = 'elastic-binaries',
    [string]$Repo = 'xlaesch/Win-Hardening',
    [string]$GitHubToken
)

$ErrorActionPreference = 'Stop'
$toolsElastic = Join-Path $PSScriptRoot '..\tools\elastic'
$toolsWin = Join-Path $toolsElastic 'win'
foreach ($d in @($toolsElastic, $toolsWin)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# TLS 1.2 for older PowerShell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{ 'User-Agent' = 'Win-Hardening' }
if ($GitHubToken) { $headers.Authorization = "Bearer $GitHubToken" }

Write-Host "Fetching release $ReleaseTag from $Repo..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$ReleaseTag" -Headers $headers

$total = [math]::Round(($release.assets | Measure-Object -Property size -Sum).Sum / 1MB)
Write-Host "Downloading $($release.assets.Count) files (~${total}MB)..."

foreach ($asset in $release.assets) {
    $dest = switch -Wildcard ($asset.name) {
        'elastic-agent-*' { Join-Path $toolsElastic $asset.name }
        default { Join-Path $toolsWin $asset.name }
    }
    if (Test-Path $dest) {
        $existing = (Get-Item $dest).Length
        if ($existing -eq $asset.size) {
            Write-Host "  $($asset.name): already present ($($existing) bytes)" -ForegroundColor Green
            continue
        }
    }
    Write-Host "  $($asset.name)..." -ForegroundColor Yellow
    $ProgressPreference = 0
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest -Headers $headers
    Write-Host "    downloaded: $((Get-Item $dest).Length) bytes" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Binaries in $toolsElastic and $toolsWin"
Write-Host "Verify SHA512 checksums in tools\elastic\ if present."
