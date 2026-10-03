# Invoke-Inventory.ps1 - know the box before you touch it.
# Template: Cal Poly Pomona's CCDC Inventory.ps1 (national runner-up 2023/2024;
# altoid0.com writeups, github.com/cpp-cyber/blue). Their lesson: inventory runs
# FIRST, and mapping services to boxes is "quite literally gold" for remediation.
# Read-only. Collects: host/network basics, DNS records (DC), shares + permissions,
# IIS sites/bindings, interesting services, TCP connections, installed software,
# users & groups, registry startup entries, scheduled tasks, enabled features.
#
#   .\Invoke-Inventory.ps1                      # console + report file
#   .\Invoke-Inventory.ps1 -ReportDir C:\temp   # custom report location
[CmdletBinding()]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$ReportDir
)

$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\lib\common.ps1"
Assert-Admin

if (-not $ReportDir) { $ReportDir = Join-Path $BackupRoot 'inventory' }
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$reportFile = Join-Path $ReportDir ("{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = Start-RunLog -Name 'inventory' -BackupRoot $BackupRoot

function Out-Report {
    param([string]$Text = '')
    Write-Host $Text
    Add-Content -Path $reportFile -Value $Text -Encoding UTF8
}

function Section {
    param([Parameter(Mandatory)][string]$Name)
    Out-Report ''
    Out-Report ('=' * 70)
    Out-Report ("== {0}" -f $Name.ToUpper())
    Out-Report ('=' * 70)
}

function Out-Table {
    # Renders objects as a table into both console and report file.
    param($Objects, [string[]]$Properties)
    if (-not $Objects) { Out-Report '  (none)'; return }
    $Objects | Select-Object $Properties | Format-Table -AutoSize | Out-String -Width 200 | ForEach-Object { $_.TrimEnd() } | ForEach-Object { Out-Report $_ }
}

function Get-SharePermissions {
    # 'net share <name>' prints a permissions block; parsing it works on every version.
    param([string]$ShareName)
    $lines = & net.exe share $ShareName 2>$null
    ($lines | Where-Object { $_ -match '\S' -and $_ -notmatch '^-' }) -join ' | '
}

try {
    # ---------- 1. host & network basics ----------
    Section 'Host'
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $isDC = Test-IsDomainController
    $domain = $cs.Domain
    Out-Report ("  Host:      {0}.{1}" -f $env:COMPUTERNAME, $domain)
    Out-Report ("  OS:        {0} (installed {1})" -f $os.Caption, $os.InstallDate)
    Out-Report ("  Role:      {0}" -f $(if ($isDC) { 'Domain Controller' } elseif ($cs.PartOfDomain) { 'Domain member' } else { 'Workgroup' }))
    Out-Report ("  User:      {0}" -f (whoami.exe))
    Out-Report ("  Last boot: {0}  (uptime {1:d\.hh\:mm})" -f $os.LastBootUpTime, ((Get-Date) - $os.LastBootUpTime))
    Out-Report ''
    Out-Report '  IPv4 addresses:'
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" | ForEach-Object {
        $ipv4 = ($_.IPAddress | Where-Object { $_ -like '*.*' }) -join ', '
        Out-Report ("    {0}: {1}  gw={2}" -f $_.Description, $ipv4, ($_.DefaultIPGateway -join ', '))
        if ($_.DNSServerSearchOrder) {
            Out-Report ("    DNS servers: {0}" -f ($_.DNSServerSearchOrder -join ', '))
        }
    }

    # ---------- 2. DNS records (DC only) ----------
    if ($isDC) {
        Section 'DNS zone records (A/CNAME)'
        try {
            Import-Module DnsServer -ErrorAction Stop
            $records = Get-DnsServerResourceRecord -ZoneName $domain | Where-Object RecordType -in 'A', 'CNAME'
            Out-Table $records @('HostName', 'RecordType', 'TimeToLive', 'RecordData')
        }
        catch { Out-Report "  DnsServer module/query failed: $_" }
    }

    # ---------- 3. SMB shares & permissions ----------
    Section 'SMB shares'
    $shares = Get-CimInstance Win32_Share
    foreach ($s in $shares) {
        Out-Report ("  {0}  ->  {1}  ({2})" -f $s.Name, $s.Path, $s.Description)
        if ($s.Name -notmatch '\$') {
            Out-Report ("      perms: {0}" -f (Get-SharePermissions $s.Name))
        }
    }
    $adminShares = @($shares | Where-Object Name -match '\$$')
    Out-Report ("  Administrative shares present: {0}" -f $adminShares.Count)

    # ---------- 4. IIS sites & bindings ----------
    Section 'IIS'
    $svcIIS = Get-Service W3SVC
    if ($svcIIS) {
        Out-Report ("  W3SVC status: {0}" -f $svcIIS.Status)
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($site in Get-Website) {
                Out-Report ("  Site: {0}  ({1})  -> {2}" -f $site.Name, $site.State, $site.PhysicalPath)
                foreach ($b in $site.Bindings.Collection) {
                    Out-Report ("      binding: {0}://{1}:{2} host={3}" -f $b.Protocol, $b.Address, $b.Port, $b.HostName)
                }
            }
        }
        catch { Out-Report "  WebAdministration module failed: $_" }
    }
    else { Out-Report '  IIS not installed' }

    # ---------- 5. services of interest + suspicious paths ----------
    Section 'Services of interest'
    $patterns = 'mssql', 'mysql', 'mariadb', 'pgsql', 'postgres', 'apache', 'nginx', 'tomcat', 'httpd', 'mongo', 'ftp', 'filezilla', 'ssh', 'vnc', 'nssm', 'iis', 'w3svc', 'smtp', 'pop', 'imap'
    $interesting = Get-CimInstance Win32_Service |
        Where-Object { $n = $_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName; $hit = $false; foreach ($p in $patterns) { if ($n -like "*$p*") { $hit = $true } }; $hit }
    Out-Table $interesting @('Name', 'State', 'StartMode', 'StartName', 'PathName')
    Out-Report ''
    Out-Report '  Services NOT running from Windows/Program Files (possible persistence):'
    $suspicious = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and $_.PathName -notmatch '(?i)^\"?C:\\(Windows|Program Files( \(x86\))? )' -and $_.PathName -notmatch '(?i)system32'
    }
    Out-Table $suspicious @('Name', 'State', 'StartName', 'PathName')

    # ---------- 6. TCP connections ----------
    Section 'TCP connections (listening + established)'
    $tcp = Get-NetTCPConnection -State Listen, Established | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Local         = "{0}:{1}" -f $_.LocalAddress, $_.LocalPort
            Remote        = "{0}:{1}" -f $_.RemoteAddress, $_.RemotePort
            State         = $_.State
            PID           = $_.OwningProcess
            Process       = $proc.ProcessName
        }
    }
    Out-Table $tcp @('Local', 'Remote', 'State', 'PID', 'Process')

    # ---------- 7. installed software ----------
    Section 'Installed software'
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wow6432Node\*'
    )
    $software = Get-ItemProperty $uninstallPaths | Where-Object DisplayName |
        Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher
    Out-Table $software @('DisplayName', 'DisplayVersion', 'Publisher')

    # ---------- 8. users & groups ----------
    Section 'Users & groups'
    if ($isDC) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            foreach ($grp in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators') {
                $members = Get-ADGroupMember $grp -Recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
                Out-Report ("  {0}: {1}" -f $grp, ($members -join ', '))
            }
            Out-Report ''
            Out-Report '  Domain users (descriptions often leak passwords - GOAD plants one):'
            $users = Get-ADUser -Filter * -Properties Description, Enabled, PasswordLastSet |
                Sort-Object SamAccountName |
                Select-Object @{n = 'User'; e = { $_.SamAccountName } }, Enabled, PasswordLastSet, Description
            Out-Table $users @('User', 'Enabled', 'PasswordLastSet', 'Description')
        }
        catch { Out-Report "  ActiveDirectory module failed: $_" }
    }
    else {
        Out-Report '  Local Administrators:'
        $admins = Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544') -ErrorAction SilentlyContinue
        Out-Table $admins @('Name', 'PrincipalSource', 'ObjectClass')
        Out-Report '  Remote Desktop Users:'
        $rdp = Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue
        Out-Table $rdp @('Name', 'PrincipalSource', 'ObjectClass')
        Out-Report '  Local users:'
        $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
        Out-Table $users @('Name', 'Enabled', 'LastLogon', 'PasswordLastSet', 'Description')
    }

    # ---------- 9. registry startup entries ----------
    Section 'Registry startup entries'
    $startupKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $startupKeys) {
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { Out-Report ("  {0}  {1} = {2}" -f $key.Replace('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\', '...').Replace('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\', '...'), $_.Name, $_.Value) }
        }
    }
    Out-Report '  Winlogon:'
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($v in 'Shell', 'Userinit', 'AlternateShell', 'System') {
        Out-Report ("    {0} = {1}" -f $v, $winlogon.$v)
    }
    Out-Report '  Active Setup StubPaths (classic persistence):'
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -ErrorAction SilentlyContinue | ForEach-Object {
        $stub = (Get-ItemProperty $_.PSPath).StubPath
        if ($stub) { Out-Report ("    {0}  ->  {1}" -f $_.PSChildName, $stub) }
    }

    # ---------- 10. scheduled tasks (non-Microsoft) ----------
    Section 'Scheduled tasks (non-Microsoft)'
    $tasks = Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' | ForEach-Object {
        [pscustomobject]@{
            Path     = $_.TaskPath
            Name     = $_.TaskName
            State    = $_.State
            Action   = ($_.Actions | ForEach-Object { "{0} {1} {2}" -f $_.Execute, $_.Arguments, $_.WorkingDirectory }) -join ' ; '
        }
    }
    Out-Table $tasks @('Path', 'Name', 'State', 'Action')

    # ---------- 11. enabled Windows features ----------
    Section 'Enabled Windows features (slow - DISM)'
    $features = Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' |
        Select-Object FeatureName
    Out-Table $features @('FeatureName')

    # ---------- epilogue ----------
    Section 'Errors encountered'
    $newErrors = $Error | Select-Object -First 20
    if ($newErrors) {
        foreach ($e in $newErrors) { Out-Report ("  {0}" -f $e.Exception.Message) }
    }
    else { Out-Report '  (none)' }

    Section 'Report location'
    Out-Report ("  {0}" -f $reportFile)
    Write-Log "Inventory complete: $reportFile" 'OK'
}
catch {
    Write-Log "Inventory FAILED: $_" 'FAIL'
    exit 1
}
finally {
    Stop-RunLog
}
exit 0
