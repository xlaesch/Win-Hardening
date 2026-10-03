# 22-ElasticStack.ps1 - run Elasticsearch + Kibana ON THIS Windows host as services.
# Designed for the competition pattern where the only boxes you control are the
# inherited Windows servers: agents ship to http://<this-host>:9200 with zero
# cross-network routing. Everything needed is vendored in tools\elastic\win\
# (ES + Kibana Windows zips, nssm for the Kibana service) - no internet required.
#
# One host runs the stack; the OTHERS run module 21 pointed at this host.
# Safe under -All (skips on non-designated hosts via -Designate or config).
#
#   .\22-ElasticStack.ps1 -Designate                          # this host runs the stack
#   .\Invoke-Harden.ps1 -Modules ElasticStack                 # skips unless designated
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BackupRoot = 'C:\HardeningBackups',
    [string]$BackupDir,
    [switch]$Force,
    [switch]$Designate,             # required: install the stack on THIS host
    [string]$InstallRoot = 'C:\Elastic',   # install destination (short path, no spaces usage)
    [string]$EsHeapMb = 1024,
    [int]$HttpPort = 9200,
    [int]$KibanaPort = 5601,
    [string]$StackPassword,         # elastic user password; default generated + printed
    [switch]$SkipRules              # install stack only, skip detection-rule setup
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"
Assert-Admin
if (-not $BackupDir) { $BackupDir = Get-LatestBackupOrThrow -BackupRoot $BackupRoot -Force:$Force }

$exitCode = 0
$null = Start-RunLog -Name 'elasticstack' -BackupRoot $BackupRoot
$toolsDir = Join-Path $PSScriptRoot '..\..\tools\elastic\win'

function Invoke-EsApi {
    param([string]$Method, [string]$Path, $Body = $null, [string]$EsUrl = "http://localhost:$HttpPort", [pscredential]$Cred = $null)
    $params = @{ Method = $Method; Uri = "$EsUrl$Path"; ContentType = 'application/json'; ErrorAction = 'SilentlyContinue' }
    if ($Cred) { $params.Credential = $Cred } elseif ($script:stackCred) { $params.Credential = $script:stackCred }
    if ($Body) { $params.Body = $Body }
    Invoke-RestMethod @params
}

function Invoke-KibanaApi {
    param([string]$Method, [string]$Path, $Body = $null)
    $h = @{ Authorization = 'Basic ' + [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("elastic:$script:stackPassword")) ; 'kbn-xsrf' = 'true' }
    $params = @{ Method = $Method; Uri = "http://localhost:$KibanaPort$Path"; Headers = $h; ContentType = 'application/json'; ErrorAction = 'SilentlyContinue' }
    if ($Body) { $params.Body = $Body }
    Invoke-RestMethod @params
}

try {
    # ---------- 0. gate ----------
    $cfg = Get-ElasticAgentConfig -ConfigDir (Join-Path $PSScriptRoot '..\files')
    $designated = $Designate -or ($cfg -and $cfg.StackHost -and $cfg.StackHost -eq $env:COMPUTERNAME)
    if (-not $designated) {
        Write-Log 'ElasticStack SKIPPED: this host is not the designated stack host (-Designate or StackHost in elastic-config.json).' 'WARN'
        exit 0
    }
    if (-not $StackPassword) {
        if ($cfg -and $cfg.StackPassword) { $StackPassword = $cfg.StackPassword }
        else { $StackPassword = (New-RandomPassword -Length 20) }
    }
    $script:stackPassword = $StackPassword
    $script:stackCred = New-Object PSCredential('elastic', (ConvertTo-SecureString $StackPassword -AsPlainText -Force))

    # ---------- 1. locate vendored zips ----------
    $esZip = Join-Path $toolsDir 'elasticsearch-9.5.4-windows-x86_64.zip'
    $kbZip = Join-Path $toolsDir 'kibana-9.5.4-windows-x86_64.zip'
    $nssm = Join-Path $toolsDir 'nssm.exe'
    foreach ($f in @($esZip, $kbZip, $nssm)) {
        if (-not (Test-Path $f)) { throw "Missing vendored file: $f (expected in tools\elastic\win\)" }
    }

    # ---------- 2. Elasticsearch ----------
    $esSvc = Get-Service elasticsearch-service -ErrorAction SilentlyContinue
    if (-not $esSvc) {
        Write-Log 'Installing Elasticsearch...'
        $esDir = Join-Path $InstallRoot 'elasticsearch'
        if (-not (Test-Path "$esDir\bin\elasticsearch.bat")) {
            if ($PSCmdlet.ShouldProcess('Elasticsearch', "extract to $esDir")) {
                New-Item -ItemType Directory -Path $esDir -Force | Out-Null
                Expand-Archive -Path $esZip -DestinationPath $InstallRoot -Force
                $inner = (Get-ChildItem $InstallRoot -Directory | Where-Object Name -like 'elasticsearch-*' | Select-Object -First 1).FullName
                if ($inner -ne $esDir) {
                    if (Test-Path $esDir) { Remove-Item $esDir -Recurse -Force }
                    Rename-Item $inner 'elasticsearch'
                }
            }
        }
        $esYml = @"
cluster.name: winhardening
node.name: `{0}`
network.host: 0.0.0.0
http.port: $HttpPort
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.license.self_generated.type: basic
path.data: $InstallRoot\elasticsearch\data
path.logs: $InstallRoot\elasticsearch\logs
"@ -f $env:COMPUTERNAME
        if ($PSCmdlet.ShouldProcess('elasticsearch.yml', 'write config')) {
            Set-Content -Path "$esDir\config\elasticsearch.yml" -Value $esYml -Encoding UTF8
            # heap sizing
            $jvm = "$esDir\config\jvm.options.d\heap.options"
            New-Item -ItemType Directory -Path "$esDir\config\jvm.options.d" -Force | Out-Null
            Set-Content -Path $jvm -Value "-Xms${EsHeapMb}m`r`n-Xmx${EsHeapMb}m" -Encoding ASCII   # ASCII: UTF8 BOM breaks the JVM parser
        }
        if ($PSCmdlet.ShouldProcess('Elasticsearch', 'install + start service')) {
            # bootstrap password via keystore so the API is reachable on first boot.
            # Password goes through a temp file piped by cmd: echo mangles specials,
            # and .bat files cannot take redirected stdin via ProcessStartInfo.
            # .bat tools write to stderr even on success - cmd-redirect everything
            # (2>&1 under EAP=Stop throws on native stderr).
            $esLog = Join-Path $env:TEMP 'es-install.log'
            & cmd.exe /c "`"$esDir\bin\elasticsearch-keystore.bat`" create --force > `"$esLog`" 2>&1"
            $pwFile = Join-Path $env:TEMP 'es-bootstrap-pw'
            [IO.File]::WriteAllText($pwFile, $StackPassword)
            & cmd.exe /c "type `"$pwFile`" | `"$esDir\bin\elasticsearch-keystore.bat`" add -x -f bootstrap.password >> `"$esLog`" 2>&1"
            Remove-Item $pwFile -Force -ErrorAction SilentlyContinue

            & cmd.exe /c "`"$esDir\bin\elasticsearch-service.bat`" install >> `"$esLog`" 2>&1"
            & cmd.exe /c "`"$esDir\bin\elasticsearch-service.bat`" start >> `"$esLog`" 2>&1"
            Get-Content $esLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "  es: $_" }
        }
        # wait for ES health
        Write-Log 'Waiting for Elasticsearch to accept connections (first boot takes 1-3 min)...'
        $ready = $false
        for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
            Start-Sleep -Seconds 5
            $ready = [bool](Invoke-EsApi 'GET' '/' -ErrorAction SilentlyContinue)
        }
        if (-not $ready) { throw 'Elasticsearch did not become ready in 5 minutes' }
        # set the real elastic password (bootstrap was same value; set explicitly)
        $null = Invoke-EsApi 'PUT' "/_cluster/settings" ('{"persistent":{"action.auto_create_index":"true"}}')
        Write-Log "Elasticsearch running on :$HttpPort (elastic / $StackPassword)" 'CHANGE'
        Add-ChangeRecord -BackupDir $BackupDir -Module 'ElasticStack' -Action 'InstallEs' `
            -Target 'elasticsearch-service' -NewValue "Running :$HttpPort" -WasAdded
    }
    else {
        Write-Log "Elasticsearch service already present ($($esSvc.Status))" 'OK'
        $ready = [bool](Invoke-EsApi 'GET' '/' -ErrorAction SilentlyContinue)
        if (-not $ready) {
            if ($PSCmdlet.ShouldProcess('elasticsearch-service', 'start')) { Start-Service elasticsearch-service }
            for ($i = 0; $i -lt 40 -and -not $ready; $i++) { Start-Sleep -Seconds 5; $ready = [bool](Invoke-EsApi 'GET' '/' -ErrorAction SilentlyContinue) }
        }
        if (-not $ready) { throw 'Elasticsearch not reachable' }
        Write-Log 'Elasticsearch reachable' 'OK'
    }

    # ---------- 3. Kibana (via NSSM service) ----------
    if (-not (Get-Service kibana-service -ErrorAction SilentlyContinue)) {
        Write-Log 'Installing Kibana...'
        $kbDir = Join-Path $InstallRoot 'kibana'
        if (-not (Test-Path "$kbDir\bin\kibana.bat")) {
            if ($PSCmdlet.ShouldProcess('Kibana', "extract to $kbDir")) {
                New-Item -ItemType Directory -Path $kbDir -Force | Out-Null
                Expand-Archive -Path $kbZip -DestinationPath $InstallRoot -Force
                $inner = (Get-ChildItem $InstallRoot -Directory | Where-Object Name -like 'kibana-*' | Select-Object -First 1).FullName
                if ($inner -ne $kbDir) {
                    if (Test-Path $kbDir) { Remove-Item $kbDir -Recurse -Force }
                    Rename-Item $inner 'kibana'
                }
            }
        }
        # Kibana needs an encryption key + cannot use the elastic superuser: create a service account token
        $tokResp = Invoke-EsApi 'POST' '/_security/service/elastic/kibana/credential/token/winhardening' -ErrorAction SilentlyContinue
        $kbToken = $tokResp.token.value
        if (-not $kbToken) { throw 'could not create Kibana service-account token' }
        $encKey = (New-RandomPassword -Length 42) -replace '[^A-Za-z0-9]', 'x'
        $kbYml = @"
server.port: $KibanaPort
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:$HttpPort"]
elasticsearch.serviceAccountToken: "$kbToken"
xpack.encryptedSavedObjects.encryptionKey: "$encKey"
logging.root.level: warn
"@
        if ($PSCmdlet.ShouldProcess('kibana.yml', 'write config')) {
            Set-Content -Path "$kbDir\config\kibana.yml" -Value $kbYml -Encoding UTF8
        }
        if ($PSCmdlet.ShouldProcess('kibana-service', 'install via NSSM + start')) {
            Copy-Item $nssm "$kbDir\nssm.exe" -Force
            $kbLog = Join-Path $env:TEMP 'kibana-install.log'
            & cmd.exe /c "`"$kbDir\nssm.exe`" install kibana-service `"$kbDir\node\bin\node.exe`" `"`"`"$kbDir\src\cli\dist\index.js`"`"`" > `"$kbLog`" 2>&1"
            & cmd.exe /c "`"$kbDir\nssm.exe`" set kibana-service AppDirectory `"$kbDir`" >> `"$kbLog`" 2>&1"
            & cmd.exe /c "`"$kbDir\nssm.exe`" set kibana-service AppStdout `"$kbDir\kibana-stdout.log`" >> `"$kbLog`" 2>&1"
            & cmd.exe /c "`"$kbDir\nssm.exe`" set kibana-service AppStderr `"$kbDir\kibana-stderr.log`" >> `"$kbLog`" 2>&1"
            Get-Content $kbLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "  nssm: $_" }
            Start-Service kibana-service
        }
        Write-Log 'Waiting for Kibana (1-3 min)...'
        $kready = $false
        for ($i = 0; $i -lt 60 -and -not $kready; $i++) {
            Start-Sleep -Seconds 5
            try { $null = Invoke-RestMethod "http://localhost:$KibanaPort/api/status" -ErrorAction Stop; $kready = $true } catch { }
        }
        if (-not $kready) { throw 'Kibana did not become ready' }
        Write-Log "Kibana running on :$KibanaPort" 'CHANGE'
        Add-ChangeRecord -BackupDir $BackupDir -Module 'ElasticStack' -Action 'InstallKibana' `
            -Target 'kibana-service' -NewValue "Running :$KibanaPort" -WasAdded
    }
    else {
        $kb = Get-Service kibana-service
        Write-Log "Kibana service already present ($($kb.Status))" 'OK'
    }

    if ($SkipRules) { Write-Log 'Skipping detection-rule setup (-SkipRules)' 'WARN'; exit 0 }

    # ---------- 4. ingest pipelines (pre-rendered JSON, no YAML on target) ----------
    $pipeDir = Join-Path $PSScriptRoot '..\files\elastic-pipelines'
    $manifest = Get-Content (Join-Path $pipeDir 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($p in $manifest.pipelines) {
        $body = Get-Content (Join-Path $pipeDir "$p.json") -Raw
        $null = Invoke-EsApi 'PUT' "/_ingest/pipeline/$p" $body
    }
    foreach ($t in $manifest.templates) {
        $null = Invoke-EsApi 'PUT' "/_index_template/$($t.name)" ($t.body | ConvertTo-Json -Depth 10)
    }
    Write-Log "Installed $($manifest.pipelines.Count) ingest pipelines + $($manifest.templates.Count) index templates" 'CHANGE'

    # ---------- 5. detection engine + prebuilt + curated ----------
    $null = Invoke-KibanaApi 'POST' '/api/detection_engine/index'
    $null = Invoke-EsApi 'POST' '/_license/start_trial?acknowledge=true' -ErrorAction SilentlyContinue
    $pp = Invoke-KibanaApi 'PUT' '/api/detection_engine/rules/prepackaged' '{}'
    Write-Log "Prebuilt rules installed: $($pp.rules_installed) (total library)" 'CHANGE'

    $curated = @(
        '48b6edfc-079d-4907-b43c-baffa243270d', '4e85dc8a-3e41-40d8-bc28-91af7ac6cf60',
        'f9790abf-bd0c-45f9-8b5f-d0b74015e029', '57bc9e8d-9054-472c-9752-4aa91dc4cd49',
        'e514d8cd-ed15-4011-84e2-d15147e059f1', 'd33ea3bf-9a11-463e-bd46-f648f2a0f4b1',
        '92a6faf5-78ec-4e25-bea1-73bacc9b59d9', '5cd8e1f7-0050-4afc-b2df-904e40b2f5ae',
        '128468bf-cab1-4637-99ea-fdf3780a4609', 'cde1bafa-9f01-4f43-a872-605b678968b0',
        'fddff193-48a3-484d-8d35-90bb3d323a56', 'fe794edd-487f-4a90-b285-3ee54f2af2d3'
    )
    $ids = @()
    foreach ($rid in $curated) {
        $r = Invoke-KibanaApi 'GET' "/api/detection_engine/rules?rule_id=$rid"
        if ($r -and $r.id) { $ids += $r.id }
    }
    if ($ids.Count -gt 0) {
        $null = Invoke-KibanaApi 'POST' '/api/detection_engine/rules/_bulk_action' (
            @{ action = 'enable'; ids = $ids } | ConvertTo-Json)
    }
    Write-Log "Enabled $($ids.Count) curated detection rules" 'CHANGE'

    # ---------- 6. custom rules ----------
    $ndjson = Get-Content (Join-Path $PSScriptRoot '..\files\ccdc-rules.ndjson') -ErrorAction SilentlyContinue
    if ($ndjson) {
        foreach ($line in $ndjson) {
            if (-not $line.Trim()) { continue }
            $obj = $line | ConvertFrom-Json
            $existing = Invoke-KibanaApi 'GET' "/api/detection_engine/rules?rule_id=$($obj.rule_id)"
            if (-not ($existing -and $existing.id)) {
                $null = Invoke-KibanaApi 'POST' '/api/detection_engine/rules' $line
                Write-Log "Custom rule created: $($obj.name)" 'CHANGE'
            }
        }
    }

    # ---------- 7. data views ----------
    foreach ($pat in @('logs-*', 'metrics-*', '.alerts-security.alerts-*')) {
        $null = Invoke-KibanaApi 'POST' '/api/saved_objects/index-pattern' (
            @{ attributes = @{ title = $pat; timeFieldName = '@timestamp' } } | ConvertTo-Json)
    }

    $myIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' } |
        Select-Object -First 1).IPAddress
    Write-Log "STACK READY. Kibana: http://${myIp}:$KibanaPort (elastic / $StackPassword)" 'OK'
    Write-Log "Agents: set ElasticUrl=http://${myIp}:$HttpPort in elastic-config.json + run module 21 on every host." 'OK'
}
catch {
    Write-Log "ElasticStack module FAILED: $_" 'FAIL'
    Write-Log ("  at line {0}" -f $_.InvocationInfo.ScriptLineNumber) 'FAIL'
    $exitCode = 1
}
finally {
    Stop-RunLog
}
exit $exitCode
