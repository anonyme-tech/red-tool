param(
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$ListenerId = "",
    [string]$ListenerName = "Local Audit Listener",
    [int]$ListenerPort = 8443
)

$ErrorActionPreference = "Stop"

function Assert-LoopbackUrl {
    param([string]$Url)

    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "Server URL is invalid: $Url"
    }

    if ($uri.Scheme -notin @("http", "https")) {
        throw "Server URL must use http or https."
    }

    if ($uri.Host -notin @("localhost", "127.0.0.1", "::1")) {
        throw "This helper only supports localhost listeners."
    }

    return "{0}://{1}" -f $uri.Scheme, $uri.Authority
}

function Invoke-JsonApi {
    param(
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Uri,
        [object]$Body = $null
    )

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri
    }

    return Invoke-RestMethod `
        -Method $Method `
        -Uri $Uri `
        -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 8)
}

$normalizedServerUrl = Assert-LoopbackUrl -Url $ServerUrl
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceRoot = Split-Path -Parent $scriptRoot
$agentProject = Join-Path $workspaceRoot "MyAgent\MyAgent.csproj"

if (-not (Test-Path $agentProject)) {
    throw "MyAgent project not found: $agentProject"
}

Write-Host "Checking local listener API..." -ForegroundColor Cyan
Invoke-JsonApi -Method GET -Uri "$normalizedServerUrl/api/health" | Out-Null

if ([string]::IsNullOrWhiteSpace($ListenerId)) {
    Write-Host "Creating a localhost audit listener..." -ForegroundColor Cyan
    $listener = Invoke-JsonApi `
        -Method POST `
        -Uri "$normalizedServerUrl/api/listeners/" `
        -Body @{
            name = $ListenerName
            protocol = "https"
            host = "127.0.0.1"
            port = $ListenerPort
            enabled = $true
        }

    $ListenerId = [string]$listener.listener_id
}
else {
    Write-Host "Loading listener '$ListenerId'..." -ForegroundColor Cyan
    $listener = Invoke-JsonApi -Method GET -Uri "$normalizedServerUrl/api/listeners/$ListenerId"
    if ($listener.status -ne "online") {
        Write-Host "Starting listener '$ListenerId'..." -ForegroundColor Yellow
        Invoke-JsonApi -Method POST -Uri "$normalizedServerUrl/api/listeners/$ListenerId/start" | Out-Null
    }
}

Write-Host "Running MyAgent audit and uploading JSON report..." -ForegroundColor Green
& dotnet run --project $agentProject -- --json --server $normalizedServerUrl --listener $ListenerId

Write-Host "Fetching latest stored report..." -ForegroundColor Cyan
$reports = Invoke-JsonApi -Method GET -Uri "$normalizedServerUrl/api/listeners/$ListenerId/audit-reports?limit=1"

if ($reports.total -gt 0) {
    $latest = $reports.reports[0]
    Write-Host ""
    Write-Host "Audit upload complete." -ForegroundColor Green
    Write-Host ("Listener ID : {0}" -f $ListenerId)
    Write-Host ("Report ID   : {0}" -f $latest.report_id)
    Write-Host ("Risk Level  : {0}" -f $latest.risk_level)
    Write-Host ("Findings    : {0}" -f $latest.finding_count)
    Write-Host ("API URL     : {0}/api/listeners/{1}/audit-reports/{2}" -f $normalizedServerUrl, $ListenerId, $latest.report_id)
}
else {
    Write-Warning "The upload command completed, but no audit report was returned by the API."
}
