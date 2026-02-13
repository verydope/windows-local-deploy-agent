[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "C:\services\auto-deploy-agent\config.json",
    [Parameter(Mandatory = $false)]
    [string]$Pm2Path
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (-not $config.appRoot) {
    throw 'Config missing appRoot.'
}

$processName = if ($config.processName) { [string]$config.processName } elseif ($config.serviceName) { [string]$config.serviceName } else { $null }
if (-not $processName) {
    throw 'Config missing processName.'
}

if (-not $Pm2Path) {
    $Pm2Path = if ($config.pm2Path) { [string]$config.pm2Path } else { 'pm2' }
}

$appRoot = [string]$config.appRoot
$appDir = Join-Path $appRoot 'app'
$stateDir = Join-Path $appRoot 'state'
$logsDir = Join-Path $appRoot 'state\logs'
$stdoutLog = Join-Path $logsDir 'pm2-out.log'
$stderrLog = Join-Path $logsDir 'pm2-err.log'

function Resolve-AppEntrypoint {
    param(
        [Parameter(Mandatory = $true)][string]$AppPath,
        [Parameter(Mandatory = $false)][string]$ConfiguredEntrypoint
    )

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($ConfiguredEntrypoint)) {
        $normalized = [string]$ConfiguredEntrypoint
        if ([System.IO.Path]::IsPathRooted($normalized)) {
            $candidates += $normalized
        }
        else {
            $candidates += (Join-Path $AppPath $normalized)
        }
    }

    $candidates += @(
        (Join-Path $AppPath 'dist\src\main.js'),
        (Join-Path $AppPath 'dist\main.js'),
        (Join-Path $AppPath 'main.js')
    )

    $seen = @{}
    $uniqueCandidates = @()
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (-not $seen.ContainsKey($candidate)) {
            $seen[$candidate] = $true
            $uniqueCandidates += $candidate
        }
    }

    foreach ($candidate in $uniqueCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "App entrypoint not found. Checked: $($uniqueCandidates -join ', '). Set 'entryScript' in config to the built server entrypoint path."
}

if (-not (Test-Path -LiteralPath $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $stateDir)) {
    New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $appDir)) {
    New-Item -Path $appDir -ItemType Directory -Force | Out-Null
}

$appMain = Resolve-AppEntrypoint -AppPath $appDir -ConfiguredEntrypoint $config.entryScript

$exists = $false
$jlist = & $Pm2Path jlist 2>$null
if ($LASTEXITCODE -eq 0 -and $jlist) {
    $procs = ($jlist -join [Environment]::NewLine) | ConvertFrom-Json
    foreach ($p in @($procs)) {
        if ($p.name -eq $processName) {
            $exists = $true
            break
        }
    }
}

if ($exists) {
    & $Pm2Path delete $processName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to reset existing PM2 process '$processName'."
    }
}

$startArgs = @(
    'start',
    $appMain,
    '--name', $processName,
    '--cwd', $appDir,
    '--output', $stdoutLog,
    '--error', $stderrLog,
    '--time'
)

if ($config.nodeEnv) {
    $env:NODE_ENV = [string]$config.nodeEnv
}

& $Pm2Path @startArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to start PM2 process '$processName'. Resolved entrypoint: $appMain"
}

$enablePm2Startup = if ($null -ne $config.enablePm2Startup) { [bool]$config.enablePm2Startup } else { $true }
if ($enablePm2Startup) {
    $startupMarker = Join-Path $stateDir 'pm2-startup-registered.marker'
    if (-not (Test-Path -LiteralPath $startupMarker)) {
        $startupOutput = & $Pm2Path startup 2>&1
        if ($LASTEXITCODE -eq 0) {
            Set-Content -LiteralPath $startupMarker -Value (Get-Date -Format 'o') -Encoding ascii
        }
        else {
            Write-Warning "PM2 startup registration failed. Reboot auto-start may not be configured. Output: $($startupOutput -join [Environment]::NewLine)"
        }
    }
}

& $Pm2Path save | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to persist PM2 process list via `pm2 save`.'
}

Write-Host "PM2 bindings configured for process '$processName'."
