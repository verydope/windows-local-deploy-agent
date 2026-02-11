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
$appMain = Join-Path $appDir 'dist\src\main.js'
$logsDir = Join-Path $appRoot 'state\logs'
$stdoutLog = Join-Path $logsDir 'pm2-out.log'
$stderrLog = Join-Path $logsDir 'pm2-err.log'

if (-not (Test-Path -LiteralPath $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $appDir)) {
    New-Item -Path $appDir -ItemType Directory -Force | Out-Null
}

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
    throw "Failed to start PM2 process '$processName'. Ensure app\\dist\\src\\main.js exists first."
}

& $Pm2Path save | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to persist PM2 process list via `pm2 save`.'
}

Write-Host "PM2 bindings configured for process '$processName'."
