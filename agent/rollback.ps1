[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [Parameter(Mandatory = $false)]
    [string]$Reason = 'Unknown deploy failure'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:LogFile = $null

function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in $InputObject.Keys) {
            $table[$key] = ConvertTo-Hashtable -InputObject $InputObject[$key]
        }
        return $table
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $list = @()
        foreach ($item in $InputObject) {
            $list += ,(ConvertTo-Hashtable -InputObject $item)
        }
        return $list
    }

    if ($InputObject -is [psobject]) {
        $props = $InputObject.PSObject.Properties
        if ($props.Count -gt 0) {
            $table = @{}
            foreach ($prop in $props) {
                $table[$prop.Name] = ConvertTo-Hashtable -InputObject $prop.Value
            }
            return $table
        }
    }

    return $InputObject
}

function Read-JsonAsHashtable {
    param(
        [string]$Path,
        [hashtable]$Default
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $Default
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $Default
        }
        return (ConvertTo-Hashtable -InputObject ($raw | ConvertFrom-Json))
    }
    catch {
        return $Default
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [hashtable]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function Write-Log {
    param([string]$Level, [string]$Message)

    $line = "[{0}][{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line
    }
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-PathForce {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function New-Junction {
    param([string]$LinkPath, [string]$TargetPath)

    Remove-PathForce -Path $LinkPath
    $null = & cmd.exe /c "mklink /J \"$LinkPath\" \"$TargetPath\""
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create junction '$LinkPath' -> '$TargetPath'."
    }
}

function Get-LinkTargetPath {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Target) {
        if ($item.Target -is [Array]) {
            return [string]$item.Target[0]
        }
        return [string]$item.Target
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Invoke-Pm2 {
    param(
        [string]$Pm2Path,
        [string[]]$Arguments,
        [bool]$IgnoreFailure = $false
    )

    $output = & $Pm2Path @Arguments 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $IgnoreFailure) {
        throw "PM2 command failed: $Pm2Path $($Arguments -join ' ')`n$output"
    }

    return $output
}

function Test-Pm2ProcessExists {
    param([string]$Pm2Path, [string]$ProcessName)

    $json = Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('jlist')
    if ([string]::IsNullOrWhiteSpace(($json -join ''))) {
        return $false
    }

    $list = ($json -join [Environment]::NewLine) | ConvertFrom-Json
    foreach ($proc in @($list)) {
        if ($proc.name -eq $ProcessName) {
            return $true
        }
    }

    return $false
}

function Stop-Pm2ProcessIfExists {
    param([string]$Pm2Path, [string]$ProcessName)

    if (Test-Pm2ProcessExists -Pm2Path $Pm2Path -ProcessName $ProcessName) {
        Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('stop', $ProcessName) -IgnoreFailure $true | Out-Null
    }
}

function Start-Or-RestartPm2Process {
    param(
        [string]$Pm2Path,
        [string]$ProcessName,
        [string]$CurrentPath,
        [string]$LogsPath,
        [string]$NodeEnv
    )

    $mainScript = Join-Path $CurrentPath 'dist\main.js'
    if (-not (Test-Path -LiteralPath $mainScript)) {
        throw "App entrypoint not found: $mainScript"
    }

    $stdoutLog = Join-Path $LogsPath 'pm2-out.log'
    $stderrLog = Join-Path $LogsPath 'pm2-err.log'

    if (Test-Pm2ProcessExists -Pm2Path $Pm2Path -ProcessName $ProcessName) {
        if ($NodeEnv) {
            $env:NODE_ENV = $NodeEnv
        }
        Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('restart', $ProcessName, '--update-env') | Out-Null
        return
    }

    if ($NodeEnv) {
        $env:NODE_ENV = $NodeEnv
    }

    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @(
        'start',
        $mainScript,
        '--name', $ProcessName,
        '--cwd', $CurrentPath,
        '--output', $stdoutLog,
        '--error', $stderrLog,
        '--time'
    ) | Out-Null

    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('save') | Out-Null
}

function Invoke-HealthCheck {
    param(
        [string]$HealthUrl,
        [int]$TimeoutSec,
        [int]$Retries,
        [int]$DelaySec
    )

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $HealthUrl -TimeoutSec $TimeoutSec
            if ($null -ne $response -and $response.status -eq 'ok') {
                return $true
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message "Rollback health check attempt $attempt failed: $($_.Exception.Message)"
        }

        if ($attempt -lt $Retries) {
            Start-Sleep -Seconds $DelaySec
        }
    }

    return $false
}

$start = Get-Date

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Read-JsonAsHashtable -Path $ConfigPath -Default @{}
    foreach ($field in @('appRoot', 'healthUrl')) {
        if (-not $config.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$config[$field])) {
            throw "Missing required config field '$field'."
        }
    }

    if (-not $config.ContainsKey('pm2Path')) { $config.pm2Path = 'pm2' }
    if (-not $config.ContainsKey('processName') -or [string]::IsNullOrWhiteSpace([string]$config.processName)) {
        if ($config.ContainsKey('serviceName') -and -not [string]::IsNullOrWhiteSpace([string]$config.serviceName)) {
            $config.processName = [string]$config.serviceName
        }
        else {
            throw "Missing required config field 'processName'."
        }
    }
    if (-not $config.ContainsKey('healthTimeoutSec')) { $config.healthTimeoutSec = 3 }
    if (-not $config.ContainsKey('healthRetries')) { $config.healthRetries = 3 }
    if (-not $config.ContainsKey('healthRetryDelaySec')) { $config.healthRetryDelaySec = 5 }

    $stateRoot = Join-Path $config.appRoot 'state'
    $logsRoot = Join-Path $stateRoot 'logs'
    $statePath = Join-Path $stateRoot 'deployed.json'
    $currentLink = Join-Path $config.appRoot 'current'
    $previousLink = Join-Path $config.appRoot 'previous'

    Ensure-Directory -Path $stateRoot
    Ensure-Directory -Path $logsRoot

    $script:LogFile = Join-Path $logsRoot ("deploy-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))

    $state = Read-JsonAsHashtable -Path $statePath -Default ([ordered]@{
        currentVersion   = $null
        previousVersion  = $null
        currentReleaseId = $null
        lastCheckedUtc   = $null
        lastStatus       = 'failed'
        lastError        = $null
        lastDurationMs   = 0
    })

    $previousTarget = Get-LinkTargetPath -Path $previousLink
    if (-not $previousTarget -or -not (Test-Path -LiteralPath $previousTarget)) {
        throw 'Rollback target does not exist. Previous release is unavailable.'
    }

    Write-Log -Level 'WARN' -Message "Starting rollback. Reason: $Reason"

    Stop-Pm2ProcessIfExists -Pm2Path $config.pm2Path -ProcessName $config.processName
    New-Junction -LinkPath $currentLink -TargetPath $previousTarget
    Start-Or-RestartPm2Process -Pm2Path $config.pm2Path -ProcessName $config.processName -CurrentPath $currentLink -LogsPath $logsRoot -NodeEnv $config.nodeEnv

    $healthy = Invoke-HealthCheck -HealthUrl $config.healthUrl -TimeoutSec ([int]$config.healthTimeoutSec) -Retries ([int]$config.healthRetries) -DelaySec ([int]$config.healthRetryDelaySec)
    if (-not $healthy) {
        throw 'Service did not pass health check after rollback.'
    }

    $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.lastStatus = 'failed'
    $state.lastError = "Rollback executed after failure: $Reason"
    $state.lastDurationMs = [int]((Get-Date) - $start).TotalMilliseconds
    Write-JsonFile -Path $statePath -Data $state

    Write-Log -Level 'INFO' -Message 'Rollback completed successfully.'
    exit 0
}
catch {
    Write-Log -Level 'ERROR' -Message "Rollback failed: $($_.Exception.Message)"
    exit 1
}
