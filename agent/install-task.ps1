[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "C:\services\auto-deploy-agent\config.json",
    [Parameter(Mandatory = $false)]
    [string]$TaskName = "VeryDopeAutoDeploy",
    [Parameter(Mandatory = $false)]
    [string]$TaskUser,
    [Parameter(Mandatory = $false)]
    [string]$TaskPassword
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$pollInterval = if ($config.pollIntervalMinutes) { [int]$config.pollIntervalMinutes } else { 10 }
if ($pollInterval -lt 1) {
    throw 'pollIntervalMinutes must be >= 1.'
}

$deployScript = Join-Path (Split-Path -Parent $ConfigPath) 'deploy.ps1'
if (-not (Test-Path -LiteralPath $deployScript)) {
    throw "deploy.ps1 not found next to config file: $deployScript"
}

$actionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$deployScript`" -ConfigPath `"$ConfigPath`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs

$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$recurringTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $pollInterval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if ($TaskUser) {
    if (-not $TaskPassword) {
        throw 'TaskPassword is required when TaskUser is provided.'
    }

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($startupTrigger, $recurringTrigger) -Settings $settings -User $TaskUser -Password $TaskPassword | Out-Null
}
else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($startupTrigger, $recurringTrigger) -Settings $settings | Out-Null
}

Write-Host "Scheduled task '$TaskName' installed with $pollInterval-minute polling."
