[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:LogFile = $null
$script:LockStream = $null
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)

    if ($null -eq $InputObject) {
        return $null
    }

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
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][hashtable]$Default = @{}
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $Default
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $Default
        }

        $parsed = $raw | ConvertFrom-Json
        return (ConvertTo-Hashtable -InputObject $parsed)
    }
    catch {
        Write-Log -Level 'WARN' -Message "Could not parse JSON at '$Path'. Replacing with defaults. Error: $($_.Exception.Message)"
        return $Default
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $line = "[{0}][{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-DefaultState {
    return [ordered]@{
        currentVersion   = $null
        previousVersion  = $null
        currentReleaseId = $null
        lastCheckedUtc   = $null
        lastStatus       = 'noop'
        lastError        = $null
        lastDurationMs   = 0
    }
}

function New-DeployLock {
    param([Parameter(Mandatory = $true)][string]$LockPath)

    try {
        $script:LockStream = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    }
    catch {
        throw "Another deploy run is already active (lock file: $LockPath)."
    }
}

function Release-DeployLock {
    if ($script:LockStream) {
        $script:LockStream.Dispose()
        $script:LockStream = $null
    }
}

function Initialize-CredentialApi {
    if (-not ("Win32.NativeCred" -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;

namespace Win32 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static class NativeCred {
        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        public static extern void CredFree([In] IntPtr cred);
    }
}
'@
    }
}

function Get-StoredCredentialPassword {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $false)][string]$Username
    )

    Initialize-CredentialApi

    foreach ($credType in @(1, 2)) {
        $credPtr = [IntPtr]::Zero
        if (-not [Win32.NativeCred]::CredRead($Target, [uint32]$credType, 0, [ref]$credPtr)) {
            continue
        }

        try {
            $cred = [Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type][Win32.CREDENTIAL])
            if ($Username -and $cred.UserName -and $cred.UserName -ne $Username) {
                continue
            }
            if ($cred.CredentialBlobSize -le 0 -or $cred.CredentialBlob -eq [IntPtr]::Zero) {
                continue
            }
            return [Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, [int]($cred.CredentialBlobSize / 2))
        }
        finally {
            if ($credPtr -ne [IntPtr]::Zero) {
                [Win32.NativeCred]::CredFree($credPtr)
            }
        }
    }

    throw "Credential target '$Target' was not found in Windows Credential Manager."
}

function Invoke-GitHubApiGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][string]$Token
    )

    $headers = @{
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'windows-local-auto-deploy-agent'
    }
    if ($Token) {
        $headers.Authorization = "Bearer $Token"
    }

    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Invoke-GitHubDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $false)][string]$Token
    )

    $headers = @{
        Accept = 'application/octet-stream'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'windows-local-auto-deploy-agent'
    }
    if ($Token) {
        $headers.Authorization = "Bearer $Token"
    }

    Invoke-WebRequest -Uri $Uri -Headers $headers -OutFile $OutFile
}

function Get-LatestStableRelease {
    param(
        [Parameter(Mandatory = $true)][string]$RepoOwner,
        [Parameter(Mandatory = $true)][string]$RepoName,
        [Parameter(Mandatory = $true)][string]$ApiBase,
        [Parameter(Mandatory = $false)][string]$Token
    )

    $uri = "$ApiBase/repos/$RepoOwner/$RepoName/releases?per_page=30"
    $releases = Invoke-GitHubApiGet -Uri $uri -Token $Token
    if (-not $releases) {
        return $null
    }

    $stable = @($releases | Where-Object { -not $_.draft -and -not $_.prerelease })
    if ($stable.Count -eq 0) {
        return $null
    }

    return $stable | Sort-Object { [datetime]$_.published_at } -Descending | Select-Object -First 1
}

function Get-Asset {
    param(
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)][string]$AssetName
    )

    return $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
}

function Invoke-HealthCheck {
    param(
        [Parameter(Mandatory = $true)][string]$HealthUrl,
        [Parameter(Mandatory = $true)][int]$TimeoutSec,
        [Parameter(Mandatory = $true)][int]$Retries,
        [Parameter(Mandatory = $true)][int]$DelaySec
    )

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $HealthUrl -TimeoutSec $TimeoutSec
            if ($null -ne $response -and $response.status -eq 'ok') {
                Write-Log -Level 'INFO' -Message "Health check succeeded on attempt $attempt."
                return $true
            }
            Write-Log -Level 'WARN' -Message "Health check attempt $attempt returned invalid payload."
        }
        catch {
            Write-Log -Level 'WARN' -Message "Health check attempt $attempt failed: $($_.Exception.Message)"
        }

        if ($attempt -lt $Retries) {
            Start-Sleep -Seconds $DelaySec
        }
    }

    return $false
}

function Remove-PathForce {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function New-Junction {
    param(
        [Parameter(Mandatory = $true)][string]$LinkPath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        throw "Junction target does not exist: $TargetPath"
    }

    Remove-PathForce -Path $LinkPath

    try {
        New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath -Force | Out-Null
        return
    }
    catch {
        # Fall back to mklink for older environments with limited Junction support.
    }

    $mklinkOut = & cmd.exe /c mklink /J "$LinkPath" "$TargetPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create junction '$LinkPath' -> '$TargetPath'. mklink output: $mklinkOut"
    }
}

function Get-LinkTargetPath {
    param([Parameter(Mandatory = $true)][string]$Path)

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
        [Parameter(Mandatory = $true)][string]$Pm2Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $false)][bool]$IgnoreFailure = $false
    )

    $output = & $Pm2Path @Arguments 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $IgnoreFailure) {
        throw "PM2 command failed: $Pm2Path $($Arguments -join ' ')`n$output"
    }

    return $output
}

function Test-Pm2ProcessExists {
    param(
        [Parameter(Mandatory = $true)][string]$Pm2Path,
        [Parameter(Mandatory = $true)][string]$ProcessName
    )

    $json = Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('jlist')
    if ([string]::IsNullOrWhiteSpace(($json -join ''))) {
        return $false
    }

    try {
        $list = ($json -join [Environment]::NewLine) | ConvertFrom-Json
        foreach ($proc in @($list)) {
            if ($proc.name -eq $ProcessName) {
                return $true
            }
        }
        return $false
    }
    catch {
        throw "Unable to parse PM2 process list. $($_.Exception.Message)"
    }
}

function Stop-Pm2ProcessIfExists {
    param(
        [Parameter(Mandatory = $true)][string]$Pm2Path,
        [Parameter(Mandatory = $true)][string]$ProcessName
    )

    if (Test-Pm2ProcessExists -Pm2Path $Pm2Path -ProcessName $ProcessName) {
        Write-Log -Level 'INFO' -Message "Stopping PM2 process '$ProcessName'."
        Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('stop', $ProcessName) -IgnoreFailure $true | Out-Null
    }
}

function Start-Or-RestartPm2Process {
    param(
        [Parameter(Mandatory = $true)][string]$Pm2Path,
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [Parameter(Mandatory = $true)][string]$CurrentPath,
        [Parameter(Mandatory = $true)][string]$LogsPath,
        [Parameter(Mandatory = $false)][string]$NodeEnv
    )

    $mainScript = Join-Path $CurrentPath 'dist\main.js'
    if (-not (Test-Path -LiteralPath $mainScript)) {
        throw "App entrypoint not found: $mainScript"
    }

    $stdoutLog = Join-Path $LogsPath 'pm2-out.log'
    $stderrLog = Join-Path $LogsPath 'pm2-err.log'

    if (Test-Pm2ProcessExists -Pm2Path $Pm2Path -ProcessName $ProcessName) {
        $args = @('restart', $ProcessName, '--update-env')
        if ($NodeEnv) {
            $env:NODE_ENV = $NodeEnv
        }
        Invoke-Pm2 -Pm2Path $Pm2Path -Arguments $args | Out-Null
        return
    }

    $startArgs = @(
        'start',
        $mainScript,
        '--name', $ProcessName,
        '--cwd', $CurrentPath,
        '--output', $stdoutLog,
        '--error', $stderrLog,
        '--time'
    )

    if ($NodeEnv) {
        $env:NODE_ENV = $NodeEnv
    }

    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments $startArgs | Out-Null
    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('save') | Out-Null
}

function Install-ProductionDependencies {
    param([Parameter(Mandatory = $true)][string]$ReleasePath)

    Push-Location $ReleasePath
    try {
        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'pnpm-lock.yaml')) {
            Write-Log -Level 'INFO' -Message 'Installing production dependencies with pnpm.'
            & pnpm install --prod --frozen-lockfile --ignore-scripts
            if ($LASTEXITCODE -ne 0) { throw 'pnpm install failed.' }
            return
        }

        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'package-lock.json')) {
            Write-Log -Level 'INFO' -Message 'Installing production dependencies with npm ci.'
            & npm ci --omit=dev --ignore-scripts
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
            return
        }

        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'yarn.lock')) {
            Write-Log -Level 'INFO' -Message 'Installing production dependencies with yarn.'
            & yarn install --production --frozen-lockfile --ignore-scripts
            if ($LASTEXITCODE -ne 0) { throw 'yarn install failed.' }
            return
        }

        throw 'No supported lockfile found (pnpm-lock.yaml, package-lock.json, yarn.lock).'
    }
    finally {
        Pop-Location
    }
}

function Prune-OldReleases {
    param(
        [Parameter(Mandatory = $true)][string]$ReleasesRoot,
        [Parameter(Mandatory = $true)][string[]]$KeepTargets
    )

    $keep = @{}
    foreach ($target in $KeepTargets) {
        if ($target -and (Test-Path -LiteralPath $target)) {
            $keep[(Resolve-Path -LiteralPath $target).Path.ToLowerInvariant()] = $true
        }
    }

    Get-ChildItem -LiteralPath $ReleasesRoot -Directory | ForEach-Object {
        $full = $_.FullName
        if (-not $keep.ContainsKey($full.ToLowerInvariant())) {
            Write-Log -Level 'INFO' -Message "Pruning old release folder '$full'."
            Remove-Item -LiteralPath $full -Recurse -Force
        }
    }
}

function Invoke-Rollback {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $rollbackScript = Join-Path $PSScriptRoot 'rollback.ps1'
    if (-not (Test-Path -LiteralPath $rollbackScript)) {
        throw "Rollback script not found at '$rollbackScript'."
    }

    & $rollbackScript -ConfigPath $ConfigPath -Reason $Reason
    if ($LASTEXITCODE -ne 0) {
        throw 'Rollback script failed.'
    }
}

$swapPerformed = $false
$state = $null
$statePath = $null

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Read-JsonAsHashtable -Path $ConfigPath -Default @{}

    foreach ($field in @('repoOwner', 'repoName', 'appRoot', 'healthUrl')) {
        if (-not $config.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$config[$field])) {
            throw "Missing required config field '$field'."
        }
    }

    if (-not $config.ContainsKey('assetName')) { $config.assetName = 'server-win-x64.zip' }
    if (-not $config.ContainsKey('shaAssetName')) { $config.shaAssetName = 'build.sha256' }
    if (-not $config.ContainsKey('healthTimeoutSec')) { $config.healthTimeoutSec = 3 }
    if (-not $config.ContainsKey('healthRetries')) { $config.healthRetries = 3 }
    if (-not $config.ContainsKey('healthRetryDelaySec')) { $config.healthRetryDelaySec = 5 }
    if (-not $config.ContainsKey('credentialTarget')) { $config.credentialTarget = 'github.com' }
    if (-not $config.ContainsKey('credentialUser')) { $config.credentialUser = 'GITHUB' }
    if (-not $config.ContainsKey('githubApiBaseUrl')) { $config.githubApiBaseUrl = 'https://api.github.com' }
    if (-not $config.ContainsKey('pm2Path')) { $config.pm2Path = 'pm2' }
    if (-not $config.ContainsKey('processName') -or [string]::IsNullOrWhiteSpace([string]$config.processName)) {
        if ($config.ContainsKey('serviceName') -and -not [string]::IsNullOrWhiteSpace([string]$config.serviceName)) {
            $config.processName = [string]$config.serviceName
        }
        else {
            throw "Missing required config field 'processName'."
        }
    }

    $releasesRoot = Join-Path $config.appRoot 'releases'
    $stateRoot = Join-Path $config.appRoot 'state'
    $logsRoot = Join-Path $stateRoot 'logs'
    $tmpRoot = Join-Path $stateRoot 'tmp'
    $currentLink = Join-Path $config.appRoot 'current'
    $previousLink = Join-Path $config.appRoot 'previous'

    Ensure-Directory -Path $config.appRoot
    Ensure-Directory -Path $releasesRoot
    Ensure-Directory -Path $stateRoot
    Ensure-Directory -Path $logsRoot
    Ensure-Directory -Path $tmpRoot

    $script:LogFile = Join-Path $logsRoot ("deploy-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))

    $lockPath = Join-Path $stateRoot 'deploy.lock'
    New-DeployLock -LockPath $lockPath

    $statePath = Join-Path $stateRoot 'deployed.json'
    $state = Read-JsonAsHashtable -Path $statePath -Default (Get-DefaultState)

    $token = Get-StoredCredentialPassword -Target $config.credentialTarget -Username $config.credentialUser

    Write-Log -Level 'INFO' -Message "Checking releases for $($config.repoOwner)/$($config.repoName)."

    try {
        $release = Get-LatestStableRelease -RepoOwner $config.repoOwner -RepoName $config.repoName -ApiBase $config.githubApiBaseUrl -Token $token
    }
    catch {
        Write-Log -Level 'WARN' -Message "GitHub check failed. Skipping deploy: $($_.Exception.Message)"
        $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $state.lastStatus = 'noop'
        $state.lastError = "GitHub unavailable: $($_.Exception.Message)"
        $state.lastDurationMs = [int]$script:Stopwatch.ElapsedMilliseconds
        Write-JsonFile -Path $statePath -Data $state
        exit 0
    }

    if (-not $release) {
        Write-Log -Level 'INFO' -Message 'No stable release available. Exiting.'
        $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $state.lastStatus = 'noop'
        $state.lastError = $null
        $state.lastDurationMs = [int]$script:Stopwatch.ElapsedMilliseconds
        Write-JsonFile -Path $statePath -Data $state
        exit 0
    }

    $targetVersion = if ($release.tag_name) { [string]$release.tag_name } else { "release-$($release.id)" }
    $currentReleaseId = if ($state.currentReleaseId) { [string]$state.currentReleaseId } else { '' }

    if ($currentReleaseId -eq [string]$release.id -or ($state.currentVersion -and [string]$state.currentVersion -eq $targetVersion)) {
        Write-Log -Level 'INFO' -Message "No update required. Already on '$($state.currentVersion)'."
        $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $state.lastStatus = 'noop'
        $state.lastError = $null
        $state.lastDurationMs = [int]$script:Stopwatch.ElapsedMilliseconds
        Write-JsonFile -Path $statePath -Data $state
        exit 0
    }

    $zipAsset = Get-Asset -Release $release -AssetName $config.assetName
    $shaAsset = Get-Asset -Release $release -AssetName $config.shaAssetName
    if (-not $zipAsset) { throw "Release '$targetVersion' missing '$($config.assetName)'." }
    if (-not $shaAsset) { throw "Release '$targetVersion' missing '$($config.shaAssetName)'." }

    $runId = [guid]::NewGuid().ToString('N')
    $runRoot = Join-Path $tmpRoot $runId
    $extractRoot = Join-Path $runRoot 'extract'
    Ensure-Directory -Path $runRoot
    Ensure-Directory -Path $extractRoot

    $zipPath = Join-Path $runRoot $config.assetName
    $shaPath = Join-Path $runRoot $config.shaAssetName

    Write-Log -Level 'INFO' -Message "Downloading release '$targetVersion'."
    Invoke-GitHubDownload -Uri $zipAsset.url -OutFile $zipPath -Token $token
    Invoke-GitHubDownload -Uri $shaAsset.url -OutFile $shaPath -Token $token

    $expectedHashLine = (Get-Content -LiteralPath $shaPath -Raw).Trim()
    $expectedHash = ($expectedHashLine -split '\s+')[0].Trim().ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.Trim().ToLowerInvariant()

    if ($expectedHash -ne $actualHash) {
        throw "Hash mismatch. Expected $expectedHash got $actualHash."
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractRoot -Force

    $versionTxtPath = Join-Path $extractRoot 'version.txt'
    if (Test-Path -LiteralPath $versionTxtPath) {
        $artifactVersion = (Get-Content -LiteralPath $versionTxtPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($artifactVersion)) {
            $targetVersion = $artifactVersion
        }
    }

    $safeVersion = $targetVersion -replace '[^0-9A-Za-z._+-]', '_'
    $finalReleasePath = Join-Path $releasesRoot $safeVersion
    if (Test-Path -LiteralPath $finalReleasePath) {
        $finalReleasePath = Join-Path $releasesRoot ("{0}-{1}" -f $safeVersion, $release.id)
    }

    $stagingPath = "$finalReleasePath.staging"
    Remove-PathForce -Path $stagingPath
    Move-Item -LiteralPath $extractRoot -Destination $stagingPath

    Install-ProductionDependencies -ReleasePath $stagingPath

    Move-Item -LiteralPath $stagingPath -Destination $finalReleasePath
    Remove-PathForce -Path $runRoot

    $currentTarget = Get-LinkTargetPath -Path $currentLink

    Stop-Pm2ProcessIfExists -Pm2Path $config.pm2Path -ProcessName $config.processName

    if ($currentTarget) {
        New-Junction -LinkPath $previousLink -TargetPath $currentTarget
    }

    New-Junction -LinkPath $currentLink -TargetPath $finalReleasePath
    $swapPerformed = $true

    Start-Or-RestartPm2Process -Pm2Path $config.pm2Path -ProcessName $config.processName -CurrentPath $currentLink -LogsPath $logsRoot -NodeEnv $config.nodeEnv

    $healthy = Invoke-HealthCheck -HealthUrl $config.healthUrl -TimeoutSec ([int]$config.healthTimeoutSec) -Retries ([int]$config.healthRetries) -DelaySec ([int]$config.healthRetryDelaySec)
    if (-not $healthy) {
        throw 'Health check failed after deployment.'
    }

    $state.previousVersion = $state.currentVersion
    $state.currentVersion = [System.IO.Path]::GetFileName($finalReleasePath)
    $state.currentReleaseId = [string]$release.id
    $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.lastStatus = 'success'
    $state.lastError = $null
    $state.lastDurationMs = [int]$script:Stopwatch.ElapsedMilliseconds
    Write-JsonFile -Path $statePath -Data $state

    $keepTargets = @((Get-LinkTargetPath -Path $currentLink), (Get-LinkTargetPath -Path $previousLink))
    Prune-OldReleases -ReleasesRoot $releasesRoot -KeepTargets $keepTargets

    Write-Log -Level 'INFO' -Message "Deployment succeeded. Current version: $($state.currentVersion)."
    exit 0
}
catch {
    $err = $_.Exception.Message
    Write-Log -Level 'ERROR' -Message $err

    if ($swapPerformed) {
        try {
            Invoke-Rollback -ConfigPath $ConfigPath -Reason $err
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Rollback failed: $($_.Exception.Message)"
        }
    }

    if (-not $state) {
        $state = Get-DefaultState
    }

    if ($statePath) {
        $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $state.lastStatus = 'failed'
        $state.lastError = $err
        $state.lastDurationMs = [int]$script:Stopwatch.ElapsedMilliseconds
        Write-JsonFile -Path $statePath -Data $state
    }

    exit 1
}
finally {
    Release-DeployLock
}
