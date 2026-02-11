[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json"
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

        return (ConvertTo-Hashtable -InputObject ($raw | ConvertFrom-Json))
    }
    catch {
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

function Remove-PathForce {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Invoke-GitHubApiGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][string]$Token
    )

    $headers = @{
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'windows-local-deploy-agent'
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
        'User-Agent' = 'windows-local-deploy-agent'
    }
    if ($Token) {
        $headers.Authorization = "Bearer $Token"
    }

    Invoke-WebRequest -Uri $Uri -Headers $headers -OutFile $OutFile
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

function Install-Dependencies {
    param([Parameter(Mandatory = $true)][string]$ReleasePath)

    Push-Location $ReleasePath
    try {
        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'pnpm-lock.yaml')) {
            & pnpm install
            if ($LASTEXITCODE -ne 0) { throw 'pnpm install failed.' }
            return
        }

        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'package-lock.json')) {
            & npm ci
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
            return
        }

        if (Test-Path -LiteralPath (Join-Path $ReleasePath 'yarn.lock')) {
            & yarn install --frozen-lockfile
            if ($LASTEXITCODE -ne 0) { throw 'yarn install failed.' }
            return
        }

        throw 'No supported lockfile found (pnpm-lock.yaml, package-lock.json, yarn.lock).'
    }
    finally {
        Pop-Location
    }
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

    $list = ($json -join [Environment]::NewLine) | ConvertFrom-Json
    foreach ($proc in @($list)) {
        if ($proc.name -eq $ProcessName) {
            return $true
        }
    }
    return $false
}

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

function Start-Pm2ProcessFresh {
    param(
        [Parameter(Mandatory = $true)][string]$Pm2Path,
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [Parameter(Mandatory = $true)][string]$AppPath,
        [Parameter(Mandatory = $true)][string]$LogsPath,
        [Parameter(Mandatory = $false)][string]$EntryScript,
        [Parameter(Mandatory = $false)][string]$NodeEnv
    )

    $mainScript = Resolve-AppEntrypoint -AppPath $AppPath -ConfiguredEntrypoint $EntryScript

    if (Test-Pm2ProcessExists -Pm2Path $Pm2Path -ProcessName $ProcessName) {
        Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('delete', $ProcessName) -IgnoreFailure $true | Out-Null
    }

    $stdoutLog = Join-Path $LogsPath 'pm2-out.log'
    $stderrLog = Join-Path $LogsPath 'pm2-err.log'

    if ($NodeEnv) {
        $env:NODE_ENV = $NodeEnv
    }

    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @(
        'start',
        $mainScript,
        '--name', $ProcessName,
        '--cwd', $AppPath,
        '--output', $stdoutLog,
        '--error', $stderrLog,
        '--time'
    ) | Out-Null

    Invoke-Pm2 -Pm2Path $Pm2Path -Arguments @('save') | Out-Null
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Read-JsonAsHashtable -Path $ConfigPath -Default @{}
    foreach ($field in @('repoOwner', 'repoName', 'appRoot')) {
        if (-not $config.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$config[$field])) {
            throw "Missing required config field '$field'."
        }
    }

    if (-not $config.ContainsKey('assetName')) { $config.assetName = 'server-win-x64.zip' }
    if (-not $config.ContainsKey('shaAssetName')) { $config.shaAssetName = 'build.sha256' }
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

    $appPath = Join-Path $config.appRoot 'app'
    $stateRoot = Join-Path $config.appRoot 'state'
    $logsRoot = Join-Path $stateRoot 'logs'
    $tmpRoot = Join-Path $stateRoot 'tmp'
    $statePath = Join-Path $stateRoot 'deployed.json'

    Ensure-Directory -Path $config.appRoot
    Ensure-Directory -Path $stateRoot
    Ensure-Directory -Path $logsRoot
    Ensure-Directory -Path $tmpRoot

    $script:LogFile = Join-Path $logsRoot ("deploy-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
    $state = Read-JsonAsHashtable -Path $statePath -Default @{ currentReleaseId = $null; currentVersion = $null; lastStatus = 'noop'; lastCheckedUtc = $null; lastError = $null }

    $token = Get-StoredCredentialPassword -Target $config.credentialTarget -Username $config.credentialUser
    $release = Get-LatestStableRelease -RepoOwner $config.repoOwner -RepoName $config.repoName -ApiBase $config.githubApiBaseUrl -Token $token
    if (-not $release) {
        Write-Log -Level 'INFO' -Message 'No stable release available. Exiting.'
        exit 0
    }

    $targetVersion = if ($release.tag_name) { [string]$release.tag_name } else { "release-$($release.id)" }
    $currentReleaseId = if ($state.currentReleaseId) { [string]$state.currentReleaseId } else { '' }
    if ($currentReleaseId -eq [string]$release.id -or ([string]$state.currentVersion -eq $targetVersion)) {
        Write-Log -Level 'INFO' -Message "No update required. Already on '$targetVersion'."
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
    Install-Dependencies -ReleasePath $extractRoot

    Remove-PathForce -Path $appPath
    Move-Item -LiteralPath $extractRoot -Destination $appPath
    Remove-PathForce -Path $runRoot

    Start-Pm2ProcessFresh -Pm2Path $config.pm2Path -ProcessName $config.processName -AppPath $appPath -LogsPath $logsRoot -EntryScript $config.entryScript -NodeEnv $config.nodeEnv

    $state.currentReleaseId = [string]$release.id
    $state.currentVersion = $targetVersion
    $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.lastStatus = 'success'
    $state.lastError = $null
    Write-JsonFile -Path $statePath -Data $state

    Write-Log -Level 'INFO' -Message "Deploy complete. Running version '$targetVersion'."
    exit 0
}
catch {
    $err = $_.Exception.Message
    Write-Log -Level 'ERROR' -Message $err

    try {
        if ($statePath) {
            if (-not $state) {
                $state = @{ currentReleaseId = $null; currentVersion = $null; lastStatus = 'failed'; lastCheckedUtc = $null; lastError = $err }
            }
            $state.lastCheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
            $state.lastStatus = 'failed'
            $state.lastError = $err
            Write-JsonFile -Path $statePath -Data $state
        }
    }
    catch {
    }

    exit 1
}
