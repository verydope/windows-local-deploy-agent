# Requires -Version 5.1
# Pester contract tests for deploy-agent behavior rules.

Describe 'Release filtering' {
    It 'excludes draft and prerelease when selecting latest' {
        $releases = @(
            [pscustomobject]@{ id = 1; draft = $false; prerelease = $false; published_at = '2026-02-10T10:00:00Z' },
            [pscustomobject]@{ id = 2; draft = $true; prerelease = $false; published_at = '2026-02-11T10:00:00Z' },
            [pscustomobject]@{ id = 3; draft = $false; prerelease = $true; published_at = '2026-02-12T10:00:00Z' },
            [pscustomobject]@{ id = 4; draft = $false; prerelease = $false; published_at = '2026-02-13T10:00:00Z' }
        )

        $selected = $releases |
            Where-Object { -not $_.draft -and -not $_.prerelease } |
            Sort-Object { [datetime]$_.published_at } -Descending |
            Select-Object -First 1

        $selected.id | Should -Be 4
    }
}

Describe 'Version comparison' {
    It 'returns noop when release id is already deployed' {
        $state = @{ currentReleaseId = '123'; currentVersion = '2026.02.11+001' }
        $release = [pscustomobject]@{ id = '123'; tag_name = 'v2026.02.12+001' }

        $isNoop = ($state.currentReleaseId -eq [string]$release.id) -or ($state.currentVersion -eq $release.tag_name)
        $isNoop | Should -BeTrue
    }

    It 'returns noop when version tag is already deployed' {
        $state = @{ currentReleaseId = '123'; currentVersion = '2026.02.11+001' }
        $release = [pscustomobject]@{ id = '124'; tag_name = '2026.02.11+001' }

        $isNoop = ($state.currentReleaseId -eq [string]$release.id) -or ($state.currentVersion -eq $release.tag_name)
        $isNoop | Should -BeTrue
    }

    It 'returns deploy-needed when release id and version differ' {
        $state = @{ currentReleaseId = '123'; currentVersion = '2026.02.11+001' }
        $release = [pscustomobject]@{ id = '124'; tag_name = 'v2026.02.12+001' }

        $isNoop = ($state.currentReleaseId -eq [string]$release.id) -or ($state.currentVersion -eq $release.tag_name)
        $isNoop | Should -BeFalse
    }
}

Describe 'SHA verification' {
    It 'detects mismatch' {
        $tmp = Join-Path $env:TEMP ('deploy-agent-test-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tmp -ItemType Directory | Out-Null

        try {
            $zip = Join-Path $tmp 'server-win-x64.zip'
            Set-Content -LiteralPath $zip -Value 'sample artifact bytes'

            $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            $expected = 'deadbeef'

            ($expected -eq $actual) | Should -BeFalse
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -Recurse
        }
    }
}

Describe 'State self-heal policy' {
    It 'falls back to defaults on invalid JSON' {
        $defaults = [ordered]@{
            currentVersion = $null
            previousVersion = $null
            currentReleaseId = $null
            lastCheckedUtc = $null
            lastStatus = 'noop'
            lastError = $null
            lastDurationMs = 0
        }

        $tmp = Join-Path $env:TEMP ('deploy-agent-state-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            Set-Content -LiteralPath $tmp -Value '{invalid-json'
            $parsed = $null
            try {
                $parsed = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            }
            catch {
                $parsed = $defaults
            }

            if ($parsed -isnot [hashtable]) {
                $rehydrated = @{}
                foreach ($p in $parsed.PSObject.Properties) {
                    $rehydrated[$p.Name] = $p.Value
                }
                $parsed = $rehydrated
            }

            $parsed.lastStatus | Should -Be 'noop'
            $parsed.ContainsKey('currentReleaseId') | Should -BeTrue
        }
        finally {
            if (Test-Path -LiteralPath $tmp) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
    }
}
