# Windows Local Auto-Deploy Agent (PM2, Pull-Based)

This repository is only the Windows deploy agent.

- Agent install path: `C:\services\auto-deploy-agent`
- App deploy path: `C:\services\[PROJECT_NAME]`
- CI/CD source: separate Nest.js app repo (`verydope-device-core`) publishes GitHub Releases

## Files

- `agent/deploy.ps1`: pull latest release, verify hash, deploy, health check, rollback
- `agent/rollback.ps1`: rollback to `previous` and recover app
- `agent/config.example.json`: config template
- `agent/install-task.ps1`: Scheduled Task installer (startup + every 10 minutes)
- `agent/install-service-bindings.ps1`: PM2 process bootstrap/binding
- `tests/DeployAgent.Tests.ps1`: contract tests
- `.github/workflows/app-release-template.yml`: workflow template matching your current `verydope-device-core` release workflow

## Runtime layout (per project)

For a project named `my-api`, app root is `C:\services\my-api`:

- `C:\services\my-api\releases\`
- `C:\services\my-api\current` (junction)
- `C:\services\my-api\previous` (junction)
- `C:\services\my-api\state\deployed.json`
- `C:\services\my-api\state\logs\`

## Prerequisites (Windows)

- PowerShell (5.1+ or 7+)
- Node.js in PATH
- `pm2` installed globally (`npm i -g pm2`)
- `pm2` available in PATH (or set `pm2Path` in config)
- One package manager for production install: `pnpm` or `npm` or `yarn`
- GitHub PAT (read-only to repo contents/releases)

Store PAT in Credential Manager:

```powershell
cmdkey /add:github.com /user:GITHUB /pass:<TOKEN>
```

## Install flow

1. Copy this repo's `agent/*` files to:
`C:\services\auto-deploy-agent\`

2. Create config:

```powershell
Copy-Item C:\services\auto-deploy-agent\config.example.json C:\services\auto-deploy-agent\config.json
notepad C:\services\auto-deploy-agent\config.json
```

3. Bootstrap PM2 process binding (run after first release deploy or after a manual initial app copy):

```powershell
powershell -ExecutionPolicy Bypass -File C:\services\auto-deploy-agent\install-service-bindings.ps1 -ConfigPath C:\services\auto-deploy-agent\config.json
```

4. Install Scheduled Task:

```powershell
powershell -ExecutionPolicy Bypass -File C:\services\auto-deploy-agent\install-task.ps1 -ConfigPath C:\services\auto-deploy-agent\config.json -TaskName VeryDopeAutoDeploy
```

5. Run first deploy manually:

```powershell
powershell -ExecutionPolicy Bypass -File C:\services\auto-deploy-agent\deploy.ps1 -ConfigPath C:\services\auto-deploy-agent\config.json
```

## Config fields

- `repoOwner`: GitHub org/user of the Nest app repo
- `repoName`: GitHub repo for the Nest app (ex: `verydope-device-core`)
- `assetName`: release zip asset name (`server-win-x64.zip`)
- `shaAssetName`: SHA file name (`build.sha256`)
- `projectName`: informational only
- `processName`: PM2 process name
- `appRoot`: deploy root (`C:\services\[PROJECT_NAME]`)
- `healthUrl`: health endpoint (`http://127.0.0.1:<PORT>/health`)
- `healthTimeoutSec`: request timeout, default `3`
- `healthRetries`: retry count, default `3`
- `healthRetryDelaySec`: retry delay, default `5`
- `pollIntervalMinutes`: task interval, default `10`
- `credentialTarget`: default `github.com`
- `credentialUser`: default `GITHUB`
- `githubApiBaseUrl`: default `https://api.github.com`
- `pm2Path`: default `pm2`
- `nodeEnv`: optional, commonly `production`

## Compatibility with your current app workflow

Your existing release workflow is compatible with this agent as-is:

- Tag format `v<version+run_number>` is supported.
- Artifact name `server-win-x64.zip` is the default expected by the agent.
- SHA file format `"<sha>  <zipName>"` is supported.
- `INCLUDE_NODE_MODULES=false` is supported (agent installs prod deps on target machine).

## Operational behavior

- Pull-only release check (no inbound webhooks)
- Deploys latest stable GitHub Release (non-draft, non-prerelease)
- SHA256 verification before deploy
- Atomic junction switch (`current`/`previous`)
- PM2 process stop/restart around swap
- Health check and automatic rollback on failure
- Keeps only current + previous release folders

## Tests

Run on Windows with Pester:

```powershell
Invoke-Pester -Path .\tests\DeployAgent.Tests.ps1
```
