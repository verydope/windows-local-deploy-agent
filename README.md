# Windows Manual Deploy Agent (PM2)

This repository contains a simplified Windows deploy agent for one app:

- No scheduler
- No rollback script
- No `current` / `previous` release switching
- One in-place app directory

## Files

- `agent/deploy.ps1`: manual deploy script
- `agent/install-service-bindings.ps1`: PM2 bootstrap helper for existing app files
- `agent/config.example.json`: config template
- `tests/DeployAgent.Tests.ps1`: lightweight contract tests

## Runtime layout

For a project named `my-api`, app root is `C:\services\my-api`:

- `C:\services\my-api\app` (active app files)
- `C:\services\my-api\state\deployed.json`
- `C:\services\my-api\state\logs\`
- `C:\services\my-api\state\tmp\`

## Prerequisites (Windows)

- PowerShell (5.1+ or 7+)
- Node.js in PATH
- `pm2` installed globally (`npm i -g pm2`)
- `pm2` available in PATH (or set `pm2Path` in config)
- One package manager for production install: `pnpm` or `npm` or `yarn`
- GitHub PAT with read access to repo releases

Store PAT in Credential Manager:

```powershell
cmdkey /add:github.com /user:GITHUB /pass:<TOKEN>
```

## Setup

1. Copy `agent/*` files to:
`C:\services\auto-deploy-agent\`

2. Create config:

```powershell
Copy-Item C:\services\auto-deploy-agent\config.example.json C:\services\auto-deploy-agent\config.json
notepad C:\services\auto-deploy-agent\config.json
```

## Manual deploy command

Run deploy whenever you want to update:

```powershell
powershell -ExecutionPolicy Bypass -File C:\services\auto-deploy-agent\deploy.ps1 -ConfigPath C:\services\auto-deploy-agent\config.json
```

The script will:

1. Check latest stable GitHub release
2. Skip if same version is already deployed
3. Download zip + sha file
4. Verify SHA256
5. Extract into `app` and install dependencies from lockfile (including devDependencies)
6. Run PM2 as a fresh start (`delete` then `start`) using `entryScript` (or fallback: `app\dist\src\main.js`, `app\dist\main.js`, `app\main.js`)

## Config fields

- `repoOwner`: GitHub org/user of the app repo
- `repoName`: GitHub repo name
- `assetName`: release zip asset name (`server-win-x64.zip`)
- `shaAssetName`: SHA file name (`build.sha256`)
- `projectName`: informational only
- `processName`: PM2 process name
- `appRoot`: deploy root (`C:\services\[PROJECT_NAME]`)
- `credentialTarget`: default `github.com`
- `credentialUser`: default `GITHUB`
- `githubApiBaseUrl`: default `https://api.github.com`
- `pm2Path`: default `pm2`
- `entryScript`: optional app entrypoint, relative to `appRoot\app` (example: `dist\main.js`)
- `nodeEnv`: optional, commonly `production`

## Tests

Run on Windows with Pester:

```powershell
Invoke-Pester -Path .\tests\DeployAgent.Tests.ps1
```
