param(
  [Parameter(Position = 0)]
  [ValidateSet('help', 'deploy', 'deploy-dev', 'status', 'backup', 'restore', 'prune', 'feed-sync')]
  [string]$Command = 'help',
  [ValidateSet('production', 'dev')]
  [string]$Stack = 'production',
  [string]$BackupPath,
  [int]$Keep = 7,
  [int]$LogRetentionDays = 7,
  [switch]$FeedSync
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackupsRoot = Join-Path $RepoRoot 'backups/redis'
$TmpRoot = Join-Path $RepoRoot 'tmp'

function Write-Section {
  param([string]$Text)
  Write-Host ''
  Write-Host $Text -ForegroundColor Cyan
}

function Invoke-Compose {
  param(
    [string[]]$Args,
    [string]$TargetStack = $Stack,
    [switch]$UseProductionProfile
  )

  $composeArgs = @('-f', 'docker-compose.yml')
  switch ($TargetStack) {
    'production' { $composeArgs += @('-f', 'docker-compose.production.yml') }
    'dev' { $composeArgs += @('-f', 'docker-compose.dev.yml') }
    default { throw "unsupported stack: $TargetStack" }
  }
  if ($UseProductionProfile) {
    $composeArgs += @('--profile', 'production-edge')
  }
  $composeArgs += $Args

  & docker compose @composeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose $($composeArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Get-ComposeContainerId {
  param(
    [string]$ServiceName,
    [string]$TargetStack = $Stack
  )

  $composeArgs = @('-f', 'docker-compose.yml')
  switch ($TargetStack) {
    'production' { $composeArgs += @('-f', 'docker-compose.production.yml') }
    'dev' { $composeArgs += @('-f', 'docker-compose.dev.yml') }
    default { throw "unsupported stack: $TargetStack" }
  }

  $containerId = (& docker compose @composeArgs ps -q $ServiceName).Trim()
  if (-not $containerId) {
    throw "service '$ServiceName' is not running"
  }

  return $containerId
}

function Wait-ForHealth {
  param(
    [string]$Url,
    [string]$Name,
    [int]$TimeoutSeconds = 60
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 3
      if ($response.StatusCode -eq 200) {
        return
      }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }

  throw "$Name did not become healthy within $TimeoutSeconds seconds"
}

function New-Backup {
  if (-not (Test-Path $BackupsRoot)) {
    New-Item -ItemType Directory -Force -Path $BackupsRoot | Out-Null
  }

  Invoke-Compose -Args @('exec', '-T', 'redis', 'redis-cli', 'SAVE')
  $containerId = Get-ComposeContainerId -ServiceName 'redis'
  $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $targetDir = Join-Path $BackupsRoot $timestamp
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  $targetFile = Join-Path $targetDir 'dump.rdb'
  & docker cp "${containerId}:/data/dump.rdb" $targetFile
  if ($LASTEXITCODE -ne 0) {
    throw 'docker cp failed while exporting the Redis snapshot'
  }

  Write-Host "Backup written to $targetFile"
}

function Resolve-BackupFile {
  param([string]$Path)

  if ($Path) {
    if (-not (Test-Path $Path)) {
      throw "backup path not found: $Path"
    }

    if (Test-Path $Path -PathType Container) {
      $candidate = Join-Path $Path 'dump.rdb'
      if (-not (Test-Path $candidate)) {
        throw "backup snapshot not found inside directory: $candidate"
      }
      return (Resolve-Path $candidate).Path
    }

    return (Resolve-Path $Path).Path
  }

  if (-not (Test-Path $BackupsRoot)) {
    throw "no backups found in $BackupsRoot"
  }

  $latest = Get-ChildItem -Path $BackupsRoot -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $latest) {
    throw "no backups found in $BackupsRoot"
  }

  $candidate = Join-Path $latest.FullName 'dump.rdb'
  if (-not (Test-Path $candidate)) {
    throw "backup snapshot not found inside directory: $candidate"
  }

  return (Resolve-Path $candidate).Path
}

function Restore-Backup {
  param([string]$Path)

  $backupFile = Resolve-BackupFile -Path $Path
  Invoke-Compose -Args @('stop', 'redis')
  $containerId = Get-ComposeContainerId -ServiceName 'redis'

  & docker cp $backupFile "${containerId}:/data/dump.rdb"
  if ($LASTEXITCODE -ne 0) {
    throw 'docker cp failed while restoring the Redis snapshot'
  }

  Invoke-Compose -Args @('start', 'redis')
  Write-Host "Restored Redis snapshot from $backupFile"
}

function Prune-Backups {
  param([int]$KeepCount)

  if (-not (Test-Path $BackupsRoot)) {
    Write-Host "No backups directory found at $BackupsRoot"
    return
  }

  $backups = Get-ChildItem -Path $BackupsRoot -Directory |
    Sort-Object LastWriteTime -Descending

  if ($backups.Count -le $KeepCount) {
    Write-Host "Backup retention already satisfied ($($backups.Count) <= $KeepCount)"
    return
  }

  $toRemove = $backups | Select-Object -Skip $KeepCount
  foreach ($entry in $toRemove) {
    Remove-Item -Recurse -Force $entry.FullName
    Write-Host "Removed backup $($entry.Name)"
  }
}

function Prune-Logs {
  param([int]$RetentionDays)

  if (-not (Test-Path $TmpRoot)) {
    Write-Host "No tmp directory found at $TmpRoot"
    return
  }

  $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
  $oldLogs = Get-ChildItem -Path $TmpRoot -File -Filter '*.log' |
    Where-Object { $_.LastWriteTime -lt $cutoff }

  foreach ($log in $oldLogs) {
    Remove-Item -Force $log.FullName
    Write-Host "Removed log $($log.Name)"
  }

  if (-not $oldLogs) {
    Write-Host "No logs older than $RetentionDays day(s)"
  }
}

function Show-Help {
  @'
Safe Road ops helper

Usage:
  pwsh ./scripts/safe-road.ps1 deploy
  pwsh ./scripts/safe-road.ps1 deploy-dev
  pwsh ./scripts/safe-road.ps1 status
  pwsh ./scripts/safe-road.ps1 backup
  pwsh ./scripts/safe-road.ps1 restore [-BackupPath <path>]
  pwsh ./scripts/safe-road.ps1 prune [-Keep 7] [-LogRetentionDays 7]
  pwsh ./scripts/safe-road.ps1 feed-sync

Commands:
  deploy      Build and start the production Compose stack, then wait for loopback health.
  deploy-dev  Build and start the local developer stack.
  status   Show Compose status and probe the local health endpoints.
  backup   Save a Redis RDB snapshot into ./backups/redis/<timestamp>/dump.rdb.
  restore  Restore Redis from a snapshot file or backup directory.
  prune    Keep the newest backup directories and delete stale tmp/*.log files.
  feed-sync Run the configured threat feed sync sources once.

Options:
  -Stack production|dev   Choose the stack used by status/backup/restore/prune helpers.
'@ | Write-Host
}

function Resolve-FeedSources {
  if ($env:SAFE_ROAD_AGENT_FEED_SOURCES) {
    return $env:SAFE_ROAD_AGENT_FEED_SOURCES -split ','
  }

  if ($env:SAFE_ROAD_AGENT_FEED_PRESET -eq 'production-free') {
    return @(
      'https://urlhaus.abuse.ch/downloads/csv_recent/',
      'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
    )
  }

  if ($env:SAFE_ROAD_THREAT_FEED_SOURCE) {
    return @($env:SAFE_ROAD_THREAT_FEED_SOURCE)
  }

  return @()
}

switch ($Command) {
  'help' {
    Show-Help
  }
  'deploy' {
    Write-Section 'Deploying Safe Road'
    $composeArgs = @('up', '-d', '--build')
    if ($FeedSync) {
      $composeArgs = @('--profile', 'feed-sync') + $composeArgs
    }
    Invoke-Compose -Args $composeArgs -TargetStack 'production' -UseProductionProfile
    Wait-ForHealth -Url 'http://localhost:8080/healthz' -Name 'core-api'
    Wait-ForHealth -Url 'http://localhost:8081/healthz' -Name 'dns-resolver'
    Write-Host 'Deployment healthy.' -ForegroundColor Green
  }
  'deploy-dev' {
    Write-Section 'Deploying Safe Road (dev stack)'
    Invoke-Compose -Args @('up', '-d', '--build') -TargetStack 'dev'
    Wait-ForHealth -Url 'http://localhost:8080/healthz' -Name 'core-api'
    Wait-ForHealth -Url 'http://localhost:8081/healthz' -Name 'dns-resolver'
    Write-Host 'Deployment healthy.' -ForegroundColor Green
  }
  'status' {
    Write-Section 'Compose status'
    Invoke-Compose -Args @('ps')
    Write-Section 'Health checks'
    foreach ($item in @(
      @{ Name = 'core-api'; Url = 'http://localhost:8080/healthz' },
      @{ Name = 'dns-resolver'; Url = 'http://localhost:8081/healthz' }
    )) {
      try {
        $response = Invoke-WebRequest -Uri $item.Url -Method Get -TimeoutSec 3
        Write-Host "$($item.Name): $($response.StatusCode)"
      } catch {
        Write-Host "$($item.Name): offline"
      }
    }
  }
  'backup' {
    Write-Section 'Backing up Redis'
    New-Backup
  }
  'restore' {
    Write-Section 'Restoring Redis'
    Restore-Backup -Path $BackupPath
  }
  'prune' {
    Write-Section 'Pruning backups and logs'
    Prune-Backups -KeepCount $Keep
    Prune-Logs -RetentionDays $LogRetentionDays
  }
  'feed-sync' {
    $sources = Resolve-FeedSources | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $sources) {
      throw 'No feed sources configured. Set SAFE_ROAD_AGENT_FEED_SOURCES, SAFE_ROAD_AGENT_FEED_PRESET, or SAFE_ROAD_THREAT_FEED_SOURCE.'
    }

    foreach ($source in $sources) {
      Write-Section "Syncing $source"
      Invoke-Compose -Args @('--profile', 'feed-sync', 'run', '--rm', 'feed-sync', '/app/service', '-source', $source)
    }
  }
  default {
    throw "unsupported command: $Command"
  }
}
