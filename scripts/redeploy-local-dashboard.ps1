param([switch]$InternalSites)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $repositoryRoot
try {
  $composeArgs = @('compose', '-f', 'docker-compose.yml')
  $previousId = ((& docker @composeArgs ps -q dashboard) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the current dashboard container.' }

  $internalNetworks = @('ca3p-universities_daehan-net', 'ca3p-universities_wonchang-net')
  $attachedInternalNetworks = @()
  if ($previousId) {
    $previousContainer = @(& docker inspect $previousId | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0 -or -not $previousContainer) { throw 'Could not inspect the previous dashboard networks.' }
    $attachedInternalNetworks = @($previousContainer.NetworkSettings.Networks.PSObject.Properties.Name |
      Where-Object { $internalNetworks -contains $_ })
  }
  $useInternalSites = [bool]$InternalSites -or $attachedInternalNetworks.Count -gt 0
  if ($useInternalSites) {
    foreach ($network in $internalNetworks) {
      & docker network inspect $network --format '{{.Name}}' *> $null
      if ($LASTEXITCODE -ne 0) {
        throw "Internal site network $network is missing. Start the sites with docker compose -f vul-web2/compose.yaml up --build -d --wait."
      }
    }
    $composeArgs += @('-f', 'docker-compose.vul-web2.yml')
  }

  & docker @composeArgs up --build --force-recreate --no-deps -d --wait --wait-timeout 120 dashboard
  if ($LASTEXITCODE -ne 0) { throw 'Dashboard build or recreation failed.' }

  $containerId = ((& docker @composeArgs ps -q dashboard) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $containerId -notmatch '^[a-fA-F0-9]{12,64}$') {
    throw 'Compose did not return a running dashboard container ID.'
  }
  if ($previousId -and $previousId -eq $containerId) {
    throw 'The dashboard container was not recreated.'
  }

  $container = @(& docker inspect $containerId | ConvertFrom-Json)[0]
  if ($LASTEXITCODE -ne 0 -or -not $container.State.Running) {
    throw 'The recreated dashboard container is not running.'
  }
  if ($useInternalSites) {
    $activeNetworks = @($container.NetworkSettings.Networks.PSObject.Properties.Name)
    foreach ($network in $internalNetworks) {
      if ($activeNetworks -notcontains $network) {
        throw "The recreated dashboard is not attached to $network."
      }
    }
  }
  $imageId = ((& docker image inspect --format '{{.Id}}' 'ca3p-dashboard:local') | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $container.Image -ne $imageId) {
    throw 'The running dashboard container does not use ca3p-dashboard:local.'
  }
  $portBindings = @($container.NetworkSettings.Ports.'4173/tcp')
  if (-not @($portBindings | Where-Object { $_.HostIp -eq '127.0.0.1' -and $_.HostPort -eq '4173' }).Count) {
    throw 'The recreated dashboard is not bound to 127.0.0.1:4173.'
  }

  foreach ($asset in @('index.html', 'app.js', 'operations-pages.js')) {
    $localPath = Join-Path $repositoryRoot "agent-dashboard/dist/$asset"
    $localHash = (Get-FileHash -LiteralPath $localPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $inside = ((& docker exec $containerId sha256sum "/app/agent-dashboard/dist/$asset") | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $inside -notmatch '^([a-fA-F0-9]{64})\s+') {
      throw "Could not hash $asset inside the dashboard container."
    }
    if ($Matches[1].ToLowerInvariant() -ne $localHash) {
      throw "The dashboard container serves a different $asset than the workspace."
    }

    $assetUrl = if ($asset -eq 'index.html') { '/' } else { "/$asset" }
    $downloadPath = Join-Path ([System.IO.Path]::GetTempPath()) "ca3p-dashboard-$([guid]::NewGuid().ToString('N')).tmp"
    try {
      Invoke-WebRequest -Uri "http://127.0.0.1:4173$assetUrl" -UseBasicParsing -TimeoutSec 10 -OutFile $downloadPath | Out-Null
      $servedHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($servedHash -ne $localHash) {
        throw "The dashboard HTTP service serves a different $asset than the workspace."
      }
    }
    finally {
      if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath }
    }
  }

  Write-Output "Dashboard recreated: $($containerId.Substring(0, 12))"
  Write-Output "Image: $imageId"
  if ($useInternalSites) { Write-Output 'Internal site networks: daehan and wonchang attached' }
  Write-Output 'Verified container and HTTP assets at http://127.0.0.1:4173/#workspace/attack'
}
finally {
  Pop-Location
}
