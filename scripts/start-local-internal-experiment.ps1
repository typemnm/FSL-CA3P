Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $repositoryRoot
try {
  $runtimeDirectory = Join-Path $repositoryRoot '.runtime'
  $resetEnvFile = Join-Path $runtimeDirectory 'experiment-reset.env'
  if (-not (Test-Path -LiteralPath $resetEnvFile)) {
    [void][System.IO.Directory]::CreateDirectory($runtimeDirectory)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      function New-ResetToken {
        $bytes = New-Object byte[] 32
        $random.GetBytes($bytes)
        return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
      }
      $contents = "CA3P_DAEHAN_RESET_TOKEN=$(New-ResetToken)`nCA3P_WONCHANG_RESET_TOKEN=$(New-ResetToken)`n"
      [System.IO.File]::WriteAllText($resetEnvFile, $contents, (New-Object System.Text.UTF8Encoding($false)))
    }
    finally { $random.Dispose() }
  }
  $resetEnvLines = @(Get-Content -LiteralPath $resetEnvFile)
  if ($resetEnvLines.Count -ne 2 -or
      $resetEnvLines[0] -cnotmatch '^CA3P_DAEHAN_RESET_TOKEN=[0-9a-f]{64}$' -or
      $resetEnvLines[1] -cnotmatch '^CA3P_WONCHANG_RESET_TOKEN=[0-9a-f]{64}$') {
    throw 'The local reset token file is invalid. Restore or regenerate .runtime/experiment-reset.env.'
  }

  $baseCompose = @('compose', '-f', 'docker-compose.yml')
  $siteCompose = @('compose', '--env-file', $resetEnvFile,
    '-f', 'vul-web2/compose.yaml', '-f', 'vul-web2/compose.reset.yaml')
  $experimentCompose = @('compose', '--env-file', $resetEnvFile, '-p', 'ca3p-internal-experiment',
    '-f', 'docker-compose.yml',
    '-f', 'docker-compose.vul-web2.yml',
    '-f', 'docker-compose.internal-experiment.yml',
    '-f', 'docker-compose.vul-web2-reset.yml')

  $existingDashboardId = ((& docker @baseCompose ps -q dashboard) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the existing dashboard.' }

  & docker @siteCompose up --build -d --wait --wait-timeout 180
  if ($LASTEXITCODE -ne 0) { throw 'University sites did not build or become healthy.' }

  & docker @experimentCompose up --build -d --wait --wait-timeout 120 dashboard
  if ($LASTEXITCODE -ne 0) { throw 'Internal experiment dashboard did not build or become healthy.' }

  $containerId = ((& docker @experimentCompose ps -q dashboard) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $containerId -notmatch '^[a-fA-F0-9]{12,64}$') {
    throw 'Could not identify the internal experiment dashboard container.'
  }

  $siteProbe = @'
const sites = [
  { origin: 'http://daehan:4101', management: 'http://daehan:54101', fixtureId: 'vul-web2-daehan', name: '대한대학교' },
  { origin: 'http://wonchang:4102', management: 'http://wonchang:54102', fixtureId: 'vul-web2-wonchang', name: '원창대학교' },
];
const resetTargets = JSON.parse(process.env.CA3P_EXPERIMENT_RESET_TARGETS ?? '{}');
for (const site of sites) {
  const response = await fetch(site.origin + '/', { signal: AbortSignal.timeout(10000) });
  if (!response.ok || !(await response.text()).includes(site.name)) {
    throw new Error(`Unexpected response from ${site.origin}`);
  }
  const management = await fetch(site.management + '/health', { signal: AbortSignal.timeout(10000) });
  const health = await management.json();
  if (!management.ok || health.status !== 'ready' || health.fixtureId !== site.fixtureId
    || health.targetOrigin !== site.origin || resetTargets[site.fixtureId]?.origin !== site.management
    || resetTargets[site.fixtureId]?.targetOrigin !== site.origin
    || !/^[0-9a-f]{64}$/.test(resetTargets[site.fixtureId]?.token ?? '')) {
    throw new Error(`Reset manager is unavailable for ${site.fixtureId}`);
  }
  console.log(`${site.name}: ${site.origin}/ (HTTP ${response.status})`);
}
'@
  & docker exec $containerId node --input-type=module -e $siteProbe
  if ($LASTEXITCODE -ne 0) { throw 'The dashboard cannot reach both university sites by container origin.' }

  $health = Invoke-RestMethod -Uri 'http://127.0.0.1:4175/api/health' -TimeoutSec 10
  if ($health.status -ne 'ok') { throw 'The 4175 dashboard health response is invalid.' }

  if ($existingDashboardId) {
    $currentDashboardId = ((& docker @baseCompose ps -q dashboard) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentDashboardId -ne $existingDashboardId) {
      throw 'The existing 4173 dashboard container changed during setup.'
    }
  }

  Write-Output 'Internal sites, reset managers, and isolated dashboard are healthy.'
  Write-Output 'Open: http://127.0.0.1:4175/#workspace/attack'
  Write-Output 'Agent target origins: http://daehan:4101 and http://wonchang:4102'
  Write-Output "To read this dashboard's admin credentials: docker exec $containerId cat /app/.runtime/access.txt"
}
finally {
  Pop-Location
}
