Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $repositoryRoot
try {
  $baseCompose = @('compose', '-f', 'docker-compose.yml')
  $siteCompose = @('compose', '-f', 'vul-web2/compose.yaml')
  $experimentCompose = @('compose', '-p', 'ca3p-internal-experiment',
    '-f', 'docker-compose.yml',
    '-f', 'docker-compose.vul-web2.yml',
    '-f', 'docker-compose.internal-experiment.yml')

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
  { origin: 'http://daehan:4101', name: '대한대학교' },
  { origin: 'http://wonchang:4102', name: '원창대학교' },
];
for (const site of sites) {
  const response = await fetch(site.origin + '/', { signal: AbortSignal.timeout(10000) });
  if (!response.ok || !(await response.text()).includes(site.name)) {
    throw new Error(`Unexpected response from ${site.origin}`);
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

  Write-Output 'Internal sites and isolated dashboard are healthy.'
  Write-Output 'Open: http://127.0.0.1:4175/#workspace/attack'
  Write-Output 'Agent target origins: http://daehan:4101 and http://wonchang:4102'
  Write-Output "To read this dashboard's admin credentials: docker exec $containerId cat /app/.runtime/access.txt"
}
finally {
  Pop-Location
}
