$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$privateFolder = Join-Path $projectRoot '.private\api-supervisor'
if (Test-Path -LiteralPath $privateFolder) { '{"enabled":false}' | Set-Content -LiteralPath (Join-Path $privateFolder 'config.json') -Encoding UTF8 }
$stopped = $false
for ($attempt=0; $attempt -lt 60; $attempt++) {
    $statusFile = Join-Path $privateFolder 'status.json'
    if ((Test-Path -LiteralPath $statusFile) -and (Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json).state -eq 'stopped') { $stopped = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $stopped) { throw 'Stop was requested. The supervisor has not yet confirmed shutdown; its task was left available for recovery.' }
Disable-ScheduledTask -TaskName 'ExtSecure API Supervisor' | Out-Null
Write-Output 'SecureScope API, public access and automatic supervision stopped. PostgreSQL remains running.'
