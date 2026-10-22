$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$privateFolder = Join-Path $projectRoot '.private\api-supervisor'
if (-not (Test-Path -LiteralPath $privateFolder)) { throw 'Install the API Supervisor first.' }
'{"enabled":true}' | Set-Content -LiteralPath (Join-Path $privateFolder 'config.json') -Encoding UTF8
Enable-ScheduledTask -TaskName 'ExtSecure API Supervisor' | Out-Null
Start-ScheduledTask -TaskName 'ExtSecure API Supervisor'
Write-Output 'SecureScope API automatic supervision enabled.'
