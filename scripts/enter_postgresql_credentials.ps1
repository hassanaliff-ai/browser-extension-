$ErrorActionPreference = 'Stop'
$credentialDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) '.private'
New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
Write-Host 'ExtSecure PostgreSQL setup' -ForegroundColor Cyan
Write-Host 'Enter the existing PostgreSQL administrator password locally; it will be encrypted for this Windows account.'
$postgresUsername = Read-Host 'Administrator username (press Enter for postgres)'
if ([string]::IsNullOrWhiteSpace($postgresUsername)) { $postgresUsername = 'postgres' }
$postgresPassword = Read-Host 'PostgreSQL administrator password' -AsSecureString
if ($postgresPassword.Length -eq 0) { throw 'No password entered. Configuration was not changed.' }
@{
    host = '127.0.0.1'
    port = 5432
    username = $postgresUsername
    password_dpapi = ConvertFrom-SecureString $postgresPassword
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $credentialDirectory 'postgresql-admin-connection.json') -Encoding UTF8
Write-Host 'Encrypted credentials saved locally.' -ForegroundColor Green
