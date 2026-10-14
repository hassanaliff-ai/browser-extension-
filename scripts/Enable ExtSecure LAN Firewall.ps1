$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$config=Get-Content -LiteralPath (Join-Path $projectRoot '.private\lan\config.json') -Raw | ConvertFrom-Json
$ruleName='ExtSecure-LAN-HTTPS-'+[string]$config.port
if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $ruleName }
New-NetFirewallRule -Name $ruleName -DisplayName 'ExtSecure LAN HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([int]$config.port) -LocalAddress ([string]$config.host) -RemoteAddress ([string]$config.subnet) -Profile Public,Private | Out-Null
'Firewall configured for HTTPS from the configured local subnet only.' | Set-Content -LiteralPath (Join-Path $projectRoot '.private\lan\firewall-result.txt')
