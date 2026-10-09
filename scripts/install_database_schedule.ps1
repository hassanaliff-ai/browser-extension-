param([Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path $PSScriptRoot -Parent
$taskScript = Join-Path $PSScriptRoot 'database_ops.py'
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Select the existing project Python executable.' }
$taskName = 'ExtSecure Database Maintenance'
$taskArguments = ('"{0}" maintain' -f $taskScript)
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing -and ($existing.Actions.Execute -ne $PythonPath -or $existing.Actions.Arguments -ne $taskArguments)) {
    throw 'A different task already uses this name. It was not changed.'
}
$action = New-ScheduledTaskAction -Execute $PythonPath -Argument $taskArguments -WorkingDirectory $projectDirectory
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Private daily PostgreSQL backups, weekly isolated restore tests, and five-minute aggregate database monitoring for ExtSecure.' -Force | Out-Null
Write-Output 'Installed ExtSecure Database Maintenance: checks every five minutes while this Windows user is logged in.'
