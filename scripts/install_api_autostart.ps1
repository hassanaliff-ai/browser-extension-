param([string]$Pythonw, [switch]$Machine)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $Pythonw) { throw 'Supply the absolute path to the project virtual environment pythonw.exe.' }
if (-not (Test-Path -LiteralPath $Pythonw)) { throw 'Python runtime was not found.' }
$supervisorPath = Join-Path $PSScriptRoot 'api_supervisor.py'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principalCheck = [Security.Principal.WindowsPrincipal]::new($identity)
if ($Machine -and -not $principalCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Machine startup requires an elevated Windows administrator session.' }
$privateFolder = Join-Path $projectRoot '.private\api-supervisor'
New-Item -ItemType Directory -Path $privateFolder -Force | Out-Null
'{"enabled":true}' | Set-Content -LiteralPath (Join-Path $privateFolder 'config.json') -Encoding UTF8
$action = New-ScheduledTaskAction -Execute $Pythonw -Argument ('"' + $supervisorPath + '"') -WorkingDirectory $projectRoot
$settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$taskName = 'ExtSecure API Supervisor'
$boot = New-ScheduledTaskTrigger -AtStartup
$logon = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$retry = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType S4U -RunLevel Limited
$mode = 'background_without_sign_in'
# Administrator access is used only to register startup/batch logon. The project
# runtime remains the ordinary user, never SYSTEM running user-writable code.
if ($Machine) { $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType S4U -RunLevel Limited; $mode = 'machine_startup' }
try {
    Register-ScheduledTask -TaskName $taskName -Description 'Keep SecureScope API and its approved public gateway running; recover after crashes. No terminal windows.' -Action $action -Trigger @($boot,$logon,$retry) -Settings $settings -Principal $taskPrincipal -Force -ErrorAction Stop | Out-Null
} catch {
    if ($Machine) { throw }
    $mode = 'user_logon'
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Description 'Keep SecureScope API running while the user is signed in, including screen lock. Automatic recovery and logon startup.' -Action $action -Trigger @($logon,$retry) -Settings $settings -Principal $taskPrincipal -Force -ErrorAction Stop | Out-Null
}
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
# Virtual-environment launchers can leave their runtime child alive. End only
# supervisors whose command line contains this exact script, never API workers.
Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" | Where-Object { $_.CommandLine -match [regex]::Escape($supervisorPath) } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
if ($Machine) {
    # Retire providers from a previous privileged logon before switching to the
    # limited batch account. Every stop checks the recorded application identity.
    $stopCode = "import sys;sys.path[:0]=['scripts','src'];from activate_postgresql import api_process,stop_api;from scripts.stop_public_api import stop;stop();stop_api(api_process())"
    $pythonConsole = Join-Path (Split-Path $Pythonw -Parent) 'python.exe'
    Push-Location -LiteralPath $projectRoot
    try { $stopOutput = & $pythonConsole -c $stopCode 2>&1 } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'Existing API providers could not be verified and stopped safely.' }
}
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$info = Get-ScheduledTaskInfo -TaskName $taskName
if ($mode -in @('background_without_sign_in','machine_startup') -and (Get-ScheduledTask -TaskName $taskName).State -ne 'Running' -and $info.LastTaskResult -notin @(0,267009)) {
    if ($Machine) { throw 'Windows batch startup failed. Verify the account has Log on as a batch job.' }
    $mode = 'user_logon'
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Description 'Keep SecureScope API running while signed in; restart at logon and after failure.' -Action $action -Trigger @($logon,$retry) -Settings $settings -Principal $taskPrincipal -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName
}
$mode | Set-Content -LiteralPath (Join-Path $privateFolder 'startup-mode.txt') -Encoding UTF8
[pscustomobject]@{Task=$taskName;Mode=$mode;State=(Get-ScheduledTask -TaskName $taskName).State.ToString()} | ConvertTo-Json -Compress
