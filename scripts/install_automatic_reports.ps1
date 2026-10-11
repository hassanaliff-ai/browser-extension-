param([Parameter(Mandatory=$true)][string]$PythonwPath)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path $PSScriptRoot -Parent
if (-not (Test-Path -LiteralPath $PythonwPath)) {throw 'Background Python runtime not found'}
$taskSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskCommand=[Security.SecurityElement]::Escape($PythonwPath)
$taskScript=[Security.SecurityElement]::Escape((Join-Path $taskRoot 'scripts\run_automatic_report.py'))
$taskDirectory=[Security.SecurityElement]::Escape($taskRoot)
$taskMonths=('<January/>','<February/>','<March/>','<April/>','<May/>','<June/>','<July/>','<August/>','<September/>','<October/>','<November/>','<December/>') -join ''
$taskStart=[TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow,'Arab Standard Time').ToString('yyyy-MM-dd')+'T09:00:00+03:00'
foreach ($taskKind in @('weekly','monthly')) {
 $taskCalendar=if ($taskKind -eq 'weekly') {'<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Sunday/></DaysOfWeek></ScheduleByWeek>'} else {"<ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months>$taskMonths</Months></ScheduleByMonth>"}
 $taskName="ExtSecure Automatic $taskKind LLM Report"
 $taskXml=@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>ExtSecure local LLM report generation at 09:00 KSA; generated reports remain reviewable drafts.</Description></RegistrationInfo>
<Triggers><CalendarTrigger><StartBoundary>$taskStart</StartBoundary><Enabled>true</Enabled>$taskCalendar</CalendarTrigger></Triggers>
<Principals><Principal id="Author"><UserId>$taskSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><ExecutionTimeLimit>PT15M</ExecutionTimeLimit><RestartOnFailure><Interval>PT10M</Interval><Count>3</Count></RestartOnFailure></Settings>
<Actions Context="Author"><Exec><Command>$taskCommand</Command><Arguments>&quot;$taskScript&quot; --kind $taskKind</Arguments><WorkingDirectory>$taskDirectory</WorkingDirectory></Exec></Actions>
</Task>
"@
 Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
 $taskInfo=Get-ScheduledTaskInfo -TaskName $taskName
 [PSCustomObject]@{Task=$taskName;NextRun=$taskInfo.NextRunTime;Enabled=(Get-ScheduledTask -TaskName $taskName).State -ne 'Disabled'}
}
