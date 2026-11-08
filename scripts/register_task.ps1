# register_task.ps1 - Canari two-tier weekly scan
$action = New-ScheduledTaskAction -Execute "E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe" -Argument "E:\Temp\tbdig\canari\run_weekly.py" -WorkingDirectory "E:\Temp\tbdig\canari"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "06:00"
Register-ScheduledTask -TaskName "CanariWeeklyScan" -Action $action -Trigger $trigger -Force
Write-Host "CanariWeeklyScan registered (two-tier: deep + metadata)"
