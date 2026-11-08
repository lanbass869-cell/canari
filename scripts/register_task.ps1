# register weekly task
 = New-ScheduledTaskAction -Execute "E:\Temp\tbdig\_venv_pr_a\Scripts\python.exe" -Argument "E:\Temp\tbdig\canari\run_weekly.py" -WorkingDirectory "E:\Temp\tbdig\canari"
 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "06:00"
Register-ScheduledTask -TaskName "CanariWeeklyScan" -Action  -Trigger  -Force
Write-Host "Done"
