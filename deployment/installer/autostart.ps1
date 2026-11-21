# Registers Guardian to start at logon (per-user scheduled task). A hardened Windows service wrapper is roadmap item for M6.
param([switch]$Remove)
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($Remove) { Unregister-ScheduledTask -TaskName "SmartOSGuardian" -Confirm:$false; exit }
$act = New-ScheduledTaskAction -Execute "$root\.venv\Scripts\python.exe" -Argument "-m guardian.main --no-ui" -WorkingDirectory $root
$env:PYTHONPATH = "$root\agent\python-agent"
$trg = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "SmartOSGuardian" -Action $act -Trigger $trg -Description "Smart OS Guardian agent" -RunLevel Limited | Out-Null
Write-Host "Autostart registered. Remove with: autostart.ps1 -Remove"
