#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$taskName = 'NEU Campus Auto Login'

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "Scheduled task is not installed: $taskName"
    exit 0
}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Host "Removed scheduled task: $taskName"

