#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$taskName = 'NEU Campus Auto Login'
$exePath = Join-Path $PSScriptRoot 'AutoLogin.exe'
$workingDirectory = $PSScriptRoot

if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "AutoLogin.exe not found: $exePath"
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSid = $identity.User.Value
$escape = [System.Security.SecurityElement]
$escapedExe = $escape::Escape($exePath)
$escapedDirectory = $escape::Escape($workingDirectory)
$escapedSid = $escape::Escape($userSid)

$eventQuery = @"
<QueryList><Query Id="0" Path="Microsoft-Windows-WLAN-AutoConfig/Operational"><Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational">*[System[Provider[@Name='Microsoft-Windows-WLAN-AutoConfig'] and EventID=8001]]</Select></Query></QueryList>
"@
$escapedQuery = $escape::Escape($eventQuery.Trim())

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Log in only when connected to NEU, NEU-2.4G, or NEU-mobile.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$escapedQuery</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$escapedSid</UserId>
      <Delay>PT10S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$escapedSid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <AllowHardTerminate>true</AllowHardTerminate>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$escapedExe</Command>
      <Arguments>--scheduled</Arguments>
      <WorkingDirectory>$escapedDirectory</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed and tested scheduled task: $taskName"

