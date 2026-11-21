#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows Scheduled Tasks with non-zero LastTaskResult, disabled/failed tasks, and TaskScheduler/Operational error events.
.NOTES
    Category:  17-Scheduled-Tasks
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/dschunk/windows-it-toolkit
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ComputerName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')]
    [string]$Protocol = 'Auto',

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 168,

    [Parameter()]
    [string]$TaskFilter = '',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 300,

    [Parameter()]
    [switch]$QueryAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$effectiveMax = if ($QueryAll) { 2147483647 } else { $MaxResults }
Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $FilterText, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $failedTasks = 0
    $totalTasks  = 0

    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $totalTasks++
        if (-not [string]::IsNullOrWhiteSpace($FilterText) -and $t.TaskName -notlike "*$FilterText*" -and $t.TaskPath -notlike "*$FilterText*") { continue }

        $info = $null
        try { $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction SilentlyContinue } catch {}
        $lastResult = if ($info) { $info.LastTaskResult } else { 0 }
        $isFailure = ($lastResult -ne 0 -and $lastResult -ne 267009 -and $lastResult -ne 267011 -and $lastResult -ne 267014)
        # 267009 = Running, 267011 = Not yet run, 267014 = Terminated by user
        if (-not $isFailure -and [string]::IsNullOrWhiteSpace($FilterText)) { continue }

        if ($isFailure) { $failedTasks++ }
        $hexCode = '0x' + ('{0:X8}' -f $lastResult)
        $runAs = if ($t.Principal -and $t.Principal.UserId) { $t.Principal.UserId } else { '' }
        $lastRun = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 1990) { $info.LastRunTime.ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }

        $out.Add([PSCustomObject]@{
            TimeCreated = $lastRun
            Severity    = if ($isFailure) { 'Error' } else { 'Info' }
            RecordType  = 'Scheduled Task'
            TaskName    = "$($t.TaskPath)$($t.TaskName)"
            State       = [string]$t.State
            UserName    = $runAs
            LastResult  = "$lastResult ($hexCode)"
            EventId     = 0
            Summary     = "Task '$($t.TaskName)' | State: $($t.State) | LastResult: $lastResult ($hexCode) | RunAs: $runAs"
            RawMessage  = ($t | Select-Object TaskName, TaskPath, State, Description | Format-List | Out-String) + "`n" + ($info | Format-List | Out-String)
        })
    }

    $taskEvents = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            if (-not [string]::IsNullOrWhiteSpace($FilterText) -and $ev.Message -notlike "*$FilterText*") { continue }
            $taskEvents++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'TaskScheduler Event'
                TaskName    = $ev.ProviderName
                State       = $sev
                UserName    = ''
                LastResult  = "Event $($ev.Id)"
                EventId     = $ev.Id
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows        = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        TotalTasks  = $totalTasks
        FailedTasks = $failedTasks
        TaskEvents  = $taskEvents
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $TaskFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Last Run / Time'; type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';        type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';            type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'TaskName';    label = 'Task Name';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';       label = 'State';           type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'Run As';          type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LastResult';  label = 'Result / Code';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';        type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';         type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';    type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'tasks_total';  label = 'Total Tasks';      value = $res.Data.TotalTasks;  unit = 'tasks';  severity = 'info' }
        @{ key = 'tasks_failed'; label = 'Non-Zero Results'; value = $res.Data.FailedTasks; unit = 'tasks';  severity = if ($res.Data.FailedTasks -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'task_events';  label = 'Scheduler Errors'; value = $res.Data.TaskEvents;  unit = 'events'; severity = if ($res.Data.TaskEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '17.1-scheduled-tasks' -Category 'Scheduled Tasks' -SubCategory 'Task Scheduler' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '17.1-scheduled-tasks' -Category 'Scheduled Tasks' -SubCategory 'Task Scheduler' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
