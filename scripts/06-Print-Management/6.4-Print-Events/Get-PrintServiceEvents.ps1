#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Microsoft-Windows-PrintService Admin & Operational event logs and System Spooler service crash events.
.NOTES
    Category:  06-Print-Management / 6.4-Print-Events
    Protocols: WinRM
    ReadOnly:  True
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
    [int]$HoursBack = 72,

    [Parameter()]
    [string]$PrinterName = '',

    [Parameter()]
    [ValidateSet('All', 'ErrorsAndWarnings', 'PrintJobs307')]
    [string]$EventScope = 'All',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $NameFilter, $Scope, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $adminErrors = 0
    $opEvents = 0
    $failedJobs372 = 0
    $printed307 = 0
    $opLogEnabled = $false

    try {
        $opLogMeta = Get-WinEvent -ListLog 'Microsoft-Windows-PrintService/Operational' -ErrorAction SilentlyContinue
        if ($opLogMeta) {
            $opLogEnabled = [bool]$opLogMeta.IsEnabled
        }
        if (-not $opLogEnabled) {
            $warns.Add("Microsoft-Windows-PrintService/Operational log is currently DISABLED on this host. Enable it in Event Viewer or via 'wevtutil sl Microsoft-Windows-PrintService/Operational /e:true' to capture Event ID 307 (printed document history).")
        }
    } catch {}

    # 1. PrintService Admin log (errors, warnings, failed jobs 372, plugin failures 808)
    if ($Scope -ne 'PrintJobs307') {
        try {
            $filterAdmin = @{ LogName = 'Microsoft-Windows-PrintService/Admin'; StartTime = $startTime }
            if ($Scope -eq 'ErrorsAndWarnings') {
                $filterAdmin['Level'] = @(1, 2, 3)
            }
            $evs = Get-WinEvent -FilterHashtable $filterAdmin -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $msg = if ($ev.Message) { [string]$ev.Message } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($NameFilter) -and ($msg -notlike "*$NameFilter*")) {
                    continue
                }
                if ($ev.Level -in @(1, 2, 3)) { $adminErrors++ }
                if ($ev.Id -eq 372) { $failedJobs372++ }
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    LogSource   = 'PrintService/Admin'
                    EventId     = [int]$ev.Id
                    UserName    = if ($ev.UserId) { [string]$ev.UserId } else { '' }
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    # 2. PrintService Operational log (if enabled)
    if ($opLogEnabled) {
        try {
            $filterOp = @{ LogName = 'Microsoft-Windows-PrintService/Operational'; StartTime = $startTime }
            if ($Scope -eq 'PrintJobs307') {
                $filterOp['Id'] = 307
            }
            elseif ($Scope -eq 'ErrorsAndWarnings') {
                $filterOp['Level'] = @(1, 2, 3)
            }
            $evs = Get-WinEvent -FilterHashtable $filterOp -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $msg = if ($ev.Message) { [string]$ev.Message } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($NameFilter) -and ($msg -notlike "*$NameFilter*")) {
                    continue
                }
                $opEvents++
                if ($ev.Id -eq 307) { $printed307++ }
                if ($ev.Id -eq 372) { $failedJobs372++ }
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    LogSource   = 'PrintService/Operational'
                    EventId     = [int]$ev.Id
                    UserName    = if ($ev.UserId) { [string]$ev.UserId } else { '' }
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    # 3. System log for Spooler service unexpected terminations (7031 / 7034)
    if ($Scope -ne 'PrintJobs307') {
        try {
            $sysEvs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7031, 7034); StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue
            foreach ($ev in $sysEvs) {
                $msg = if ($ev.Message) { [string]$ev.Message } else { '' }
                if ($msg -notmatch 'Print Spooler|Spooler') { continue }
                $adminErrors++
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = 'Error'
                    LogSource   = 'System (SCM)'
                    EventId     = [int]$ev.Id
                    UserName    = ''
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    $sorted = @($out.ToArray() | Sort-Object -Property TimeCreated -Descending | Select-Object -First $Max)

    return [PSCustomObject]@{
        Rows          = $sorted
        AdminErrors   = $adminErrors
        OpEvents      = $opEvents
        FailedJobs372 = $failedJobs372
        Printed307    = $printed307
        OpLogEnabled  = $opLogEnabled
        Warnings      = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $PrinterName.Trim(), $EventScope, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogSource';   label = 'Log Source';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User / SID';   type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $opStatusStr = if ($res.Data.OpLogEnabled) { 'Enabled' } else { 'Disabled' }
    $metrics = @(
        @{ key = 'admin_errors';  label = 'Admin/SCM Errors';    value = $res.Data.AdminErrors;   unit = 'events'; severity = if ($res.Data.AdminErrors -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'failed_372';    label = 'Failed Jobs (372)';   value = $res.Data.FailedJobs372; unit = 'events'; severity = if ($res.Data.FailedJobs372 -gt 0) { 'error' } else { 'ok' } }
        @{ key = 'printed_307';   label = 'Printed Docs (307)';  value = $res.Data.Printed307;    unit = 'jobs';   severity = 'info' }
        @{ key = 'op_log_state';  label = 'Operational Log';     value = $opStatusStr;            unit = '';       severity = if ($res.Data.OpLogEnabled) { 'ok' } else { 'warning' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.4-print-events' -Category 'Print Management' -SubCategory 'PrintService Event Logs & Audit' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.4-print-events' -Category 'Print Management' -SubCategory 'PrintService Event Logs & Audit' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
