#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows Event Log service health, core log sizes/capacity/retention modes, Log Cleared events (104, 1102), and Log Full events (1104).
.NOTES
    Category:  21-Event-Log-Infrastructure
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/EvotecIT/EventViewerX
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
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250,

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
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $elSvc = Get-Service -Name EventLog -ErrorAction SilentlyContinue
    $svcState = if ($elSvc) { [string]$elSvc.Status } else { 'Unknown' }

    $coreLogs = @('System', 'Application', 'Security', 'Setup', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational')
    $fullOrSmall = 0
    foreach ($ln in $coreLogs) {
        try {
            $lg = Get-WinEvent -ListLog $ln -ErrorAction Stop
            $sizeMB = [math]::Round($lg.FileSize / 1MB, 1)
            $maxMB  = [math]::Round($lg.MaximumSizeInBytes / 1MB, 1)
            $pctUsed = if ($lg.MaximumSizeInBytes -gt 0) { [math]::Round(($lg.FileSize / $lg.MaximumSizeInBytes) * 100, 1) } else { 0 }
            if ($maxMB -lt 20 -or ($lg.LogMode -ne 'Circular' -and $pctUsed -gt 85)) { $fullOrSmall++ }
            $sev = if ($lg.LogMode -ne 'Circular' -and $pctUsed -gt 90) { 'Warning' } else { 'Info' }
            $out.Add([PSCustomObject]@{
                TimeCreated = if ($lg.LastWriteTime) { $lg.LastWriteTime.ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }
                Severity    = $sev
                RecordType  = 'Log Channel'
                LogName     = $lg.LogName
                EventId     = 0
                UserName    = ''
                Summary     = "Size: $sizeMB / $maxMB MB ($pctUsed%) | Mode: $($lg.LogMode) | Records: $($lg.RecordCount) | Enabled: $($lg.IsEnabled)"
                RawMessage  = ($lg | Select-Object LogName, IsEnabled, LogMode, FileSize, MaximumSizeInBytes, RecordCount, LastWriteTime, LogFilePath | Format-List | Out-String)
            })
        } catch {}
    }

    # Log Cleared (104 System, 1102 Security) & Log Full (1104 Security) + Eventlog Operational errors
    $clearedCount = 0
    foreach ($q in @(
        @{ Log = 'System'; Ids = @(104, 105, 110) },
        @{ Log = 'Security'; Ids = @(1100, 1102, 1104) }
    )) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $q.Log; Id = $q.Ids; StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                if ($ev.Id -in @(104, 1102)) { $clearedCount++ }
                $user = if ($ev.UserId) { try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $ev.UserId.Value } } else { '' }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = if ($ev.Id -in @(1102, 1104, 104)) { 'Critical' } else { 'Warning' }
                    RecordType  = 'Audit/Health Event'
                    LogName     = $q.Log
                    EventId     = $ev.Id
                    UserName    = $user
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        SvcState     = $svcState
        ClearedCount = $clearedCount
        FullOrSmall  = $fullOrSmall
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogName';     label = 'Log Channel';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'eventlog_svc';     label = 'EventLog Service'; value = $res.Data.SvcState;     unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'critical' } }
        @{ key = 'logs_cleared';     label = 'Log Cleared (104/1102)'; value = $res.Data.ClearedCount; unit = 'events'; severity = if ($res.Data.ClearedCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'small_full_logs';  label = 'Small/Near-Full Logs'; value = $res.Data.FullOrSmall; unit = 'logs';   severity = if ($res.Data.FullOrSmall -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '21.1-eventlog-infra' -Category 'Event Log Infrastructure' -SubCategory 'Event Log Health' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '21.1-eventlog-infra' -Category 'Event Log Infrastructure' -SubCategory 'Event Log Health' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
