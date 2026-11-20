#Requires -Version 5.1
<#
.SYNOPSIS
    Queries System Event Log for Shutdown, Restart, and Unexpected Power Loss events (41, 1074, 6008, 1076, 6005, 6006).
.NOTES
    Category:  01-OperatingSystem-Core / 1.2-Shutdown-and-Restart
    Protocols: WinRM, RPC
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
    [ValidateRange(1, 2160)]
    [int]$HoursBack = 720,

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

$eventIds = @(41, 1074, 1076, 6005, 6006, 6008)

$remoteScript = {
    param($Hours, $Max, $Ids)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $evs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $Ids; StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $evs) {
        $xmlMap = @{}
        try {
            $x = [xml]$ev.ToXml()
            $i = 0
            foreach ($n in $x.Event.EventData.Data) {
                if ($n -is [System.Xml.XmlElement]) {
                    $k = if ($n.HasAttribute('Name')) { $n.GetAttribute('Name') } else { "Param$i" }
                    $xmlMap[$k] = $n.InnerText
                }
                else { $xmlMap["Param$i"] = [string]$n }
                $i++
            }
        } catch {}

        $eventType = switch ($ev.Id) {
            41   { 'Unexpected Reboot / Kernel-Power' }
            1074 { 'Planned / User-Initiated Restart or Shutdown' }
            1076 { 'Unexpected Shutdown Reason Recorded' }
            6008 { 'Unexpected Shutdown Detected' }
            6005 { 'Event Log Service Started (Boot)' }
            6006 { 'Event Log Service Stopped (Clean Shutdown)' }
            default { "Event $($ev.Id)" }
        }

        $sev = switch ($ev.Id) {
            41   { 'Critical' }
            6008 { 'Error' }
            1076 { 'Warning' }
            default { 'Info' }
        }

        $user    = if ($xmlMap.ContainsKey('param7')) { $xmlMap['param7'] } elseif ($xmlMap.ContainsKey('Param6')) { $xmlMap['Param6'] } else { '' }
        $process = if ($xmlMap.ContainsKey('param1')) { $xmlMap['param1'] } elseif ($xmlMap.ContainsKey('Param0')) { $xmlMap['Param0'] } else { '' }
        $reason  = if ($xmlMap.ContainsKey('param3')) { $xmlMap['param3'] } elseif ($xmlMap.ContainsKey('BugcheckCode')) { "BugcheckCode=$($xmlMap['BugcheckCode'])" } else { '' }
        $msg     = if ($ev.Message) { $ev.Message } else { '(No message)' }
        $summary = ($msg -split "`r?`n")[0]
        if ($summary.Length -gt 200) { $summary = $summary.Substring(0, 197) + '...' }

        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            EventId     = $ev.Id
            EventType   = $eventType
            UserName    = $user
            Initiator   = $process
            Reason      = $reason
            Source      = $ev.ProviderName
            Summary     = $summary
            RawMessage  = $msg
        })
    }

    return $out.ToArray()
}

$fallbackRpc = {
    param($Target, $Cred, $Proto, $Hours, $Max, $Ids)
    $startTime = (Get-Date).AddHours(-$Hours)
    $evParams = @{ ComputerName = $Target; FilterHashtable = @{ LogName = 'System'; Id = $Ids; StartTime = $startTime }; MaxEvents = $Max; ErrorAction = 'SilentlyContinue' }
    if ($null -ne $Cred) { $evParams['Credential'] = $Cred }
    $evs = Get-WinEvent @evParams
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($ev in $evs) {
        $sev = switch ($ev.Id) { 41 { 'Critical' } 6008 { 'Error' } 1076 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '(No message)' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            EventId     = $ev.Id
            EventType   = "Event $($ev.Id)"
            UserName    = ''
            Initiator   = ''
            Reason      = ''
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }
    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults, $eventIds) -FallbackScriptBlock $fallbackRpc
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)

    $unexpectedCount = @($rows | Where-Object { $_.EventId -in @(41, 6008) }).Count
    $plannedCount    = @($rows | Where-Object { $_.EventId -eq 1074 }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';   type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';    type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';    type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventType';   label = 'Event Type';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';        type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Initiator';   label = 'Initiator';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Reason';      label = 'Reason/Code'; type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'total_power_events';  label = 'Total Events';             value = $rows.Count;     unit = 'events'; severity = 'info' }
        @{ key = 'unexpected_shutdowns';label = 'Unexpected (41 / 6008)';   value = $unexpectedCount;unit = 'events'; severity = if ($unexpectedCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'planned_restarts';    label = 'Planned Restarts (1074)';  value = $plannedCount;   unit = 'events'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '1.2-shutdown-restart' -Category 'Operating System & Core System' -SubCategory 'Shutdown & Restart' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '1.2-shutdown-restart' -Category 'Operating System & Core System' -SubCategory 'Shutdown & Restart' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
