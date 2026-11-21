#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Microsoft-Windows-GroupPolicy/Operational for GP processing failures, warnings, and slow CSE processing times (7016/7017/8000-8007).
.NOTES
    Category:  05-ActiveDirectory-Auth / 5.4-Group-Policy
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
    [ValidateRange(1, 720)]
    [int]$HoursBack = 72,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250,

    [Parameter()]
    [switch]$QueryAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$effectiveMax = if ($QueryAll) { 2147483647 } else { $MaxResults }
Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $evs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-GroupPolicy/Operational'
        StartTime = $startTime
    } -MaxEvents ($Max * 2) -ErrorAction SilentlyContinue

    $maxDurationMs = 0
    foreach ($ev in $evs) {
        # Include Errors/Warnings (Level 1-3) + GP completion/timing events (7016, 7017, 8000-8007)
        if ($ev.Level -gt 3 -and $ev.Id -notin @(7016, 7017, 8000, 8001, 8004, 8005, 8006, 8007)) { continue }

        $m = @{}
        try {
            $x = [xml]$ev.ToXml()
            foreach ($n in $x.Event.EventData.Data) {
                if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
            }
        } catch {}

        $durMs = 0
        if ($m.ContainsKey('ExtensionElaspedTimeInMilliSeconds')) { $durMs = [int]$m['ExtensionElaspedTimeInMilliSeconds'] }
        elseif ($m.ContainsKey('PolicyElaspedTimeInSeconds')) { $durMs = ([int]$m['PolicyElaspedTimeInSeconds']) * 1000 }
        if ($durMs -gt $maxDurationMs) { $maxDurationMs = $durMs }

        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { if ($durMs -gt 10000) { 'Warning' } else { 'Info' } } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            EventId     = $ev.Id
            UserName    = [string]$m['PrincipalSamName']
            Extension   = [string]$m['CSEExtensionName']
            DurationMs  = $durMs
            ErrorCode   = [string]$m['ErrorCode']
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
        if ($out.Count -ge $Max) { break }
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); MaxDurationMs = $maxDurationMs }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)
    $errCount = @($rows | Where-Object { $_.Severity -in @('Critical', 'Error') }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'Principal';     type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Extension';   label = 'CSE Extension'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DurationMs';  label = 'Duration (ms)'; type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'ErrorCode';   label = 'Error Code';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'gp_events';       label = 'GP Events';        value = $rows.Count;              unit = 'events'; severity = 'info' }
        @{ key = 'gp_errors';       label = 'GP Errors';        value = $errCount;                unit = 'events'; severity = if ($errCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'gp_max_duration'; label = 'Max CSE Duration'; value = $res.Data.MaxDurationMs;  unit = 'ms';     severity = if ($res.Data.MaxDurationMs -gt 10000) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '5.4-group-policy' -Category 'Active Directory & Authentication' -SubCategory 'Group Policy' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '5.4-group-policy' -Category 'Active Directory & Authentication' -SubCategory 'Group Policy' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
