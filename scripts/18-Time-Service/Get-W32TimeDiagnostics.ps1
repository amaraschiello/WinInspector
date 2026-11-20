#Requires -Version 5.1
<#
.SYNOPSIS
    Audits W32Time service, NTP sync status (w32tm /query /status & /configuration), clock drift, and Time-Service System events.
.NOTES
    Category:  18-Time-Service
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
    [int]$HoursBack = 168,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $w32svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    $svcState = if ($w32svc) { [string]$w32svc.Status } else { 'Missing' }

    $statusRaw = (& w32tm.exe /query /status 2>&1) -join "`n"
    $sourceRaw = (& w32tm.exe /query /source 2>&1) -join "`n"
    $stratum   = if ($statusRaw -match 'Stratum:\s*(\S+)') { $Matches[1] } else { 'Unknown' }
    $lastSync  = if ($statusRaw -match 'Last Successful Sync Time:\s*(.+)') { $Matches[1].Trim() } else { 'Unknown' }
    $ntpSource = ($sourceRaw -split "`r?`n")[0].Trim()

    $sev = if ($svcState -ne 'Running') { 'Error' } elseif ($ntpSource -like '*CMOS*' -or $ntpSource -like '*Free-running*') { 'Warning' } else { 'Info' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = $sev
        RecordType  = 'W32Time Status'
        EventId     = 0
        Source      = 'w32tm'
        Summary     = "W32Time: $svcState | Source: $ntpSource | Stratum: $stratum | LastSync: $lastSync"
        RawMessage  = "Service: $svcState`nSource: $ntpSource`n`n$statusRaw"
    })

    $timeErrs = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-Time-Service', 'W32Time')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $timeErrs++
        $evSev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $evSev
            RecordType  = 'Time-Service Event'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows      = @($out.ToArray() | Select-Object -First $Max)
        SvcState  = $svcState
        NtpSource = $ntpSource
        TimeErrs  = $timeErrs
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'w32time_svc';    label = 'W32Time Service'; value = $res.Data.SvcState;  unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'critical' } }
        @{ key = 'w32time_source'; label = 'Time Source';     value = $res.Data.NtpSource; unit = '';       severity = 'info' }
        @{ key = 'w32time_errors'; label = 'Time Warnings';   value = $res.Data.TimeErrs;  unit = 'events'; severity = if ($res.Data.TimeErrs -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '18.1-w32time' -Category 'Time Service' -SubCategory 'W32Time / NTP' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '18.1-w32time' -Category 'Time Service' -SubCategory 'W32Time / NTP' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
