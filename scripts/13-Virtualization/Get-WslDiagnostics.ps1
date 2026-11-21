#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows Subsystem for Linux (WSL) distributions, LxssManager/WSLService state, and WSL/LxssManager error events.
.NOTES
    Category:  13-Virtualization / 13.2-WSL
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
    $warns = New-Object System.Collections.Generic.List[string]

    $wslSvc = Get-Service -Name WSLService, LxssManager -ErrorAction SilentlyContinue | Select-Object -First 1
    $wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue

    if (-not $wslSvc -and -not $wslExe) {
        $warns.Add("WSL (WSLService/LxssManager) is not installed on '$env:COMPUTERNAME'.")
        return [PSCustomObject]@{ Rows = @(); Installed = $false; SvcState = 'Not Installed'; WslEvents = 0; Warnings = $warns.ToArray() }
    }

    $svcState = if ($wslSvc) { "$($wslSvc.Name): $($wslSvc.Status)" } else { 'wsl.exe present' }
    $wslStatusOut = if ($wslExe) { ((& wsl.exe --status 2>&1) -join "`n") -replace "`0", '' } else { 'wsl.exe not found' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'WSL State'
        EventId     = 0
        Source      = 'WSL'
        Summary     = "WSL Service: $svcState"
        RawMessage  = $wslStatusOut
    })

    $wslEvents = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = @('LxssManager', 'Microsoft-Windows-Lxss-Manager', 'WslService')
            Level        = @(1, 2, 3)
            StartTime    = $startTime
        } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $wslEvents++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'WSL Event'
                EventId     = $ev.Id
                Source      = $ev.ProviderName
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows      = @($out.ToArray() | Select-Object -First $Max)
        Installed = $true
        SvcState  = $svcState
        WslEvents = $wslEvents
        Warnings  = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
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
        @{ key = 'wsl_svc';    label = 'WSL Service'; value = $res.Data.SvcState;  unit = '';       severity = 'info' }
        @{ key = 'wsl_events'; label = 'WSL Errors';  value = $res.Data.WslEvents; unit = 'events'; severity = if ($res.Data.WslEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($res.Data.Installed) { 'Success' } else { 'Partial' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '13.2-wsl' -Category 'Virtualization' -SubCategory 'WSL' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '13.2-wsl' -Category 'Virtualization' -SubCategory 'WSL' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
