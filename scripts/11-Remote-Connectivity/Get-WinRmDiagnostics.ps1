#Requires -Version 5.1
<#
.SYNOPSIS
    Audits WinRM service state, WS-Man listeners, TrustedHosts, and Microsoft-Windows-WinRM/Operational errors.
.NOTES
    Category:  11-Remote-Connectivity / 11.2-WinRM
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

    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'Missing' }

    $listeners = @()
    try { $listeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue) } catch {}
    $trusted = try { (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value } catch { 'Access Denied / N/A' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($svcState -eq 'Running') { 'Info' } else { 'Critical' }
        RecordType  = 'WinRM State'
        EventId     = 0
        Source      = 'WinRM Service'
        Summary     = "WinRM Service: $svcState | Listeners: $($listeners.Count) | TrustedHosts: $(if ($trusted) { $trusted } else { '(empty)' })"
        RawMessage  = "Service: $svcState`nListeners: $($listeners.Count)`nTrustedHosts: $trusted"
    })

    foreach ($l in $listeners) {
        $props = @{}
        foreach ($k in $l.Keys) {
            $kv = $k -split '=', 2
            if ($kv.Count -eq 2) { $props[$kv[0]] = $kv[1] }
        }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Info'
            RecordType  = 'WinRM Listener'
            EventId     = 0
            Source      = $l.Name
            Summary     = "Transport: $($props['Transport']) | Address: $($props['Address'])"
            RawMessage  = ($l | Format-List | Out-String)
        })
    }

    $errCount = 0
    $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WinRM/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $evs) {
        $errCount++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'WinRM Event'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{ Rows = @($out | Select-Object -First $Max); SvcState = $svcState; ListenerCount = $listeners.Count; ErrCount = $errCount }
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
        @{ key = 'winrm_svc';       label = 'WinRM Service';  value = $res.Data.SvcState;      unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'critical' } }
        @{ key = 'winrm_listeners'; label = 'Listeners';      value = $res.Data.ListenerCount; unit = 'active'; severity = 'info' }
        @{ key = 'winrm_errors';    label = 'WinRM Errors';   value = $res.Data.ErrCount;      unit = 'events'; severity = if ($res.Data.ErrCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '11.2-winrm' -Category 'Remote Connectivity' -SubCategory 'WinRM' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '11.2-winrm' -Category 'Remote Connectivity' -SubCategory 'WinRM' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
