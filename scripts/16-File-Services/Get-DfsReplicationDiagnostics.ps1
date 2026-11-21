#Requires -Version 5.1
<#
.SYNOPSIS
    Audits DFS Replication (DFSR) & DFS Namespace services, replicated folder states, and DFS Replication event log errors.
.NOTES
    Category:  16-File-Services / 16.2-DFS
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

    $dfsrSvc = Get-Service -Name DFSR -ErrorAction SilentlyContinue
    $dfsSvc  = Get-Service -Name Dfs -ErrorAction SilentlyContinue
    if (-not $dfsrSvc -and -not $dfsSvc) {
        $warns.Add("Neither DFSR nor DFS Namespace service is installed on '$env:COMPUTERNAME'.")
        return [PSCustomObject]@{ Rows = @(); Installed = $false; DfsrState = 'Not Installed'; DfsErrors = 0; Warnings = $warns.ToArray() }
    }

    $dfsrState = if ($dfsrSvc) { [string]$dfsrSvc.Status } else { 'Not Installed' }
    $dfsState  = if ($dfsSvc)  { [string]$dfsSvc.Status }  else { 'Not Installed' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'DFS Services'
        EventId     = 0
        Source      = 'DFSR / DFS'
        Summary     = "DFSR Service: $dfsrState | DFS Namespace Service: $dfsState"
        RawMessage  = "DFSR: $dfsrState`nDFS: $dfsState"
    })

    # Replicated folder state via WMI (root\MicrosoftDFS)
    try {
        foreach ($rf in @(Get-CimInstance -Namespace 'root\MicrosoftDFS' -ClassName DfsrReplicatedFolderInfo -ErrorAction SilentlyContinue)) {
            $stateText = switch ($rf.State) { 0 { 'Uninitialized' } 1 { 'Initialized' } 2 { 'Initial Sync' } 3 { 'Auto Recovery' } 4 { 'Normal' } 5 { 'In Error' } default { "State $($rf.State)" } }
            $sev = if ($rf.State -eq 5) { 'Critical' } elseif ($rf.State -ne 4) { 'Warning' } else { 'Info' }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'DFSR Folder'
                EventId     = 0
                Source      = $rf.ReplicationGroupName
                Summary     = "Folder '$($rf.ReplicatedFolderName)' ($($rf.ReplicationGroupName)): $stateText"
                RawMessage  = ($rf | Format-List | Out-String)
            })
        }
    } catch {}

    $dfsErrors = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $dfsErrors++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'DFSR Event'
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
        DfsrState = $dfsrState
        DfsErrors = $dfsErrors
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
        @{ key = 'Source';      label = 'Group/Source'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dfsr_svc';    label = 'DFSR Service'; value = $res.Data.DfsrState; unit = '';       severity = if ($res.Data.DfsrState -eq 'Running') { 'ok' } else { 'info' } }
        @{ key = 'dfsr_errors'; label = 'DFSR Errors';  value = $res.Data.DfsErrors; unit = 'events'; severity = if ($res.Data.DfsErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($res.Data.Installed) { 'Success' } else { 'Partial' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '16.2-dfs' -Category 'File Services' -SubCategory 'DFS & Replication' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '16.2-dfs' -Category 'File Services' -SubCategory 'DFS & Replication' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
