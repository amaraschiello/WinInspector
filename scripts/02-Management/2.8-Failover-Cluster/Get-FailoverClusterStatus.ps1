#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Failover Cluster status, Nodes, Roles/Groups, Resources, CSVs, Networks, and Cluster Operational errors.
.NOTES
    Category:  02-Management / 2.8-Failover-Cluster
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [ValidateRange(1, 720)] [int]$HoursBack = 72
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $clusSvc = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
    $svcState = if ($clusSvc) { [string]$clusSvc.Status } else { 'NotInstalled' }

    $out.Add([PSCustomObject]@{
        Severity   = if ($clusSvc -and $clusSvc.Status -ne 'Running') { 'Warning' } else { 'Info' }
        ObjectType = 'Cluster Service'
        Name       = 'ClusSvc'
        State      = $svcState
        OwnerNode  = $env:COMPUTERNAME
        Summary    = "Cluster Service (ClusSvc): $svcState"
        RawMessage = ($clusSvc | Format-List | Out-String)
    })

    if (Get-Module -ListAvailable -Name FailoverClusters) {
        try {
            Import-Module FailoverClusters -ErrorAction Stop
            $cl = Get-Cluster -ErrorAction Stop
            $out.Add([PSCustomObject]@{
                Severity   = 'Info'
                ObjectType = 'Cluster'
                Name       = $cl.Name
                State      = 'Online'
                OwnerNode  = $cl.Domain
                Summary    = "Cluster: $($cl.Name) | Domain: $($cl.Domain)"
                RawMessage = ($cl | Format-List | Out-String)
            })
            foreach ($n in @(Get-ClusterNode -ErrorAction SilentlyContinue)) {
                $out.Add([PSCustomObject]@{
                    Severity   = if ($n.State -ne 'Up') { 'Critical' } else { 'Info' }
                    ObjectType = 'Node'
                    Name       = $n.Name
                    State      = [string]$n.State
                    OwnerNode  = $n.Name
                    Summary    = "Node $($n.Name): $($n.State)"
                    RawMessage = ($n | Format-List | Out-String)
                })
            }
            foreach ($g in @(Get-ClusterGroup -ErrorAction SilentlyContinue)) {
                $out.Add([PSCustomObject]@{
                    Severity   = if ($g.State -ne 'Online') { 'Warning' } else { 'Info' }
                    ObjectType = 'Role / Group'
                    Name       = $g.Name
                    State      = [string]$g.State
                    OwnerNode  = [string]$g.OwnerNode
                    Summary    = "Group $($g.Name): $($g.State) on $($g.OwnerNode)"
                    RawMessage = ($g | Format-List | Out-String)
                })
            }
            foreach ($r in @(Get-ClusterResource -ErrorAction SilentlyContinue)) {
                $out.Add([PSCustomObject]@{
                    Severity   = if ($r.State -ne 'Online') { 'Warning' } else { 'Info' }
                    ObjectType = 'Resource'
                    Name       = $r.Name
                    State      = [string]$r.State
                    OwnerNode  = "$($r.OwnerGroup) @ $($r.OwnerNode)"
                    Summary    = "Resource $($r.Name) ($($r.ResourceType)): $($r.State)"
                    RawMessage = ($r | Format-List | Out-String)
                })
            }
            foreach ($csv in @(Get-ClusterSharedVolume -ErrorAction SilentlyContinue)) {
                $out.Add([PSCustomObject]@{
                    Severity   = if ($csv.State -ne 'Online') { 'Critical' } else { 'Info' }
                    ObjectType = 'CSV'
                    Name       = $csv.Name
                    State      = [string]$csv.State
                    OwnerNode  = [string]$csv.OwnerNode
                    Summary    = "CSV $($csv.Name): $($csv.State) (Owner: $($csv.OwnerNode))"
                    RawMessage = ($csv | Format-List | Out-String)
                })
            }
        }
        catch {
            $out.Add([PSCustomObject]@{
                Severity   = 'Warning'
                ObjectType = 'Cluster Query'
                Name       = 'FailoverClusters'
                State      = 'Unavailable'
                OwnerNode  = $env:COMPUTERNAME
                Summary    = $_.Exception.Message
                RawMessage = $_.Exception.Message
            })
        }
    }

    $startTime = (Get-Date).AddHours(-$Hours)
    try {
        foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-FailoverClustering/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue)) {
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                Severity   = if ($ev.Level -le 2) { 'Error' } else { 'Warning' }
                ObjectType = "Cluster Event ($($ev.Id))"
                Name       = $ev.TimeCreated.ToUniversalTime().ToString('o')
                State      = "Event $($ev.Id)"
                OwnerNode  = $ev.MachineName
                Summary    = ($msg -split "`r?`n")[0]
                RawMessage = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{ Rows = $out.ToArray(); SvcState = $svcState }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';   label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ObjectType'; label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';       label = 'Name / Time';  type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'State';      label = 'State';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'OwnerNode';  label = 'Owner / Node'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'clus_svc';   label = 'ClusSvc Status'; value = $res.Data.SvcState; unit = '';      severity = 'info' }
        @{ key = 'clus_items'; label = 'Cluster Items';  value = $rows.Count;        unit = 'items'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.8-failover-cluster' -Category 'Management' -SubCategory 'Failover Cluster Status' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.8-failover-cluster' -Category 'Management' -SubCategory 'Failover Cluster Status' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
