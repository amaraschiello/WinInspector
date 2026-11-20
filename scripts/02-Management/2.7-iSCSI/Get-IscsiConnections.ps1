#Requires -Version 5.1
<#
.SYNOPSIS
    Reports iSCSI Initiator service state, Target Portals, Targets, Sessions, and Connections.
.NOTES
    Category:  02-Management / 2.7-iSCSI
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    $out = New-Object System.Collections.Generic.List[object]
    $svc = Get-Service -Name MSiSCSI -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'NotInstalled' }

    $out.Add([PSCustomObject]@{
        Type          = 'Service'
        TargetOrPortal= 'MSiSCSI (Microsoft iSCSI Initiator)'
        Address       = ''
        Status        = $svcState
        Detail        = if ($svc) { "StartType: $($svc.StartType)" } else { 'Service not present' }
        RawMessage    = ($svc | Format-List | Out-String)
    })

    if (Get-Command Get-IscsiTargetPortal -ErrorAction SilentlyContinue) {
        foreach ($tp in @(Get-IscsiTargetPortal -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                Type           = 'Target Portal'
                TargetOrPortal = "$($tp.TargetPortalAddress):$($tp.TargetPortalPortNumber)"
                Address        = $tp.TargetPortalAddress
                Status         = 'Configured'
                Detail         = "Initiator: $($tp.InitiatorInstanceName)"
                RawMessage     = ($tp | Format-List | Out-String)
            })
        }
        foreach ($t in @(Get-IscsiTarget -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                Type           = 'iSCSI Target'
                TargetOrPortal = $t.NodeAddress
                Address        = ''
                Status         = if ($t.IsConnected) { 'Connected' } else { 'Disconnected' }
                Detail         = "IsConnected=$($t.IsConnected)"
                RawMessage     = ($t | Format-List | Out-String)
            })
        }
        foreach ($s in @(Get-IscsiSession -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                Type           = 'iSCSI Session'
                TargetOrPortal = $s.TargetNodeAddress
                Address        = $s.InitiatorNodeAddress
                Status         = if ($s.IsConnected) { 'Connected' } else { 'Inactive' }
                Detail         = "SessionId=$($s.SessionIdentifier) | Persistent=$($s.IsPersistent)"
                RawMessage     = ($s | Format-List | Out-String)
            })
        }
        foreach ($c in @(Get-IscsiConnection -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                Type           = 'iSCSI Connection'
                TargetOrPortal = "$($c.InitiatorAddress):$($c.InitiatorPortNumber) -> $($c.TargetAddress):$($c.TargetPortNumber)"
                Address        = $c.TargetAddress
                Status         = 'Active'
                Detail         = "ConnId=$($c.ConnectionIdentifier)"
                RawMessage     = ($c | Format-List | Out-String)
            })
        }
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); SvcState = $svcState }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Type';           label = 'Type';            type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'TargetOrPortal'; label = 'Target / Portal'; type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Address';        label = 'Address';         type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Status';         label = 'Status';          type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Detail';         label = 'Details';         type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';     label = 'Full Details';    type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'iscsi_svc';   label = 'MSiSCSI Service'; value = $res.Data.SvcState; unit = '';      severity = 'info' }
        @{ key = 'iscsi_items'; label = 'iSCSI Objects';   value = $rows.Count;        unit = 'items'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.7-iscsi' -Category 'Management' -SubCategory 'iSCSI Connections & Targets' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.7-iscsi' -Category 'Management' -SubCategory 'iSCSI Connections & Targets' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
