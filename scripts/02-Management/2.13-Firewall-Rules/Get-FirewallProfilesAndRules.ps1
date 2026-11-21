#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Windows Firewall Profile states (Domain/Private/Public) and active Firewall Rules with port/direction details.
.NOTES
    Category:  02-Management / 2.13-Firewall-Rules
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [string]$RuleFilter = '',
    [Parameter()] [ValidateRange(10, 2000)] [int]$MaxResults = 300,

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
    param($FilterText, $Max)
    $out = New-Object System.Collections.Generic.List[object]

    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    foreach ($pf in $profiles) {
        $out.Add([PSCustomObject]@{
            Severity   = if (-not $pf.Enabled) { 'Warning' } else { 'Info' }
            Kind       = 'Firewall Profile'
            Name       = $pf.Name
            Direction  = "In:$($pf.DefaultInboundAction) / Out:$($pf.DefaultOutboundAction)"
            Action     = if ($pf.Enabled) { 'Enabled' } else { 'Disabled' }
            Profile    = $pf.Name
            Ports      = "Log:$($pf.LogFileName)"
            Summary    = "Profile $($pf.Name): Enabled=$($pf.Enabled) | DefaultIn=$($pf.DefaultInboundAction) | LogAllowed=$($pf.LogAllowed) | LogBlocked=$($pf.LogBlocked)"
            RawMessage = ($pf | Format-List | Out-String)
        })
    }

    $rules = @(Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue)
    $portFilters = @{}
    foreach ($pf in @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        $portFilters[$pf.InstanceID] = $pf
    }

    foreach ($r in $rules) {
        if ($FilterText -and $r.DisplayName -notlike "*$FilterText*" -and $r.Name -notlike "*$FilterText*") { continue }
        $pInfo = ''
        if ($portFilters.ContainsKey($r.Name)) {
            $pfObj = $portFilters[$r.Name]
            $pInfo = "$($pfObj.Protocol) L:$($pfObj.LocalPort) R:$($pfObj.RemotePort)"
        }
        $out.Add([PSCustomObject]@{
            Severity   = if ($r.Action -eq 'Block') { 'Warning' } else { 'Info' }
            Kind       = 'Firewall Rule'
            Name       = $r.DisplayName
            Direction  = [string]$r.Direction
            Action     = [string]$r.Action
            Profile    = [string]$r.Profile
            Ports      = $pInfo
            Summary    = "$($r.DisplayName) [$($r.Direction) $($r.Action)] Profile: $($r.Profile) $pInfo"
            RawMessage = ($r | Format-List DisplayName,Name,Enabled,Direction,Action,Profile,Group,Description | Out-String)
        })
        if ($out.Count -ge $Max) { break }
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); EnabledRules = $rules.Count }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($RuleFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';   label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Kind';       label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';       label = 'Name';         type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Direction';  label = 'Direction';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Action';     label = 'Action';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Profile';    label = 'Profile';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Ports';      label = 'Ports / Log';  type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'fw_rules_enabled'; label = 'Total Enabled Rules'; value = $res.Data.EnabledRules; unit = 'rules'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.13-firewall-rules-profiles' -Category 'Management' -SubCategory 'Firewall Profiles & Active Rules' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.13-firewall-rules-profiles' -Category 'Management' -SubCategory 'Firewall Profiles & Active Rules' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
