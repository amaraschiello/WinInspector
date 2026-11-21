#Requires -Version 5.1
<#
.SYNOPSIS
    Queries System Event Log for DistributedCOM (DCOM) activation, timeout, and permission denied errors (10005, 10010, 10016, 10028).
.NOTES
    Category:  12-Application-Platform / 12.2-COM-DCOM
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

    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-DistributedCOM', 'DCOM')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $m = @{}
        try {
            $x = [xml]$ev.ToXml()
            $i = 0
            foreach ($n in $x.Event.EventData.Data) {
                if ($n -is [System.Xml.XmlElement]) {
                    $k = if ($n.HasAttribute('Name')) { $n.GetAttribute('Name') } else { "Param$i" }
                    $m[$k] = $n.InnerText
                }
                else { $m["Param$i"] = [string]$n }
                $i++
            }
        } catch {}

        $user = if ($m.ContainsKey('param6') -and $m['param7']) { "$($m['param6'])\$($m['param7'])" }
                elseif ($ev.UserId) { try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $ev.UserId.Value } }
                else { '' }
        $clsid = if ($m.ContainsKey('param4')) { $m['param4'] } elseif ($m.ContainsKey('param1')) { $m['param1'] } else { '' }
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }

        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            UserName    = $user
            ClsidOrApp  = $clsid
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)
    $err10016 = @($rows | Where-Object { $_.EventId -eq 10016 }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'Account';      type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClsidOrApp';  label = 'CLSID / App';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dcom_events'; label = 'DCOM Events';       value = $rows.Count; unit = 'events'; severity = if ($rows.Count -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'dcom_10016';  label = 'Permission (10016)';value = $err10016;   unit = 'events'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '12.2-com-dcom' -Category 'Application Platform' -SubCategory 'COM / DCOM' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '12.2-com-dcom' -Category 'Application Platform' -SubCategory 'COM / DCOM' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
