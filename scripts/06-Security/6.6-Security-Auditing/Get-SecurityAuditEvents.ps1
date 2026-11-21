#Requires -Version 5.1
<#
.SYNOPSIS
    Queries high-signal Security Auditing events: Special Privileges (4672), Process Creation (4688), Service Installation (4697), and Logon/Failure (4624/4625).
.NOTES
    Category:  06-Security / 6.6-Security-Auditing
    Protocols: WinRM, RPC
    ReadOnly:  True
    Reference: https://github.com/Dan-Duran/Windows-Security-Scripts
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
    [int]$HoursBack = 24,

    [Parameter()]
    [string]$UserName = '',

    [Parameter()]
    [string[]]$EventIds = @('4625', '4672', '4688', '4697'),

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxResults = 500,

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

$intIds = @($EventIds | ForEach-Object { [int]$_ })

$remoteScript = {
    param($Hours, $Max, $Ids, $UserFilter)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $evtLabels = @{
        4624 = 'Successful Logon'
        4625 = 'Failed Logon'
        4672 = 'Special Privileges Assigned'
        4688 = 'New Process Created'
        4697 = 'Service Installed in System'
    }

    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Ids; StartTime = $startTime } -MaxEvents $Max -ErrorAction Stop
        foreach ($ev in $evs) {
            $m = @{}
            try {
                $x = [xml]$ev.ToXml()
                foreach ($n in $x.Event.EventData.Data) {
                    if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
                }
            } catch {}

            $user = if ($m.ContainsKey('SubjectUserName') -and $m['SubjectUserName'] -and $m['SubjectUserName'] -ne '-') {
                "$($m['SubjectDomainName'])\$($m['SubjectUserName'])"
            } elseif ($m.ContainsKey('TargetUserName')) {
                "$($m['TargetDomainName'])\$($m['TargetUserName'])"
            } else { '' }

            if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and ($user -notlike "*$UserFilter*")) { continue }

            $targetObj = if ($m.ContainsKey('NewProcessName')) { $m['NewProcessName'] }
                         elseif ($m.ContainsKey('ServiceName')) { "$($m['ServiceName']) ($($m['ServiceFileName']))" }
                         elseif ($m.ContainsKey('IpAddress')) { $m['IpAddress'] -replace '^::ffff:', '' }
                         else { '' }

            $sev = switch ($ev.Id) { 4697 { 'Warning' } 4625 { 'Error' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                EventId     = $ev.Id
                EventType   = if ($evtLabels.ContainsKey([int]$ev.Id)) { $evtLabels[[int]$ev.Id] } else { "Event $($ev.Id)" }
                UserName    = $user
                ObjectName  = $targetObj
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $warns.Add("Security log query note (requires Administrator / Event Log Readers): $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); Warnings = $warns.ToArray() }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax, $intIds, $UserName)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $svcInstalls = @($rows | Where-Object { $_.EventId -eq 4697 }).Count
    $procCreates = @($rows | Where-Object { $_.EventId -eq 4688 }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventType';   label = 'Audit Type';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'Account';      type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ObjectName';  label = 'Process/Svc';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'audit_events';    label = 'Audit Events';       value = $rows.Count;  unit = 'events'; severity = 'info' }
        @{ key = 'new_services';    label = 'Svc Installs (4697)';value = $svcInstalls; unit = 'events'; severity = if ($svcInstalls -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'process_creates'; label = 'Proc Starts (4688)'; value = $procCreates; unit = 'events'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.6-security-auditing' -Category 'Security' -SubCategory 'Security Auditing' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.6-security-auditing' -Category 'Security' -SubCategory 'Security Auditing' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
