#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Microsoft-Windows-NTLM/Operational (8001-8004) and Security (4776) for legacy NTLM authentication & pass-through failures.
.NOTES
    Category:  05-ActiveDirectory-Auth / 5.3-NTLM
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/BetaHydri/Get-NtlmLogonEvents
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
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 300,

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
    param($Hours, $UserFilter, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; StartTime = $startTime } -MaxEvents $Max -ErrorAction Stop
        foreach ($ev in $evs) {
            $m = @{}
            try {
                $x = [xml]$ev.ToXml()
                foreach ($n in $x.Event.EventData.Data) {
                    if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
                }
            } catch {}

            $user = if ($m.ContainsKey('UserName')) { $m['UserName'] } elseif ($m.ContainsKey('TargetName')) { $m['TargetName'] } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and ($user -notlike "*$UserFilter*")) { continue }

            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated  = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity     = $sev
                LogName      = 'NTLM Operational'
                EventId      = $ev.Id
                UserName     = $user
                ClientHost   = [string]$m['WorkstationName']
                TargetServer = [string]$m['TargetName']
                ProcessName  = [string]$m['ProcessName']
                Summary      = ($msg -split "`r?`n")[0]
                RawMessage   = $msg
            })
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $warns.Add("Microsoft-Windows-NTLM/Operational note (ensure NTLM auditing GPO is enabled for 8001-8004): $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); Warnings = $warns.ToArray() }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $UserName, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated';  label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';     label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';      label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';     label = 'User';          type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientHost';   label = 'Client Host';   type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'TargetServer'; label = 'Target Server'; type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProcessName';  label = 'Process';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';      label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';   label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'ntlm_events';  label = 'NTLM Operational Events'; value = $rows.Count; unit = 'events'; severity = 'info' }
        @{ key = 'ntlm_clients'; label = 'Unique Client Hosts';     value = @($rows | Where-Object { $_.ClientHost } | Select-Object -ExpandProperty ClientHost -Unique).Count; unit = 'hosts'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '5.3-ntlm' -Category 'Active Directory & Authentication' -SubCategory 'NTLM' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '5.3-ntlm' -Category 'Active Directory & Authentication' -SubCategory 'NTLM' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
