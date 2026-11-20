#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Windows Defender Application Control (WDAC) CodeIntegrity Operational events (3076, 3077, 3089, etc.).
.NOTES
    Category:  06-Security / 6.4-WDAC
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/HotCakeX/Harden-Windows-Security
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

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $umci = 'Unknown'
    $kmci = 'Unknown'
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $umci = switch ($dg.UsermodeCodeIntegrityPolicyEnforcementStatus) { 0 { 'Off' } 1 { 'Audit' } 2 { 'Enforced' } default { [string]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus } }
        $kmci = switch ($dg.CodeIntegrityPolicyEnforcementStatus) { 0 { 'Off' } 1 { 'Audit' } 2 { 'Enforced' } default { [string]$dg.CodeIntegrityPolicyEnforcementStatus } }
    } catch {}

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'WDAC Status'
        EventId     = 0
        FileName    = 'Win32_DeviceGuard'
        ProcessName = ''
        Summary     = "Kernel Code Integrity (KMCI): $kmci | User-Mode Code Integrity (UMCI): $umci"
        RawMessage  = "KMCI: $kmci`nUMCI: $umci"
    })

    $blockedCount = 0
    $auditCount   = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
        Id        = @(3076, 3077, 3033, 3034, 3067, 3068)
        StartTime = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $m = @{}
        try {
            $x = [xml]$ev.ToXml()
            foreach ($n in $x.Event.EventData.Data) {
                if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
            }
        } catch {}

        $isBlock = ($ev.Id -in @(3077, 3033, 3067))
        if ($isBlock) { $blockedCount++ } else { $auditCount++ }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = if ($isBlock) { 'Error' } else { 'Warning' }
            RecordType  = if ($isBlock) { 'CodeIntegrity Block' } else { 'CodeIntegrity Audit' }
            EventId     = $ev.Id
            FileName    = [string]$m['File Name']
            ProcessName = [string]$m['Process Name']
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        Kmci         = $kmci
        Umci         = $umci
        BlockedCount = $blockedCount
        AuditCount   = $auditCount
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Action';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'FileName';    label = 'Blocked File'; type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'ProcessName'; label = 'Process';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'wdac_kmci';    label = 'Kernel CI';     value = $res.Data.Kmci;         unit = '';       severity = 'info' }
        @{ key = 'wdac_umci';    label = 'User-Mode CI';  value = $res.Data.Umci;         unit = '';       severity = 'info' }
        @{ key = 'wdac_blocks';  label = 'CI Blocks';     value = $res.Data.BlockedCount; unit = 'events'; severity = if ($res.Data.BlockedCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'wdac_audits';  label = 'CI Audits';     value = $res.Data.AuditCount;   unit = 'events'; severity = if ($res.Data.AuditCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.4-wdac' -Category 'Security' -SubCategory 'WDAC (Code Integrity)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.4-wdac' -Category 'Security' -SubCategory 'WDAC (Code Integrity)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
