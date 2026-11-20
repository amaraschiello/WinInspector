#Requires -Version 5.1
<#
.SYNOPSIS
    Analyzes OS stability: BugChecks/BSODs (1001), Application/Service crashes (1000/1002),
    memory dump inventory, and Windows Reliability Monitor records.
.NOTES
    Category:  01-OperatingSystem-Core / 1.3-OS-Stability
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
    [int]$MaxResults = 300
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

    # 1. BugChecks (System Event ID 1001 from BugCheck / WER-SystemErrorReporting)
    $bugChecks = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; StartTime = $startTime } -MaxEvents 100 -ErrorAction SilentlyContinue
    foreach ($ev in $bugChecks) {
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = 'Critical'
            IssueType   = 'BSOD / BugCheck'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            ProcessName = 'Kernel'
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    # 2. Application Crashes & Hangs (1000, 1002)
    $appCrashes = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = @(1000, 1002); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $appCrashes) {
        $appName = ''
        try {
            $x = [xml]$ev.ToXml()
            $firstData = $x.Event.EventData.Data | Select-Object -First 1
            if ($firstData) {
                $appName = if ($firstData -is [System.Xml.XmlElement]) { $firstData.InnerText } else { [string]$firstData }
            }
        } catch {}
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = if ($ev.Id -eq 1000) { 'Error' } else { 'Warning' }
            IssueType   = if ($ev.Id -eq 1000) { 'Application Crash' } else { 'Application Hang' }
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            ProcessName = $appName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    # 3. Check for Minidump / Full Memory.dmp files
    $dumpCount = 0
    $minidumpDir = Join-Path $env:SystemRoot 'Minidump'
    if (Test-Path -LiteralPath $minidumpDir) {
        $dumps = Get-ChildItem -LiteralPath $minidumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $startTime }
        foreach ($d in $dumps) {
            $dumpCount++
            $out.Add([PSCustomObject]@{
                TimeCreated = $d.LastWriteTime.ToUniversalTime().ToString('o')
                Severity    = 'Critical'
                IssueType   = 'Memory Dump File'
                EventId     = 0
                Source      = 'CrashDump'
                ProcessName = $d.Name
                Summary     = "Minidump file found ($('{0:N2}' -f ($d.Length / 1MB)) MB) at $($d.FullName)"
                RawMessage  = "Path: $($d.FullName)`nSizeBytes: $($d.Length)`nLastWriteTimeUtc: $($d.LastWriteTimeUtc)"
            })
        }
    }

    # 4. Stability Index from Reliability Monitor
    $stabilityIndex = 'N/A'
    try {
        $rel = Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Sort-Object TimeGenerated -Descending | Select-Object -First 1
        if ($rel) { $stabilityIndex = [math]::Round($rel.SystemStabilityIndex, 2) }
    } catch {}

    return [PSCustomObject]@{
        Rows           = @($out | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        DumpCount      = $dumpCount
        StabilityIndex = $stabilityIndex
    }
}

$fallbackRpc = {
    param($Target, $Cred, $Proto, $Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $evParams = @{ ComputerName = $Target; FilterHashtable = @{ LogName = 'Application'; Id = @(1000, 1002); StartTime = $startTime }; MaxEvents = $Max; ErrorAction = 'SilentlyContinue' }
    if ($null -ne $Cred) { $evParams['Credential'] = $Cred }
    foreach ($ev in (Get-WinEvent @evParams)) {
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = if ($ev.Id -eq 1000) { 'Error' } else { 'Warning' }
            IssueType   = if ($ev.Id -eq 1000) { 'Application Crash' } else { 'Application Hang' }
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            ProcessName = ''
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }
    return [PSCustomObject]@{ Rows = $out.ToArray(); DumpCount = 0; StabilityIndex = 'N/A (RPC)' }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults) -FallbackScriptBlock $fallbackRpc
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $bsodCount  = @($rows | Where-Object { $_.IssueType -eq 'BSOD / BugCheck' }).Count
    $crashCount = @($rows | Where-Object { $_.IssueType -eq 'Application Crash' }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'IssueType';   label = 'Issue Type';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProcessName'; label = 'Process/File'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'stability_index'; label = 'Stability Index (0-10)'; value = $res.Data.StabilityIndex; unit = '';       severity = 'info' }
        @{ key = 'bsod_count';      label = 'BugChecks / BSODs';      value = $bsodCount;               unit = 'events'; severity = if ($bsodCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'app_crashes';     label = 'App Crashes (1000)';     value = $crashCount;              unit = 'events'; severity = if ($crashCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'minidumps';       label = 'Recent Minidumps';       value = $res.Data.DumpCount;      unit = 'files';  severity = if ($res.Data.DumpCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '1.3-os-stability' -Category 'Operating System & Core System' -SubCategory 'OS Stability' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '1.3-os-stability' -Category 'Operating System & Core System' -SubCategory 'OS Stability' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
