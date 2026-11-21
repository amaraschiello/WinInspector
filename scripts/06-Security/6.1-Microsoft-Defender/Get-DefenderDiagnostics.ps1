#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Microsoft Defender Antivirus status (signatures, real-time protection, engine) and Operational threat/update/scan events.
.NOTES
    Category:  06-Security / 6.1-Microsoft-Defender
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
Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $rtEnabled = 'Unknown'
    $sigAgeDays = -1
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $rtEnabled = [string]$st.RealTimeProtectionEnabled
        $sigAgeDays = [int]$st.AntivirusSignatureAge
        $sev = if (-not $st.RealTimeProtectionEnabled -or $sigAgeDays -gt 7) { 'Warning' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Defender Status'
            EventId     = 0
            Source      = 'WinDefend'
            Summary     = "RealTime: $($st.RealTimeProtectionEnabled) | SigVer: $($st.AntivirusSignatureVersion) (Age: $sigAgeDays d) | Engine: $($st.AMEngineVersion)"
            RawMessage  = ($st | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureVersion, AntivirusSignatureAge, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime | Format-List | Out-String)
        })
    }
    catch {
        $warns.Add("Get-MpComputerStatus unavailable: $($_.Exception.Message)")
    }

    $threatCount = 0
    $errCount = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Windows Defender/Operational'
            StartTime = $startTime
        } -MaxEvents ($Max * 2) -ErrorAction SilentlyContinue

        foreach ($ev in $evs) {
            if ($ev.Id -in @(1006, 1007, 1008, 1116, 1117)) { $threatCount++ }
            if ($ev.Level -le 3 -or $ev.Id -in @(1006, 1007, 1008, 1116, 1117, 2001, 2003, 5001, 5007)) {
                if ($ev.Level -le 2) { $errCount++ }
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { if ($ev.Id -in @(1116, 1117)) { 'Critical' } else { 'Info' } } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'Defender Event'
                    EventId     = $ev.Id
                    Source      = $ev.ProviderName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
                if ($out.Count -ge $Max) { break }
            }
        }
    }
    catch {
        $warns.Add("Defender Operational log unavailable: $($_.Exception.Message)")
    }

    return [PSCustomObject]@{
        Rows        = @($out.ToArray() | Select-Object -First $Max)
        RtEnabled   = $rtEnabled
        SigAgeDays  = $sigAgeDays
        ThreatCount = $threatCount
        ErrCount    = $errCount
        Warnings    = $warns.ToArray()
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
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'defender_rtp';     label = 'Real-Time Prot';  value = $res.Data.RtEnabled;  unit = '';       severity = if ($res.Data.RtEnabled -eq 'True') { 'ok' } else { 'warning' } }
        @{ key = 'defender_sig_age'; label = 'Signature Age';   value = $res.Data.SigAgeDays; unit = 'days';   severity = if ($res.Data.SigAgeDays -gt 7) { 'warning' } else { 'ok' } }
        @{ key = 'defender_threats'; label = 'Threat Detections';value = $res.Data.ThreatCount;unit = 'events'; severity = if ($res.Data.ThreatCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.1-microsoft-defender' -Category 'Security' -SubCategory 'Microsoft Defender' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.1-microsoft-defender' -Category 'Security' -SubCategory 'Microsoft Defender' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
