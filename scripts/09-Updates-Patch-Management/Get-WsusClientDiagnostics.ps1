#Requires -Version 5.1
<#
.SYNOPSIS
    Audits WSUS client policy settings, targeting group, last sync/detect timestamps, UpdateServices role (if WSUS server), and WindowsUpdate sync errors.
.NOTES
    Category:  09-Updates-Patch-Management / 9.2-WSUS
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
    [ValidateRange(1, 2160)]
    [int]$HoursBack = 168,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $wuPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $auPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    $results = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -ErrorAction SilentlyContinue

    $wsusUrl = if ($wuPol -and $wuPol.WUServer) { $wuPol.WUServer } else { 'Not Configured (Direct WU)' }
    $useWsus = if ($auPol -and $null -ne $auPol.UseWUServer) { [bool]$auPol.UseWUServer } else { $false }
    $targetGrp = if ($wuPol -and $wuPol.TargetGroup) { $wuPol.TargetGroup } else { '(Default)' }
    $lastDetect = if ($results -and $results.LastSuccessTime) { $results.LastSuccessTime } else { 'Unknown' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'WSUS Client Config'
        EventId     = 0
        Source      = 'Registry'
        Summary     = "UseWUServer=$useWsus | WUServer=$wsusUrl | TargetGroup=$targetGrp | LastDetect=$lastDetect"
        RawMessage  = ($wuPol | Format-List | Out-String) + "`n" + ($auPol | Format-List | Out-String) + "`nLastDetectSuccess: $lastDetect"
    })

    # If target is itself a WSUS server, check WsusService & UpdateServices logs
    $wsusSvc = Get-Service -Name WsusService -ErrorAction SilentlyContinue
    if ($wsusSvc) {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($wsusSvc.Status -eq 'Running') { 'Info' } else { 'Critical' }
            RecordType  = 'WSUS Server Role'
            EventId     = 0
            Source      = 'WsusService'
            Summary     = "Target hosts WSUS Server Role (WsusService: $($wsusSvc.Status))"
            RawMessage  = ($wsusSvc | Format-List | Out-String)
        })
    }

    $syncErrs = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
        Id        = @(20, 25, 26, 27, 31, 41)
        StartTime = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $syncErrs++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'WU/WSUS Event'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows       = @($out.ToArray() | Select-Object -First $Max)
        UseWsus    = $useWsus
        WsusUrl    = $wsusUrl
        LastDetect = $lastDetect
        SyncErrs   = $syncErrs
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
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
        @{ key = 'use_wsus';      label = 'WSUS Enabled';     value = if ($res.Data.UseWsus) { 'Yes' } else { 'No' }; unit = ''; severity = 'info' }
        @{ key = 'last_detect';   label = 'Last Detect';      value = $res.Data.LastDetect; unit = '';       severity = 'info' }
        @{ key = 'wsus_errors';   label = 'Sync/Det Errors';  value = $res.Data.SyncErrs;   unit = 'events'; severity = if ($res.Data.SyncErrs -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '9.2-wsus-client' -Category 'Updates & Patch Management' -SubCategory 'WSUS Client' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '9.2-wsus-client' -Category 'Updates & Patch Management' -SubCategory 'WSUS Client' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
