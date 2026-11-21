#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Display/GPU adapters, driver versions, and Display / DxgKrnl TDR (4101) crash/reset events.
.NOTES
    Category:  02-Hardware / 2.4-Graphics
    Protocols: WinRM, CIM-DCOM
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

    $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue)
    foreach ($g in $gpus) {
        $sev = if ($g.ConfigManagerErrorCode -ne 0) { 'Error' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Display Adapter'
            EventId     = 0
            Source      = $g.Name
            DriverVer   = $g.DriverVersion
            Summary     = "$($g.Name) | Status: $($g.Status) | Driver: $($g.DriverVersion) | Res: $($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)"
            RawMessage  = ($g | Select-Object Name, Status, DriverVersion, DriverDate, VideoProcessor, AdapterRAM, ConfigManagerErrorCode | Format-List | Out-String)
        })
    }

    $tdrCount = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Display', 'DxgKrnl', 'nvlddmkm', 'amdkmdag', 'igfx')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        if ($ev.Id -eq 4101) { $tdrCount++ }
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = if ($ev.Id -eq 4101) { 'TDR Reset (4101)' } else { 'Display Event' }
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            DriverVer   = ''
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{ Rows = @($out.ToArray() | Select-Object -First $Max); GpuCount = $gpus.Count; TdrCount = $tdrCount }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'GPU / Source'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DriverVer';   label = 'Driver Ver';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'gpu_count';  label = 'Display Adapters'; value = $res.Data.GpuCount; unit = 'GPUs';   severity = 'info' }
        @{ key = 'tdr_events'; label = 'TDR Events (4101)';value = $res.Data.TdrCount; unit = 'events'; severity = if ($res.Data.TdrCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.4-graphics' -Category 'Hardware' -SubCategory 'Graphics' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.4-graphics' -Category 'Hardware' -SubCategory 'Graphics' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
