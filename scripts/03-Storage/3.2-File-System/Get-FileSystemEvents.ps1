#Requires -Version 5.1
<#
.SYNOPSIS
    Inspects Logical Volumes (capacity, free space %, health) and NTFS/ReFS/Chkdsk events.
.NOTES
    Category:  03-Storage / 3.2-File-System
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
Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $lowSpaceCount = 0

    $vols = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
    foreach ($v in $vols) {
        $sizeGB = if ($v.Size -gt 0) { [math]::Round($v.Size / 1GB, 2) } else { 0 }
        $freeGB = if ($v.FreeSpace -gt 0) { [math]::Round($v.FreeSpace / 1GB, 2) } else { 0 }
        $pctFree = if ($v.Size -gt 0) { [math]::Round(($v.FreeSpace / $v.Size) * 100, 1) } else { 0 }
        $sev = if ($pctFree -lt 10) { $lowSpaceCount++; 'Critical' } elseif ($pctFree -lt 20) { $lowSpaceCount++; 'Warning' } else { 'Info' }

        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Logical Volume'
            Volume      = "$($v.DeviceID) ($($v.VolumeName))"
            FileSystem  = $v.FileSystem
            EventId     = 0
            Source      = 'Win32_LogicalDisk'
            Summary     = "$freeGB GB free of $sizeGB GB ($pctFree% free)"
            RawMessage  = "Drive: $($v.DeviceID)`nLabel: $($v.VolumeName)`nFileSystem: $($v.FileSystem)`nTotalGB: $sizeGB`nFreeGB: $freeGB`nPercentFree: $pctFree%"
        })
    }

    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Ntfs', 'Microsoft-Windows-Ntfs', 'ReFS', 'Microsoft-Windows-ReFS', 'Chkdsk')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'FileSystem Event'
            Volume      = 'System Log'
            FileSystem  = $ev.ProviderName
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows          = @($out | Select-Object -First $Max)
        LowSpaceCount = $lowSpaceCount
        VolumeCount   = @($vols).Count
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)
    $fsEvents = @($rows | Where-Object { $_.RecordType -eq 'FileSystem Event' }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';   type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';    type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Volume';      label = 'Volume';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'FileSystem';  label = 'FS / Driver'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';    type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'volumes';          label = 'Fixed Volumes';      value = $res.Data.VolumeCount;   unit = 'vols';   severity = 'info' }
        @{ key = 'low_space_vols';   label = 'Low Space (<20%)';   value = $res.Data.LowSpaceCount; unit = 'vols';   severity = if ($res.Data.LowSpaceCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'fs_error_events';  label = 'NTFS / ReFS Events'; value = $fsEvents;               unit = 'events'; severity = if ($fsEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '3.2-file-system' -Category 'Storage' -SubCategory 'File System' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '3.2-file-system' -Category 'Storage' -SubCategory 'File System' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
