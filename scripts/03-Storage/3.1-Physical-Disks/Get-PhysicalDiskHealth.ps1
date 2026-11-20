#Requires -Version 5.1
<#
.SYNOPSIS
    Audits physical disks, storage reliability/SMART counters, and Disk/StorPort/StorAHCI System events.
.NOTES
    Category:  03-Storage / 3.1-Physical-Disks
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
    $unhealthyDisks = 0
    $diskCount = 0

    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $disks) {
            $diskCount++
            $rel = $null
            try { $rel = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue } catch {}
            $isUnhealthy = ($d.HealthStatus -ne 'Healthy') -or ($rel -and ($rel.ReadErrorsUncorrected -gt 0 -or $rel.WriteErrorsUncorrected -gt 0))
            if ($isUnhealthy) { $unhealthyDisks++ }

            $sev = if ($d.HealthStatus -eq 'Unhealthy') { 'Critical' } elseif ($isUnhealthy) { 'Warning' } else { 'Info' }
            $temp = if ($rel -and $null -ne $rel.Temperature) { "$($rel.Temperature)C" } else { 'N/A' }
            $wear = if ($rel -and $null -ne $rel.Wear) { "$($rel.Wear)%" } else { 'N/A' }
            $readErr = if ($rel -and $null -ne $rel.ReadErrorsTotal) { $rel.ReadErrorsTotal } else { 0 }

            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'Physical Disk'
                DiskName    = "Disk $($d.DeviceId): $($d.FriendlyName)"
                MediaType   = "$($d.MediaType) ($($d.BusType))"
                HealthState = "$($d.HealthStatus) / $($d.OperationalStatus)"
                EventId     = 0
                Summary     = "Size: $([math]::Round($d.Size / 1GB, 1)) GB | Temp: $temp | Wear: $wear | ReadErrors: $readErr"
                RawMessage  = ($d | Select-Object DeviceId, FriendlyName, SerialNumber, MediaType, BusType, HealthStatus, OperationalStatus, Size | Format-List | Out-String)
            })
        }
    }
    catch {
        # Fallback to Win32_DiskDrive if Storage module unavailable
        foreach ($d in (Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue)) {
            $diskCount++
            $sev = if ($d.Status -ne 'OK') { 'Warning' } else { 'Info' }
            if ($d.Status -ne 'OK') { $unhealthyDisks++ }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'Physical Disk'
                DiskName    = $d.Model
                MediaType   = $d.InterfaceType
                HealthState = $d.Status
                EventId     = 0
                Summary     = "Size: $([math]::Round($d.Size / 1GB, 1)) GB | Status: $($d.Status)"
                RawMessage  = ($d | Format-List | Out-String)
            })
        }
    }

    # Disk / StorPort / StorAHCI / NTFS disk error events
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Disk', 'storahci', 'stornvme', 'storport', 'partmgr', 'volmgr')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Storage Event'
            DiskName    = $ev.ProviderName
            MediaType   = 'EventLog'
            HealthState = $sev
            EventId     = $ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows           = @($out | Select-Object -First $Max)
        DiskCount      = $diskCount
        UnhealthyDisks = $unhealthyDisks
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)
    $storageEvCount = @($rows | Where-Object { $_.RecordType -eq 'Storage Event' }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';   type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';    type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DiskName';    label = 'Disk/Source'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'MediaType';   label = 'Bus/Media';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'HealthState'; label = 'Health';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';    type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'physical_disks';  label = 'Physical Disks';   value = $res.Data.DiskCount;      unit = 'disks';  severity = 'info' }
        @{ key = 'unhealthy_disks'; label = 'Unhealthy Disks';  value = $res.Data.UnhealthyDisks; unit = 'disks';  severity = if ($res.Data.UnhealthyDisks -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'storage_errors';  label = 'Disk I/O Events';  value = $storageEvCount;          unit = 'events'; severity = if ($storageEvCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '3.1-physical-disks' -Category 'Storage' -SubCategory 'Physical Disks' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '3.1-physical-disks' -Category 'Storage' -SubCategory 'Physical Disks' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
