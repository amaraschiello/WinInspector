#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Storage Spaces pools, virtual disks, pool capacity/degradation, and StorageSpaces-Driver events.
.NOTES
    Category:  03-Storage / 3.3-Storage-Spaces
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/PowerShell/PrivateCloud.DiagnosticInfo
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
    $warns = New-Object System.Collections.Generic.List[string]

    $poolCount = 0
    $degradedPools = 0

    try {
        $pools = @(Get-StoragePool -IsPrimordial $false -ErrorAction Stop)
        $poolCount = $pools.Count
        foreach ($p in $pools) {
            $isBad = ($p.HealthStatus -ne 'Healthy')
            if ($isBad) { $degradedPools++ }
            $sev = if ($p.HealthStatus -eq 'Unhealthy') { 'Critical' } elseif ($isBad) { 'Warning' } else { 'Info' }
            $usedPct = if ($p.Size -gt 0) { [math]::Round(($p.AllocatedSize / $p.Size) * 100, 1) } else { 0 }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'Storage Pool'
                Name        = $p.FriendlyName
                Health      = "$($p.HealthStatus) / $($p.OperationalStatus)"
                EventId     = 0
                Summary     = "Pool '$($p.FriendlyName)': $($p.HealthStatus) | Allocated: $usedPct% ($([math]::Round($p.AllocatedSize/1GB,1))/$([math]::Round($p.Size/1GB,1)) GB)"
                RawMessage  = ($p | Format-List | Out-String)
            })
        }

        foreach ($vd in @(Get-VirtualDisk -ErrorAction SilentlyContinue)) {
            $isBad = ($vd.HealthStatus -ne 'Healthy')
            $sev = if ($vd.HealthStatus -eq 'Unhealthy') { 'Critical' } elseif ($isBad) { 'Warning' } else { 'Info' }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'Virtual Disk'
                Name        = $vd.FriendlyName
                Health      = "$($vd.HealthStatus) / $($vd.OperationalStatus)"
                EventId     = 0
                Summary     = "VirtualDisk '$($vd.FriendlyName)' ($($vd.ResiliencySettingName)): $($vd.HealthStatus) | Size: $([math]::Round($vd.Size/1GB,1)) GB"
                RawMessage  = ($vd | Format-List | Out-String)
            })
        }
    }
    catch {
        $warns.Add("Storage Spaces query note: $($_.Exception.Message)")
    }

    $spEvents = 0
    foreach ($logName in @('Microsoft-Windows-StorageSpaces-Driver/Operational', 'Microsoft-Windows-StorageSpaces-SpaceManager/Operational')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $spEvents++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'StorageSpaces Event'
                    Name        = $ev.ProviderName
                    Health      = $sev
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows          = @($out.ToArray() | Select-Object -First $Max)
        PoolCount     = $poolCount
        DegradedPools = $degradedPools
        SpEvents      = $spEvents
        Warnings      = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';        label = 'Pool/Disk';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Health';      label = 'Health';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'storage_pools';  label = 'Storage Pools';  value = $res.Data.PoolCount;     unit = 'pools';  severity = 'info' }
        @{ key = 'degraded_pools'; label = 'Degraded Pools'; value = $res.Data.DegradedPools; unit = 'pools';  severity = if ($res.Data.DegradedPools -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'spaces_events';  label = 'Driver Events';  value = $res.Data.SpEvents;      unit = 'events'; severity = if ($res.Data.SpEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '3.3-storage-spaces' -Category 'Storage' -SubCategory 'Storage Spaces' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '3.3-storage-spaces' -Category 'Storage' -SubCategory 'Storage Spaces' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
