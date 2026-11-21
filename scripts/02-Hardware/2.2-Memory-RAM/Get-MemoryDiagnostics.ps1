#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Physical RAM DIMMs, Commit Limit / Paging File usage, Resource Exhaustion Detector (2004), and MemoryDiagnostics events.
.NOTES
    Category:  02-Hardware / 2.2-Memory-RAM
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

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $totalMemGB = if ($os) { [math]::Round($os.TotalVisibleMemorySize / 1MB, 2) } else { 0 }
    $freeMemGB  = if ($os) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
    $usedPct    = if ($totalMemGB -gt 0) { [math]::Round((($totalMemGB - $freeMemGB) / $totalMemGB) * 100, 1) } else { 0 }
    $commitPct  = 0

    try {
        $c = Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction Stop
        $commitPct = [math]::Round($c.CounterSamples[0].CookedValue, 1)
    } catch {}

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($usedPct -ge 92 -or $commitPct -ge 90) { 'Critical' } elseif ($usedPct -ge 80 -or $commitPct -ge 80) { 'Warning' } else { 'Info' }
        RecordType  = 'Memory Summary'
        EventId     = 0
        Source      = 'OS Memory'
        CapacityGB  = $totalMemGB
        Summary     = "RAM Used: $usedPct% ($freeMemGB GB free of $totalMemGB GB) | Commit Used: $commitPct%"
        RawMessage  = "TotalVisibleGB: $totalMemGB`nFreePhysicalGB: $freeMemGB`nUsedPct: $usedPct%`nCommitUsedPct: $commitPct%`nTotalVirtualGB: $([math]::Round($os.TotalVirtualMemorySize / 1MB, 2))"
    })

    # Pagefile usage
    foreach ($pf in (Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue)) {
        $pfPct = if ($pf.AllocatedBaseSize -gt 0) { [math]::Round(($pf.CurrentUsage / $pf.AllocatedBaseSize) * 100, 1) } else { 0 }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($pfPct -ge 85) { 'Warning' } else { 'Info' }
            RecordType  = 'Page File'
            EventId     = 0
            Source      = $pf.Name
            CapacityGB  = [math]::Round($pf.AllocatedBaseSize / 1024, 2)
            Summary     = "PageFile '$($pf.Name)': $($pf.CurrentUsage) / $($pf.AllocatedBaseSize) MB ($pfPct% used, Peak $($pf.PeakUsage) MB)"
            RawMessage  = ($pf | Format-List | Out-String)
        })
    }

    # Physical DIMMs
    foreach ($dimm in (Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue)) {
        $capGB = [math]::Round($dimm.Capacity / 1GB, 1)
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Info'
            RecordType  = 'Physical DIMM'
            EventId     = 0
            Source      = $dimm.DeviceLocator
            CapacityGB  = $capGB
            Summary     = "$($dimm.DeviceLocator): $capGB GB @ $($dimm.Speed) MHz ($($dimm.Manufacturer))"
            RawMessage  = ($dimm | Select-Object DeviceLocator, BankLabel, Capacity, Speed, Manufacturer, PartNumber | Format-List | Out-String)
        })
    }

    # Resource Exhaustion & Memory Diagnostics Events
    $exhaustCount = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-Resource-Exhaustion-Detector', 'Microsoft-Windows-MemoryDiagnostics-Results')
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        if ($ev.Id -eq 2004) { $exhaustCount++ }
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Memory Event'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            CapacityGB  = 0
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        UsedPct      = $usedPct
        CommitPct    = $commitPct
        ExhaustCount = $exhaustCount
    }
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
        @{ key = 'Source';      label = 'Source/Slot';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'CapacityGB';  label = 'Size (GB)';    type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'ram_used_pct';    label = 'RAM Used';            value = $res.Data.UsedPct;      unit = '%';      severity = if ($res.Data.UsedPct -ge 90) { 'critical' } elseif ($res.Data.UsedPct -ge 80) { 'warning' } else { 'ok' } }
        @{ key = 'commit_used_pct'; label = 'Commit Used';         value = $res.Data.CommitPct;    unit = '%';      severity = if ($res.Data.CommitPct -ge 90) { 'critical' } elseif ($res.Data.CommitPct -ge 80) { 'warning' } else { 'ok' } }
        @{ key = 'exhaust_events';  label = 'Exhaustion (2004)';   value = $res.Data.ExhaustCount; unit = 'events'; severity = if ($res.Data.ExhaustCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.2-memory-ram' -Category 'Hardware' -SubCategory 'Memory (RAM)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.2-memory-ram' -Category 'Hardware' -SubCategory 'Memory (RAM)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
