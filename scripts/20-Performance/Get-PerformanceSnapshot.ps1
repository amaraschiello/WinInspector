#Requires -Version 5.1
<#
.SYNOPSIS
    Captures a Performance Snapshot: CPU, Memory, Disk Latency/Queue, GPU Utilization/VRAM,
    Network Adapter Throughput & Receive/Outbound Packet Errors, and Top Processes.
.NOTES
    Category:  20-Performance / 20.1-Snapshot
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
    [ValidateRange(5, 100)]
    [int]$TopProcesses = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

try {
    $sampleScript = Join-Path $PSScriptRoot 'Get-LivePerformanceSample.ps1'
    $sampleParams = @{
        ComputerName = $ComputerName
        Protocol     = $Protocol
        TopProcesses = $TopProcesses
    }
    if ($null -ne $Credential) { $sampleParams['Credential'] = $Credential }

    $raw = & $sampleScript @sampleParams
    $sample = ($raw | Out-String) | ConvertFrom-Json
    foreach ($w in @($sample.warnings)) { $warnings.Add($w) }

    $rows = [System.Collections.Generic.List[object]]::new()
    $ts = $sample.tsUtc
    $sum = $sample.summary

    # System rows
    $rows.Add([PSCustomObject]@{
        TimeCreated = $ts
        Severity    = if ($sum.cpuPct -ge 90) { 'Critical' } elseif ($sum.cpuPct -ge 75) { 'Warning' } else { 'Info' }
        Subsystem   = 'CPU'
        Name        = 'Processor (_Total)'
        ProcessId   = 0
        MetricValue = $sum.cpuPct
        Unit        = '%'
        MemoryMB    = 0
        Summary     = "CPU Utilization: $($sum.cpuPct)%"
        RawMessage  = ($sum | Format-List | Out-String)
    })

    $rows.Add([PSCustomObject]@{
        TimeCreated = $ts
        Severity    = if ($sum.memUsedPct -ge 92) { 'Critical' } elseif ($sum.memUsedPct -ge 80) { 'Warning' } else { 'Info' }
        Subsystem   = 'Memory'
        Name        = 'Physical RAM'
        ProcessId   = 0
        MetricValue = $sum.memUsedPct
        Unit        = '%'
        MemoryMB    = $sum.memAvailMB
        Summary     = "RAM Used: $($sum.memUsedPct)% ($($sum.memAvailMB) MB available)"
        RawMessage  = ($sum | Format-List | Out-String)
    })

    $rows.Add([PSCustomObject]@{
        TimeCreated = $ts
        Severity    = if ($sum.diskReadMs -ge 25 -or $sum.diskQueue -ge 4) { 'Warning' } else { 'Info' }
        Subsystem   = 'Storage'
        Name        = 'PhysicalDisk (_Total)'
        ProcessId   = 0
        MetricValue = $sum.diskReadMs
        Unit        = 'ms'
        MemoryMB    = 0
        Summary     = "Disk Read: $($sum.diskReadMs) ms | Write: $($sum.diskWriteMs) ms | Queue: $($sum.diskQueue)"
        RawMessage  = ($sum | Format-List | Out-String)
    })

    $rows.Add([PSCustomObject]@{
        TimeCreated = $ts
        Severity    = if ($sum.gpuUtilPct -ge 90) { 'Warning' } else { 'Info' }
        Subsystem   = 'GPU'
        Name        = 'GPU Engine (_Total)'
        ProcessId   = 0
        MetricValue = $sum.gpuUtilPct
        Unit        = '%'
        MemoryMB    = $sum.gpuMemMB
        Summary     = "GPU Utilization: $($sum.gpuUtilPct)% | Dedicated VRAM Used: $($sum.gpuMemMB) MB"
        RawMessage  = ($sum | Format-List | Out-String)
    })

    foreach ($a in @($sample.adapters)) {
        $totErr = [long]$a.rxErrors + [long]$a.txErrors
        $rows.Add([PSCustomObject]@{
            TimeCreated = $ts
            Severity    = if ($totErr -gt 0) { 'Warning' } else { 'Info' }
            Subsystem   = 'Network Adapter'
            Name        = $a.adapterName
            ProcessId   = 0
            MetricValue = [math]::Round([double]$a.rxKbps + [double]$a.txKbps, 2)
            Unit        = 'KB/s'
            MemoryMB    = 0
            Summary     = "Rx: $($a.rxKbps) KB/s | Tx: $($a.txKbps) KB/s | RxErr: $($a.rxErrors) | TxErr: $($a.txErrors) | RxDisc: $($a.rxDiscards) | TxDisc: $($a.txDiscards)"
            RawMessage  = ($a | Format-List | Out-String)
        })
    }

    foreach ($p in @($sample.topProcesses)) {
        $rows.Add([PSCustomObject]@{
            TimeCreated = $ts
            Severity    = if ($p.cpuPct -ge 70 -or $p.memMB -ge 4096) { 'Warning' } else { 'Info' }
            Subsystem   = 'Top Process'
            Name        = $p.procName
            ProcessId   = $p.pid
            MetricValue = $p.cpuPct
            Unit        = '% CPU'
            MemoryMB    = $p.memMB
            Summary     = "$($p.procName) (PID $($p.pid)) | CPU: $($p.cpuPct)% ($($p.cpuSec)s) | RAM: $($p.memMB) MB | GPU: $($p.gpuPct)% ($($p.gpuMemMB) MB) | Handles: $($p.handles)"
            RawMessage  = ($p | Format-List | Out-String)
        })
    }

    $schema = @(
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Subsystem';   label = 'Subsystem';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';        label = 'Resource/Proc';type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProcessId';   label = 'PID';          type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'MetricValue'; label = 'Value';        type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Unit';        label = 'Unit';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'MemoryMB';    label = 'Memory (MB)';  type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $totalNetPktErr = [long]$sum.netRxErrors + [long]$sum.netTxErrors
    $metrics = @(
        @{ key = 'cpu_pct';       label = 'CPU Utilization';     value = $sum.cpuPct;     unit = '%';    severity = if ($sum.cpuPct -ge 90) { 'critical' } elseif ($sum.cpuPct -ge 75) { 'warning' } else { 'ok' } }
        @{ key = 'mem_used_pct';  label = 'RAM Used';            value = $sum.memUsedPct; unit = '%';    severity = if ($sum.memUsedPct -ge 92) { 'critical' } elseif ($sum.memUsedPct -ge 80) { 'warning' } else { 'ok' } }
        @{ key = 'gpu_util_pct';  label = 'GPU Utilization';     value = $sum.gpuUtilPct; unit = '%';    severity = if ($sum.gpuUtilPct -ge 90) { 'warning' } else { 'info' } }
        @{ key = 'net_pkt_errs';  label = 'Net Rx/Tx Errors';    value = $totalNetPktErr;  unit = 'pkts'; severity = if ($totalNetPktErr -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'disk_read_ms';  label = 'Disk Read Latency';   value = $sum.diskReadMs; unit = 'ms';   severity = if ($sum.diskReadMs -ge 25) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '20.1-performance-snapshot' -Category 'Performance' -SubCategory 'Live Resource Snapshot' -TargetServer $ComputerName -ProtocolUsed $sample.protocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows.ToArray() -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '20.1-performance-snapshot' -Category 'Performance' -SubCategory 'Live Resource Snapshot' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
