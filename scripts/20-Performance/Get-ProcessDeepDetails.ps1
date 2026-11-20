#Requires -Version 5.1
<#
.SYNOPSIS
    Collects deep live diagnostics for a specific process (CPU, RAM, Private Bytes, GPU/VRAM,
    Disk & I/O rate counters, CommandLine, Owner, Open TCP/UDP Sockets, and Loaded Modules).
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
    [int]$ProcessId = 0,

    [Parameter()]
    [string]$ProcessName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

if ($ProcessId -le 0 -and [string]::IsNullOrWhiteSpace($ProcessName)) {
    throw "Either ProcessId or ProcessName is required."
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

$remoteScript = {
    param($TargetPid, $TargetName)

    $proc = $null
    if ($TargetPid -gt 0) {
        $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    }
    if ($null -eq $proc -and -not [string]::IsNullOrWhiteSpace($TargetName)) {
        $cleanName = $TargetName -replace '\.exe$', ''
        $proc = Get-Process -Name $cleanName -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
    }
    if ($null -eq $proc) {
        throw "Process not found (PID=$TargetPid, Name='$TargetName'). It may have exited."
    }

    $pidVal = [int]$proc.Id
    $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$pidVal" -ErrorAction SilentlyContinue
    $owner = ''
    if ($wmiProc) {
        try {
            $ownRes = Invoke-CimMethod -InputObject $wmiProc -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($ownRes -and $ownRes.ReturnValue -eq 0 -and $ownRes.User) {
                $owner = if ($ownRes.Domain) { "$($ownRes.Domain)\$($ownRes.User)" } else { [string]$ownRes.User }
            }
        } catch {}
    }

    # Live I/O & Memory performance counters for this PID
    $ioPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -Filter "IDProcess=$pidVal" -ErrorAction SilentlyContinue | Select-Object -First 1
    $cpuCount = [Math]::Max(1, [Environment]::ProcessorCount)
    $cpuPct = if ($ioPerf) { [math]::Round([double]$ioPerf.PercentProcessorTime / $cpuCount, 2) } else { 0 }

    # GPU utilization & VRAM for this PID
    $gpuPct = 0.0
    $gpuDedMB = 0.0
    $gpuSharedMB = 0.0
    try {
        $gpuMem = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -Filter "Name LIKE 'pid_${pidVal}_%'" -ErrorAction SilentlyContinue
        foreach ($gm in @($gpuMem)) {
            $gpuDedMB += [double]$gm.DedicatedUsage / 1MB
            $gpuSharedMB += [double]$gm.SharedUsage / 1MB
        }
        $gpuEng = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -Filter "Name LIKE 'pid_${pidVal}_%'" -ErrorAction SilentlyContinue
        foreach ($ge in @($gpuEng)) {
            $gpuPct += [double]$ge.UtilizationPercentage
        }
    } catch {}

    # Active TCP/UDP connections owned by this PID
    $sockets = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($t in @(Get-NetTCPConnection -OwningProcess $pidVal -ErrorAction SilentlyContinue | Select-Object -First 100)) {
            $sockets.Add([PSCustomObject]@{
                Protocol      = 'TCP'
                LocalAddress  = $t.LocalAddress
                LocalPort     = [int]$t.LocalPort
                RemoteAddress = $t.RemoteAddress
                RemotePort    = [int]$t.RemotePort
                State         = [string]$t.State
            })
        }
        foreach ($u in @(Get-NetUDPEndpoint -OwningProcess $pidVal -ErrorAction SilentlyContinue | Select-Object -First 50)) {
            $sockets.Add([PSCustomObject]@{
                Protocol      = 'UDP'
                LocalAddress  = $u.LocalAddress
                LocalPort     = [int]$u.LocalPort
                RemoteAddress = '*'
                RemotePort    = 0
                State         = 'Bound'
            })
        }
    } catch {}

    # Loaded modules (top 30)
    $modules = [System.Collections.Generic.List[object]]::new()
    $totalModules = 0
    try {
        $mods = @($proc.Modules)
        $totalModules = $mods.Count
        foreach ($m in ($mods | Select-Object -First 30)) {
            $modules.Add([PSCustomObject]@{
                Name    = $m.ModuleName
                SizeKB  = [math]::Round([double]$m.ModuleMemorySize / 1KB, 1)
                Version = if ($m.FileVersionInfo) { [string]$m.FileVersionInfo.FileVersion } else { '' }
                Path    = $m.FileName
            })
        }
    } catch {}

    $exePath = ''
    try { $exePath = [string]$proc.Path } catch {}
    if (-not $exePath -and $wmiProc) { $exePath = [string]$wmiProc.ExecutablePath }

    $startUtc = ''
    try { $startUtc = $proc.StartTime.ToUniversalTime().ToString('o') } catch {
        if ($wmiProc -and $wmiProc.CreationDate) {
            try { $startUtc = ([datetime]$wmiProc.CreationDate).ToUniversalTime().ToString('o') } catch {}
        }
    }

    $readBps  = if ($ioPerf) { [math]::Round([double]$ioPerf.IOReadBytesPersec / 1KB, 2) } else { 0 }
    $writeBps = if ($ioPerf) { [math]::Round([double]$ioPerf.IOWriteBytesPersec / 1KB, 2) } else { 0 }
    $otherBps = if ($ioPerf) { [math]::Round([double]$ioPerf.IOOtherBytesPersec / 1KB, 2) } else { 0 }

    return [PSCustomObject]@{
        pid              = $pidVal
        parentPid        = if ($wmiProc) { [int]$wmiProc.ParentProcessId } else { 0 }
        processName      = $proc.ProcessName
        owner            = $owner
        executablePath   = $exePath
        commandLine      = if ($wmiProc) { [string]$wmiProc.CommandLine } else { '' }
        startTimeUtc     = $startUtc
        priorityClass    = $(try { [string]$proc.PriorityClass } catch { '' })
        cpuPct           = $cpuPct
        cpuSec           = $(try { [math]::Round([double]$proc.CPU, 2) } catch { 0 })
        workingSetMB     = [math]::Round([double]$proc.WorkingSet64 / 1MB, 2)
        privateMB        = [math]::Round([double]$proc.PrivateMemorySize64 / 1MB, 2)
        virtualMB        = [math]::Round([double]$proc.VirtualMemorySize64 / 1MB, 2)
        pagedPoolKB      = if ($ioPerf) { [math]::Round([double]$ioPerf.PoolPagedBytes / 1KB, 1) } else { [math]::Round([double]$proc.PagedSystemMemorySize64 / 1KB, 1) }
        nonPagedPoolKB   = if ($ioPerf) { [math]::Round([double]$ioPerf.PoolNonpagedBytes / 1KB, 1) } else { [math]::Round([double]$proc.NonpagedSystemMemorySize64 / 1KB, 1) }
        pageFaultsPerSec = if ($ioPerf) { [math]::Round([double]$ioPerf.PageFaultsPersec, 1) } else { 0 }
        gpuPct           = [math]::Round([Math]::Min(100, $gpuPct), 2)
        gpuDedicatedMB   = [math]::Round($gpuDedMB, 2)
        gpuSharedMB      = [math]::Round($gpuSharedMB, 2)
        ioReadOpsPerSec  = if ($ioPerf) { [math]::Round([double]$ioPerf.IOReadOperationsPersec, 1) } else { 0 }
        ioWriteOpsPerSec = if ($ioPerf) { [math]::Round([double]$ioPerf.IOWriteOperationsPersec, 1) } else { 0 }
        ioReadKBps       = $readBps
        ioWriteKBps      = $writeBps
        ioOtherKBps      = $otherBps
        totalReadMB      = if ($wmiProc) { [math]::Round([double]$wmiProc.ReadTransferCount / 1MB, 2) } else { 0 }
        totalWriteMB     = if ($wmiProc) { [math]::Round([double]$wmiProc.WriteTransferCount / 1MB, 2) } else { 0 }
        handles          = [int]$proc.HandleCount
        threads          = $proc.Threads.Count
        sockets          = $sockets.ToArray()
        totalModules     = $totalModules
        modules          = $modules.ToArray()
    }
}

$res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($ProcessId, $ProcessName)
$sw.Stop()

[ordered]@{
    ok           = $true
    targetServer = $ComputerName
    protocolUsed = $res.ProtocolUsed
    executedAs   = $res.ExecutedAs
    durationMs   = $sw.ElapsedMilliseconds
    details      = $res.Data
} | ConvertTo-Json -Depth 6 -Compress
