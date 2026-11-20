#Requires -Version 5.1
<#
.SYNOPSIS
    Captures a single lightweight, high-speed performance, GPU, network packet-error,
    top-process, open-connection, SMB-file, and named-pipe sample for SQLite persistence.
.NOTES
    Category:  20-Performance / 20.2-Live-Monitor
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
    [ValidateRange(5, 50)]
    [int]$TopProcesses = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($TopN)
    $nowIso = (Get-Date).ToUniversalTime().ToString('o')
    $warns = New-Object System.Collections.Generic.List[string]

    # 1. OS & CPU
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $totalMemMB = if ($os) { [math]::Round($os.TotalVisibleMemorySize / 1024.0, 1) } else { 0 }
    $availMemMB = if ($os) { [math]::Round($os.FreePhysicalMemory / 1024.0, 1) } else { 0 }
    $usedMemPct = if ($totalMemMB -gt 0) { [math]::Round((($totalMemMB - $availMemMB) / $totalMemMB) * 100.0, 1) } else { 0 }

    $cpuPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $cpuPct  = if ($cpuPerf) { [math]::Round([double]$cpuPerf.PercentProcessorTime, 1) } else {
        $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
        if ($cpus.Count -gt 0) { [math]::Round(($cpus | Measure-Object LoadPercentage -Average).Average, 1) } else { 0 }
    }

    $logicalProcs = [int]$env:NUMBER_OF_PROCESSORS
    if ($logicalProcs -le 0) { $logicalProcs = 1 }

    # 2. Disk Latency & Queue Length
    $diskPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $diskReadMs  = if ($diskPerf) { [math]::Round(([double]$diskPerf.AvgDiskSecPerRead) * 1000.0, 2) } else { 0 }
    $diskWriteMs = if ($diskPerf) { [math]::Round(([double]$diskPerf.AvgDiskSecPerWrite) * 1000.0, 2) } else { 0 }
    $diskQueue   = if ($diskPerf) { [math]::Round([double]$diskPerf.CurrentDiskQueueLength, 2) } else { 0 }

    # 3. GPU Utilization & VRAM (native Win32_PerfFormattedData_GPUPerformanceCounters_*)
    $gpuUtilPct = 0.0
    $gpuMemMB   = 0.0
    $gpuPidUtil = @{}
    $gpuPidMem  = @{}

    try {
        $gpuEngines = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -Filter "UtilizationPercentage > 0" -ErrorAction Stop)
        foreach ($ge in $gpuEngines) {
            $u = [double]$ge.UtilizationPercentage
            $gpuUtilPct += $u
            if ($ge.Name -match 'pid_(\d+)_') {
                $gpid = [int]$Matches[1]
                if (-not $gpuPidUtil.ContainsKey($gpid)) { $gpuPidUtil[$gpid] = 0.0 }
                $gpuPidUtil[$gpid] += $u
            }
        }
        if ($gpuUtilPct -gt 100) { $gpuUtilPct = 100.0 }
        $gpuUtilPct = [math]::Round($gpuUtilPct, 1)
    } catch {}

    try {
        $gpuAdapters = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction Stop)
        foreach ($ga in $gpuAdapters) {
            $gpuMemMB += ([double]$ga.DedicatedUsage / 1MB)
        }
        $gpuMemMB = [math]::Round($gpuMemMB, 1)

        $gpuProcs = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -Filter "DedicatedUsage > 0" -ErrorAction SilentlyContinue)
        foreach ($gp in $gpuProcs) {
            if ($gp.Name -match 'pid_(\d+)_') {
                $gpid = [int]$Matches[1]
                $mb = [math]::Round(([double]$gp.DedicatedUsage / 1MB), 1)
                if (-not $gpuPidMem.ContainsKey($gpid)) { $gpuPidMem[$gpid] = 0.0 }
                $gpuPidMem[$gpid] += $mb
            }
        }
    } catch {}

    # 4. Network Adapters: Get-NetAdapterStatistics + PerfFormattedData_Tcpip_NetworkInterface
    $perfNetMap = @{}
    foreach ($np in @(Get-CimInstance -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue)) {
        $normKey = ($np.Name -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
        $perfNetMap[$normKey] = $np
    }

    $speedMap = @{}
    foreach ($na in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
        if ($na.PSObject.Properties['LinkSpeed'] -and $na.LinkSpeed) {
            $speedMap[$na.Name] = [string]$na.LinkSpeed
        }
        elseif ($na.PSObject.Properties['TransmitLinkSpeed'] -and $na.TransmitLinkSpeed) {
            $bps = [double]$na.TransmitLinkSpeed
            $speedMap[$na.Name] = if ($bps -ge 1e9) { "$([math]::Round($bps / 1e9, 2)) Gbps" } elseif ($bps -ge 1e6) { "$([math]::Round($bps / 1e6, 0)) Mbps" } else { "$bps bps" }
        }
        else {
            $speedMap[$na.Name] = ''
        }
    }

    $adapterRows = New-Object System.Collections.Generic.List[object]
    $totRxKbps = 0.0; $totTxKbps = 0.0
    $totRxErr = 0L; $totTxErr = 0L; $totRxDisc = 0L; $totTxDisc = 0L

    foreach ($ns in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) {
        $normDesc = ($ns.InterfaceDescription -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
        $npMatch = $null
        if ($perfNetMap.ContainsKey($normDesc)) {
            $npMatch = $perfNetMap[$normDesc]
        }
        else {
            foreach ($k in $perfNetMap.Keys) {
                if ($k -like "*$normDesc*" -or $normDesc -like "*$k*") { $npMatch = $perfNetMap[$k]; break }
            }
        }

        $rxKbps = if ($npMatch) { [math]::Round([double]$npMatch.BytesReceivedPersec / 1024.0, 2) } else { 0.0 }
        $txKbps = if ($npMatch) { [math]::Round([double]$npMatch.BytesSentPersec / 1024.0, 2) } else { 0.0 }
        $rxErr  = [long]$ns.ReceivedPacketErrors
        $txErr  = [long]$ns.OutboundPacketErrors
        $rxDisc = [long]$ns.ReceivedDiscardedPackets
        $txDisc = [long]$ns.OutboundDiscardedPackets

        $totRxKbps += $rxKbps; $totTxKbps += $txKbps
        $totRxErr  += $rxErr;  $totTxErr  += $txErr
        $totRxDisc += $rxDisc; $totTxDisc += $txDisc

        $adapterRows.Add([PSCustomObject]@{
            adapterName = $ns.Name
            linkSpeed   = if ($speedMap.ContainsKey($ns.Name)) { [string]$speedMap[$ns.Name] } else { '' }
            rxKbps      = $rxKbps
            txKbps      = $txKbps
            rxErrors    = $rxErr
            txErrors    = $txErr
            rxDiscards  = $rxDisc
            txDiscards  = $txDisc
        })
    }

    # 5. Top Processes (CPU%, RAM MB, GPU%, GPU MB)
    $procCpuByPid = @{}
    foreach ($pp in @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -Filter "PercentProcessorTime > 0" -ErrorAction SilentlyContinue)) {
        if ($pp.Name -in @('_Total', 'Idle')) { continue }
        $procCpuByPid[[int]$pp.IDProcess] = [math]::Round(([double]$pp.PercentProcessorTime / $logicalProcs), 1)
    }

    $procNameMap = @{}
    $allProcs = @(Get-Process -ErrorAction SilentlyContinue)
    foreach ($p in $allProcs) { $procNameMap[$p.Id] = $p.ProcessName }

    $topProcObjects = $allProcs | ForEach-Object {
        $pidVal = [int]$_.Id
        $cPct = if ($procCpuByPid.ContainsKey($pidVal)) { $procCpuByPid[$pidVal] } else { 0.0 }
        $gPct = if ($gpuPidUtil.ContainsKey($pidVal)) { [math]::Round([math]::Min(100.0, $gpuPidUtil[$pidVal]), 1) } else { 0.0 }
        $gMem = if ($gpuPidMem.ContainsKey($pidVal)) { [math]::Round($gpuPidMem[$pidVal], 1) } else { 0.0 }
        [PSCustomObject]@{
            procName = $_.ProcessName
            pid      = $pidVal
            cpuPct   = $cPct
            cpuSec   = if ($null -ne $_.CPU) { [math]::Round($_.CPU, 1) } else { 0.0 }
            memMB    = [math]::Round($_.WorkingSet64 / 1MB, 1)
            gpuPct   = $gPct
            gpuMemMB = $gMem
            handles  = [int]$_.HandleCount
            threads  = [int]$_.Threads.Count
        }
    } | Sort-Object -Property @(
        @{ Expression = 'cpuPct'; Descending = $true },
        @{ Expression = 'gpuPct'; Descending = $true },
        @{ Expression = 'memMB';  Descending = $true }
    ) | Select-Object -First $TopN

    # 6. Open Network Connections (TCP/UDP), Service Mapping, SMB Open Files & Named Pipes (SQL, RPC, etc.)
    $portServiceMap = @{
        21   = 'FTP';          22   = 'SSH';          25   = 'SMTP';        53   = 'DNS'
        80   = 'HTTP/IIS';     88   = 'Kerberos';     123  = 'NTP';         135  = 'RPC'
        139  = 'NetBIOS';      389  = 'LDAP';         443  = 'HTTPS/IIS';   445  = 'SMB'
        636  = 'LDAPS';        1433 = 'SQL Server';   1434 = 'SQL Browser'; 3268 = 'AD GC'
        3389 = 'RDP';          5985 = 'WinRM HTTP';   5986 = 'WinRM HTTPS'; 8085 = 'WinInspector'
        9389 = 'ADWS'
    }

    $netDetails = New-Object System.Collections.Generic.List[object]
    $tcpEstabCount = 0

    $tcpConns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    foreach ($c in $tcpConns) {
        if ($c.State -eq 'Established') { $tcpEstabCount++ }
        if ($c.State -notin @('Established', 'Listen', 'CloseWait')) { continue }
        $lp = [int]$c.LocalPort
        $rp = [int]$c.RemotePort
        $svc = if ($portServiceMap.ContainsKey($lp)) { $portServiceMap[$lp] }
               elseif ($portServiceMap.ContainsKey($rp)) { $portServiceMap[$rp] }
               else { 'Other TCP' }
        $pName = if ($procNameMap.ContainsKey([int]$c.OwningProcess)) { $procNameMap[[int]$c.OwningProcess] } else { "PID $($c.OwningProcess)" }
        $clientIp = if ($c.RemoteAddress -and $c.RemoteAddress -notin @('0.0.0.0', '::')) { $c.RemoteAddress } else { $c.LocalAddress }

        $netDetails.Add([PSCustomObject]@{
            detailType   = 'TCP Connection'
            protocol     = 'TCP'
            serviceName  = $svc
            clientIp     = $clientIp
            localPort    = $lp
            remotePort   = $rp
            userName     = ''
            processName  = $pName
            resourcePath = "$($c.LocalAddress):$lp <-> $($c.RemoteAddress):$rp"
            state        = [string]$c.State
        })
        if ($netDetails.Count -ge 220) { break }
    }

    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 60)) {
        $lp = [int]$u.LocalPort
        $svc = if ($portServiceMap.ContainsKey($lp)) { $portServiceMap[$lp] } else { 'Other UDP' }
        $pName = if ($procNameMap.ContainsKey([int]$u.OwningProcess)) { $procNameMap[[int]$u.OwningProcess] } else { "PID $($u.OwningProcess)" }
        $netDetails.Add([PSCustomObject]@{
            detailType   = 'UDP Endpoint'
            protocol     = 'UDP'
            serviceName  = $svc
            clientIp     = $u.LocalAddress
            localPort    = $lp
            remotePort   = 0
            userName     = ''
            processName  = $pName
            resourcePath = "$($u.LocalAddress):$lp"
            state        = 'Bound'
        })
    }

    # SMB Open Files & Sessions
    $smbOpenCount = 0
    try {
        $smbFiles = @(Get-SmbOpenFile -ErrorAction Stop)
        $smbOpenCount = $smbFiles.Count
        foreach ($sf in ($smbFiles | Select-Object -First 80)) {
            $netDetails.Add([PSCustomObject]@{
                detailType   = 'SMB Open File'
                protocol     = 'SMB'
                serviceName  = 'SMB File Share'
                clientIp     = [string]$sf.ClientComputerName
                localPort    = 445
                remotePort   = 0
                userName     = [string]$sf.ClientUserName
                processName  = 'LanmanServer'
                resourcePath = [string]$sf.Path
                state        = "Locks: $($sf.Locks)"
            })
        }
    } catch {}

    # Open Named Pipes (SQL pipes, Print Spooler, RPC, SMB, etc.)
    try {
        $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\'))
        $interestingPipes = $pipes | Where-Object { $_ -match 'sql|MSSQL|srvsvc|wkssvc|spoolss|lsarpc|samr|netlogon|atsvc|winreg|Winsock|iis|docker|containerd' } | Select-Object -First 80
        foreach ($pipe in $interestingPipes) {
            $pSvc = if ($pipe -match 'sql|MSSQL') { 'SQL Pipe' }
                    elseif ($pipe -match 'srvsvc|wkssvc') { 'SMB/Server Pipe' }
                    elseif ($pipe -match 'spoolss') { 'Print Spooler Pipe' }
                    elseif ($pipe -match 'lsarpc|samr|netlogon') { 'AD/RPC Pipe' }
                    else { 'System Pipe' }
            $netDetails.Add([PSCustomObject]@{
                detailType   = 'Named Pipe'
                protocol     = 'NamedPipe'
                serviceName  = $pSvc
                clientIp     = 'Local/IPC$'
                localPort    = 0
                remotePort   = 0
                userName     = ''
                processName  = 'Kernel/IPC'
                resourcePath = $pipe
                state        = 'Open'
            })
        }
    } catch {}

    return [PSCustomObject]@{
        tsUtc   = $nowIso
        summary = [PSCustomObject]@{
            cpuPct         = $cpuPct
            memUsedPct     = $usedMemPct
            memAvailMB     = $availMemMB
            diskReadMs     = $diskReadMs
            diskWriteMs    = $diskWriteMs
            diskQueue      = $diskQueue
            gpuUtilPct     = $gpuUtilPct
            gpuMemMB       = $gpuMemMB
            netRxKbps      = [math]::Round($totRxKbps, 2)
            netTxKbps      = [math]::Round($totTxKbps, 2)
            netRxErrors    = $totRxErr
            netTxErrors    = $totTxErr
            netRxDiscards  = $totRxDisc
            netTxDiscards  = $totTxDisc
            tcpEstablished = $tcpEstabCount
            smbOpenFiles   = $smbOpenCount
        }
        adapters       = $adapterRows.ToArray()
        topProcesses   = @($topProcObjects)
        networkDetails = $netDetails.ToArray()
        warnings       = $warns.ToArray()
    }
}

$res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($TopProcesses)
foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
foreach ($w in @($res.Data.warnings)) { $warnings.Add($w) }

$sw.Stop()

[ordered]@{
    tsUtc          = $res.Data.tsUtc
    targetServer   = $ComputerName
    protocolUsed   = $res.ProtocolUsed
    executedAs     = $res.ExecutedAs
    durationMs     = $sw.ElapsedMilliseconds
    summary        = $res.Data.summary
    adapters       = @($res.Data.adapters)
    topProcesses   = @($res.Data.topProcesses)
    networkDetails = @($res.Data.networkDetails)
    warnings       = $warnings.ToArray()
} | ConvertTo-Json -Depth 6 -Compress
