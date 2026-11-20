#Requires -Version 5.1
<#
.SYNOPSIS
    Terminates a target process by PID on the local or remote server using the caller's
    credentials (or Local Passthrough when unlocked).
.NOTES
    Category:  20-Performance / 20.1-Snapshot
    Protocols: WinRM, CIM-DCOM
    ReadOnly:  False (Requires explicit confirmation in UI)
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

    [Parameter(Mandatory)]
    [int]$ProcessId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

if ($ProcessId -le 4) {
    throw "Refusing to terminate protected system PID $ProcessId."
}

$isLocal = Test-WinInspectorIsLocal -ComputerName $ComputerName
if ($isLocal) {
    $parentPid = 0
    try {
        $parentPid = [int](Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId
    } catch {}
    if ($ProcessId -eq $PID -or ($parentPid -gt 0 -and $ProcessId -eq $parentPid)) {
        throw "Refusing to terminate the active WinInspector server process (PID $ProcessId)."
    }
}

$remoteScript = {
    param($TargetPid)
    $p = Get-Process -Id $TargetPid -ErrorAction Stop
    $name = $p.ProcessName
    Stop-Process -Id $TargetPid -Force -ErrorAction Stop
    return [PSCustomObject]@{
        pid         = $TargetPid
        processName = $name
        method      = 'Stop-Process'
    }
}

$fallbackCim = {
    param($Target, $Cred, $Proto, $TargetPid)
    $cimBundle = $null
    try {
        $cimBundle = New-WinInspectorCimSession -ComputerName $Target -Credential $Cred -Protocol $Proto
        $cimArgs = @{ ErrorAction = 'Stop' }
        if ($null -ne $cimBundle.Session) { $cimArgs['CimSession'] = $cimBundle.Session }
        $wp = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$TargetPid" @cimArgs | Select-Object -First 1
        if ($null -eq $wp) { throw "Process PID $TargetPid not found." }
        $pname = $wp.Name
        $r = Invoke-CimMethod -InputObject $wp -MethodName Terminate -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "Win32_Process.Terminate() returned code $($r.ReturnValue)." }
        return [PSCustomObject]@{
            pid         = $TargetPid
            processName = $pname
            method      = "WMI ($($cimBundle.ProtocolUsed))"
        }
    }
    finally {
        if ($null -ne $cimBundle -and $null -ne $cimBundle.Session) {
            try { Remove-CimSession -CimSession $cimBundle.Session -ErrorAction SilentlyContinue } catch {}
        }
    }
}

$res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($ProcessId) -FallbackScriptBlock $fallbackCim

[ordered]@{
    ok           = $true
    targetServer = $ComputerName
    protocolUsed = $res.ProtocolUsed
    executedAs   = $res.ExecutedAs
    pid          = $res.Data.pid
    processName  = $res.Data.processName
    method       = $res.Data.method
    message      = "Terminated $($res.Data.processName) (PID $($res.Data.pid)) on $ComputerName."
} | ConvertTo-Json -Depth 4 -Compress
