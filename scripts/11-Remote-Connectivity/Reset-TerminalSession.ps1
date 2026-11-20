#Requires -Version 5.1
<#
.SYNOPSIS
    Disconnects / kills an active Terminal / RDP session using either:
      - Native rwinsta.exe (rwinsta SessionID|SessionName /server:ServerName /v)
      - WMI/CIM (Win32_LogonSession -> Win32_Process.Terminate() or Win32_Process SessionId termination)
.NOTES
    Category:  11-Remote-Connectivity / 11.3-RDP-Sessions
    Protocols: RPC (rwinsta /server:), WMI (CIM), WinRM
    ReadOnly:  False (Requires explicit user confirmation in UI)
    Reference: https://ss64.com/nt/reset-session.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ComputerName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9#\-_.]{1,32}$')]
    [string]$SessionTarget,

    [Parameter()]
    [ValidatePattern('^(\d{1,20})?$')]
    [string]$LogonId = '',

    [Parameter()]
    [ValidateSet('Auto', 'rwinsta', 'WMI')]
    [string]$Method = 'Auto',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')]
    [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

if ($SessionTarget -eq '0' -or $SessionTarget -ieq 'services') {
    throw "Refusing to reset session '0' (services)."
}

function Resolve-RwinstaPath {
    $candidates = @(
        (Join-Path $env:SystemRoot 'Sysnative\rwinsta.exe'),
        (Join-Path $env:SystemRoot 'System32\rwinsta.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf -ErrorAction SilentlyContinue) { return $c }
    }
    $cmd = Get-Command rwinsta.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$isLocal = Test-WinInspectorIsLocal -ComputerName $ComputerName
$rwinstaExe = Resolve-RwinstaPath

$useWmi = ($Method -eq 'WMI') -or ($Method -eq 'Auto' -and $null -eq $rwinstaExe -and $null -eq $Credential)

if (-not $useWmi) {
    if ($null -eq $Credential) {
        if ($null -eq $rwinstaExe) {
            throw "rwinsta.exe is not installed on this local machine ($env:COMPUTERNAME). Use WMI Kill instead."
        }
        $targetArg = $ComputerName.Trim()
        $cmdDisplay = if ($isLocal) { "rwinsta.exe $SessionTarget /v" } else { "rwinsta.exe $SessionTarget /server:$targetArg /v" }
        $rawOut = if ($isLocal) { & $rwinstaExe $SessionTarget /v 2>&1 } else { & $rwinstaExe $SessionTarget "/server:$targetArg" /v 2>&1 }
        $exitCode = $LASTEXITCODE
        $outText = (@($rawOut | ForEach-Object { [string]$_ }) -join "`n").Trim()
        if ($exitCode -ne 0) {
            throw "rwinsta failed (ExitCode $exitCode): $outText"
        }

        [ordered]@{
            success       = $true
            method        = 'rwinsta'
            targetServer  = $ComputerName
            sessionTarget = $SessionTarget
            command       = $cmdDisplay
            output        = if ($outText) { $outText } else { "Session '$SessionTarget' reset via rwinsta." }
            exitCode      = $exitCode
        } | ConvertTo-Json -Depth 4 -Compress
        return
    }
    elseif ($Method -in @('Auto', 'rwinsta')) {
        try {
            $remRes = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock {
                param($TargetSess)
                $exe = Join-Path $env:SystemRoot 'System32\rwinsta.exe'
                if (-not (Test-Path -LiteralPath $exe)) { throw "rwinsta.exe not found on target server." }
                $rawOut = & $exe $TargetSess /v 2>&1
                $code = $LASTEXITCODE
                $txt = (@($rawOut | ForEach-Object { [string]$_ }) -join "`n").Trim()
                if ($code -ne 0) { throw "rwinsta failed (ExitCode $code): $txt" }
                return [PSCustomObject]@{ Output = $txt; ExitCode = $code }
            } -ArgumentList @($SessionTarget)

            [ordered]@{
                success       = $true
                method        = 'rwinsta'
                targetServer  = $ComputerName
                sessionTarget = $SessionTarget
                executedAs    = $remRes.ExecutedAs
                command       = "Invoke-Command -> rwinsta.exe $SessionTarget /v"
                output        = if ($remRes.Data.Output) { $remRes.Data.Output } else { "Session '$SessionTarget' reset via rwinsta." }
                exitCode      = $remRes.Data.ExitCode
            } | ConvertTo-Json -Depth 4 -Compress
            return
        }
        catch {
            if ($Method -eq 'rwinsta') { throw }
            # In Auto mode, fall through to WMI termination using the same -Credential
        }
    }
}

# WMI / CIM Session Termination Path
$cimBundle = $null
try {
    $cimBundle = New-WinInspectorCimSession -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol
    $cimArgs = @{ ErrorAction = 'Stop' }
    if ($null -ne $cimBundle.Session) { $cimArgs['CimSession'] = $cimBundle.Session }

    $targetProcs = @()
    if (-not [string]::IsNullOrWhiteSpace($LogonId)) {
        $ls = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonId='$LogonId'" @cimArgs
        if ($ls) {
            $targetProcs = @(Get-CimAssociatedInstance -InputObject $ls -ResultClassName Win32_Process @cimArgs -ErrorAction SilentlyContinue)
        }
    }

    if ($targetProcs.Count -eq 0 -and $SessionTarget -match '^\d+$') {
        $sidInt = [int]$SessionTarget
        if ($sidInt -le 0) { throw "Refusing to terminate SessionId $sidInt (System/Services)." }
        $targetProcs = @(Get-CimInstance -ClassName Win32_Process -Filter "SessionId=$sidInt" @cimArgs)
    }

    if ($targetProcs.Count -eq 0) {
        throw "No running WMI processes found for SessionTarget='$SessionTarget' (LogonId='$LogonId')."
    }

    # Safety: if targeting localhost, avoid killing our own current pwsh/Pode PID mid-request
    $selfPid = $PID
    $parentPid = if ($isLocal) {
        (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId
    } else { 0 }

    $killed = 0
    $failed = 0
    # Terminate explorer/user apps before winlogon/dwm/csrss
    $ordered = $targetProcs | Sort-Object -Property @{ Expression = { if ($_.Name -in @('explorer.exe', 'sihost.exe', 'userinit.exe')) { 1 } else { 0 } } }

    foreach ($p in $ordered) {
        if ($isLocal -and ($p.ProcessId -eq $selfPid -or $p.ProcessId -eq $parentPid)) { continue }
        try {
            $r = Invoke-CimMethod -InputObject $p -MethodName Terminate -ErrorAction Stop
            if ($r.ReturnValue -eq 0) { $killed++ } else { $failed++ }
        }
        catch {
            $failed++
        }
    }

    [ordered]@{
        success       = ($killed -gt 0)
        method        = "WMI ($($cimBundle.ProtocolUsed))"
        targetServer  = $ComputerName
        sessionTarget = $SessionTarget
        logonId       = $LogonId
        executedAs    = $cimBundle.ExecutedAs
        command       = "WMI Win32_Process.Terminate() [Session=$SessionTarget, LogonId=$LogonId]"
        output        = "Terminated $killed process(es) via WMI ($failed skipped/denied)."
        exitCode      = if ($killed -gt 0) { 0 } else { 1 }
    } | ConvertTo-Json -Depth 4 -Compress
}
finally {
    if ($null -ne $cimBundle -and $null -ne $cimBundle.Session) {
        try { Remove-CimSession -CimSession $cimBundle.Session -ErrorAction SilentlyContinue } catch {}
    }
}
