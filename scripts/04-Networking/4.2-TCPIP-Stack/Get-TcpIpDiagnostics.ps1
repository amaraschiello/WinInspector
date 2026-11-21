#Requires -Version 5.1
<#
.SYNOPSIS
    Inspects TCP/IP stack: active TCP connections, listening ports, IP/Gateway config, and TCPIP System events.
.NOTES
    Category:  04-Networking / 4.2-TCPIP-Stack
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
    [ValidateSet('All', 'Listen', 'Established', 'TimeWait', 'CloseWait')]
    [string]$ConnectionState = 'All',

    [Parameter()]
    [string]$RemoteAddressFilter = '',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 300,

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
    param($StateFilter, $RemoteFilter, $Max)
    $out = New-Object System.Collections.Generic.List[object]

    $procMap = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $procMap[$p.Id] = $p.ProcessName
    }

    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    if ($StateFilter -ne 'All') {
        $conns = $conns | Where-Object { $_.State -eq $StateFilter }
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteFilter)) {
        $conns = $conns | Where-Object { $_.RemoteAddress -like "*$RemoteFilter*" }
    }

    $totalConns = @($conns).Count
    $listenCount = @($conns | Where-Object { $_.State -eq 'Listen' }).Count
    $estabCount  = @($conns | Where-Object { $_.State -eq 'Established' }).Count
    $closeWait   = @($conns | Where-Object { $_.State -eq 'CloseWait' }).Count

    foreach ($c in ($conns | Select-Object -First $Max)) {
        $procName = if ($procMap.ContainsKey($c.OwningProcess)) { $procMap[$c.OwningProcess] } else { "PID $($c.OwningProcess)" }
        $sev = if ($c.State -eq 'CloseWait') { 'Warning' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated   = (Get-Date).ToUniversalTime().ToString('o')
            Severity      = $sev
            State         = [string]$c.State
            LocalAddress  = $c.LocalAddress
            LocalPort     = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            ProcessName   = $procName
            OwningPid     = $c.OwningProcess
            RawMessage    = "State: $($c.State)`nLocal: $($c.LocalAddress):$($c.LocalPort)`nRemote: $($c.RemoteAddress):$($c.RemotePort)`nProcess: $procName (PID $($c.OwningProcess))`nAppliedSetting: $($c.AppliedSetting)"
        })
    }

    return [PSCustomObject]@{
        Rows       = $out.ToArray()
        Total      = $totalConns
        Listen     = $listenCount
        Estab      = $estabCount
        CloseWait  = $closeWait
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($ConnectionState, $RemoteAddressFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';      label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';         label = 'TCP State';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LocalAddress';  label = 'Local IP';     type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LocalPort';     label = 'Local Port';   type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RemoteAddress'; label = 'Remote IP';    type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RemotePort';    label = 'Remote Port';  type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProcessName';   label = 'Process';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'OwningPid';     label = 'PID';          type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';    label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'tcp_total';      label = 'Matching Sockets'; value = $res.Data.Total;     unit = 'sockets'; severity = 'info' }
        @{ key = 'tcp_listening';  label = 'Listening';        value = $res.Data.Listen;    unit = 'ports';   severity = 'info' }
        @{ key = 'tcp_estab';      label = 'Established';      value = $res.Data.Estab;     unit = 'conns';   severity = 'info' }
        @{ key = 'tcp_closewait';  label = 'CloseWait';        value = $res.Data.CloseWait; unit = 'conns';   severity = if ($res.Data.CloseWait -gt 50) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.2-tcpip-stack' -Category 'Networking' -SubCategory 'TCP/IP Stack' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.2-tcpip-stack' -Category 'Networking' -SubCategory 'TCP/IP Stack' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
