#Requires -Version 5.1
<#
.SYNOPSIS
    Audits DHCP Client service, lease state per adapter, and Microsoft-Windows-Dhcp-Client Admin/Operational events.
.NOTES
    Category:  04-Networking / 4.3-DHCP-Client
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

    $svc = Get-Service -Name Dhcp -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'Missing' }

    $dhcpEnabledCount = 0
    foreach ($cfg in (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
        if ($cfg.DHCPEnabled) { $dhcpEnabledCount++ }
        $ip = ($cfg.IPAddress -join ', ')
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Info'
            RecordType  = 'NIC IP/DHCP Config'
            Interface   = $cfg.Description
            DhcpServer  = if ($cfg.DHCPEnabled) { [string]$cfg.DHCPServer } else { 'Static IP' }
            EventId     = 0
            Summary     = "$($cfg.Description) | DHCP=$($cfg.DHCPEnabled) | IP=$ip | DHCP Server=$($cfg.DHCPServer)"
            RawMessage  = ($cfg | Select-Object Description, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires, IPAddress, DefaultIPGateway | Format-List | Out-String)
        })
    }

    $dhcpErrs = 0
    foreach ($logName in @('Microsoft-Windows-Dhcp-Client/Admin', 'Microsoft-Windows-Dhcp-Client/Operational')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $dhcpErrs++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'DHCP Event'
                    Interface   = $ev.ProviderName
                    DhcpServer  = $logName
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows             = @($out.ToArray() | Select-Object -First $Max)
        SvcState         = $svcState
        DhcpEnabledCount = $dhcpEnabledCount
        DhcpErrs         = $dhcpErrs
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
        @{ key = 'Interface';   label = 'Interface/Src';type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DhcpServer';  label = 'DHCP Server';  type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dhcp_svc';      label = 'DHCP Client Svc'; value = $res.Data.SvcState;         unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'warning' } }
        @{ key = 'dhcp_adapters'; label = 'DHCP Adapters';   value = $res.Data.DhcpEnabledCount; unit = 'NICs';   severity = 'info' }
        @{ key = 'dhcp_errors';   label = 'DHCP Warnings';   value = $res.Data.DhcpErrs;         unit = 'events'; severity = if ($res.Data.DhcpErrs -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.3-dhcp-client' -Category 'Networking' -SubCategory 'DHCP Client' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.3-dhcp-client' -Category 'Networking' -SubCategory 'DHCP Client' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
