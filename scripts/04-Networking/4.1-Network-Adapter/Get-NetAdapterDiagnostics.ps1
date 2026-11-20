#Requires -Version 5.1
<#
.SYNOPSIS
    Audits network adapter status, link speed, packet errors/discards, and NDIS/NetAdapter events.
.NOTES
    Category:  04-Networking / 4.1-Network-Adapter
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
    [int]$HoursBack = 72,

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
    $downCount = 0
    $errPacketAdapters = 0

    Import-Module NetAdapter -Force -ErrorAction SilentlyContinue

    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    $statsMap = @{}
    foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) {
        $statsMap[$s.Name] = $s
    }

    foreach ($a in $adapters) {
        $st = $statsMap[$a.Name]
        $rxErr = if ($st) { [long]$st.ReceivedPacketErrors + [long]$st.ReceivedDiscardedPackets } else { 0L }
        $txErr = if ($st) { [long]$st.OutboundPacketErrors + [long]$st.OutboundDiscardedPackets } else { 0L }

        $statusVal = if ($a.PSObject.Properties['Status'] -and $null -ne $a.Status) {
            [string]$a.Status
        } elseif ($a.PSObject.Properties['MediaConnectionState']) {
            switch ([int]$a.MediaConnectionState) { 1 { 'Up' } 2 { 'Disconnected' } default { 'Unknown' } }
        } else { 'Unknown' }

        $adminVal = if ($a.PSObject.Properties['AdminStatus'] -and $null -ne $a.AdminStatus) {
            [string]$a.AdminStatus
        } elseif ($a.PSObject.Properties['InterfaceAdminStatus']) {
            if ([int]$a.InterfaceAdminStatus -eq 1) { 'Up' } else { 'Down' }
        } else { '' }

        $linkSpeedVal = if ($a.PSObject.Properties['LinkSpeed'] -and $null -ne $a.LinkSpeed) {
            [string]$a.LinkSpeed
        } elseif ($a.PSObject.Properties['TransmitLinkSpeed'] -and $a.TransmitLinkSpeed) {
            $bps = [double]$a.TransmitLinkSpeed
            if ($bps -ge 1e9) { "$([math]::Round($bps / 1e9, 2)) Gbps" }
            elseif ($bps -ge 1e6) { "$([math]::Round($bps / 1e6, 0)) Mbps" }
            else { "$bps bps" }
        } else { '0 bps' }

        $macVal = if ($a.PSObject.Properties['MacAddress'] -and $a.MacAddress) {
            [string]$a.MacAddress
        } elseif ($a.PSObject.Properties['LinkLayerAddress'] -and $a.LinkLayerAddress) {
            [string]$a.LinkLayerAddress
        } else { '' }

        $descVal = if ($a.PSObject.Properties['InterfaceDescription']) { [string]$a.InterfaceDescription } else { [string]$a.Name }
        $drvVer  = if ($a.PSObject.Properties['DriverVersion']) { [string]$a.DriverVersion } else { '' }

        if ($statusVal -ne 'Up') { $downCount++ }
        if (($rxErr + $txErr) -gt 0) { $errPacketAdapters++ }

        $sev = if ($statusVal -eq 'Disconnected' -and $adminVal -eq 'Up') { 'Warning' } elseif (($rxErr + $txErr) -gt 10) { 'Warning' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Adapter Status'
            AdapterName = $a.Name
            Status      = $statusVal
            LinkSpeed   = $linkSpeedVal
            EventId     = 0
            Summary     = "$descVal | MAC: $macVal | RxErr/Disc: $rxErr | TxErr/Disc: $txErr"
            RawMessage  = "Name: $($a.Name)`nDescription: $descVal`nStatus: $statusVal`nAdminStatus: $adminVal`nLinkSpeed: $linkSpeedVal`nMacAddress: $macVal`nDriverVersion: $drvVer`nRxErr/Disc: $rxErr`nTxErr/Disc: $txErr"
        })
    }

    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('NDIS', 'Microsoft-Windows-NDIS', 'e1dexpress', 'e1iexpress', 'e1rexpress', 'vmxnet3', 'NetVsc', 'Tcpip')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Adapter Event'
            AdapterName = $ev.ProviderName
            Status      = $sev
            LinkSpeed   = ''
            EventId     = $ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    foreach ($ndisLog in @('Microsoft-Windows-NDIS/Operational', 'Microsoft-Windows-NdisImPlatform/Operational')) {
        try {
            $nEvs = Get-WinEvent -FilterHashtable @{ LogName = $ndisLog; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $nEvs) {
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'NDIS Operational'
                    AdapterName = $ndisLog
                    Status      = $sev
                    LinkSpeed   = ''
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows              = @($out.ToArray() | Select-Object -First $Max)
        TotalAdapters     = $adapters.Count
        DownAdapters      = $downCount
        ErrPacketAdapters = $errPacketAdapters
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'AdapterName'; label = 'Adapter/Src';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Status';      label = 'Link Status';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LinkSpeed';   label = 'Speed';        type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'adapters_total'; label = 'Adapters';            value = $res.Data.TotalAdapters;     unit = 'NICs'; severity = 'info' }
        @{ key = 'adapters_down';  label = 'Disconnected/Down';   value = $res.Data.DownAdapters;      unit = 'NICs'; severity = if ($res.Data.DownAdapters -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'packet_errors';  label = 'NICs w/ Pkt Errors';  value = $res.Data.ErrPacketAdapters; unit = 'NICs'; severity = if ($res.Data.ErrPacketAdapters -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.1-network-adapter' -Category 'Networking' -SubCategory 'Network Adapter' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.1-network-adapter' -Category 'Networking' -SubCategory 'Network Adapter' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
