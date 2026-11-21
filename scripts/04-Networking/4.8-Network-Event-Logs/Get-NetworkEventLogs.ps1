#Requires -Version 5.1
<#
.SYNOPSIS
    Queries all 8 core Windows Networking event log subsystems:
    Microsoft-Windows-TCPIP, NDIS, Winsock-AFD, WFP, Kernel-Network, SMBServer, DNS-Client, and WinINet.
.NOTES
    Category:  04-Networking / 4.8-Network-Event-Logs
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
    [string[]]$Providers = @('TCPIP', 'NDIS', 'Winsock-AFD', 'WFP', 'Kernel-Network', 'SMBServer', 'DNS-Client', 'WinINet'),

    [Parameter()]
    [ValidateSet('ErrorsAndWarnings', 'All')]
    [string]$LevelFilter = 'ErrorsAndWarnings',

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxResults = 500,

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
    param($Hours, $ProviderKeys, $LvlMode, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $providerPatterns = @{
        'TCPIP'          = @{ LogPatterns = @('Microsoft-Windows-TCPIP*');          SysProviders = @('Tcpip', 'Microsoft-Windows-TCPIP') }
        'NDIS'           = @{ LogPatterns = @('Microsoft-Windows-NDIS*', 'Microsoft-Windows-NdisImPlatform*'); SysProviders = @('NDIS', 'Microsoft-Windows-NDIS') }
        'Winsock-AFD'    = @{ LogPatterns = @('Microsoft-Windows-Winsock*');        SysProviders = @('AFD', 'Microsoft-Windows-Winsock-AFD') }
        'WFP'            = @{ LogPatterns = @('Microsoft-Windows-WFP*');            SysProviders = @('BFE', 'MPSSVC') }
        'Kernel-Network' = @{ LogPatterns = @('Microsoft-Windows-Kernel-Network*'); SysProviders = @() }
        'SMBServer'      = @{ LogPatterns = @('Microsoft-Windows-SMBServer*');      SysProviders = @('Srv', 'Srv2', 'LanmanServer') }
        'DNS-Client'     = @{ LogPatterns = @('Microsoft-Windows-DNS-Client*');     SysProviders = @('Microsoft-Windows-DNS-Client', 'Dnscache') }
        'WinINet'        = @{ LogPatterns = @('Microsoft-Windows-WinINet*');        SysProviders = @() }
    }

    $levels = if ($LvlMode -eq 'All') { @(1, 2, 3, 4, 0) } else { @(1, 2, 3) }
    $enabledChannels = 0
    $disabledChannels = New-Object System.Collections.Generic.List[string]
    $totalEvents = 0
    $errorEvents = 0
    $sysProvidersToQuery = New-Object System.Collections.Generic.List[string]

    foreach ($pk in $ProviderKeys) {
        if (-not $providerPatterns.ContainsKey($pk)) { continue }
        $spec = $providerPatterns[$pk]

        foreach ($sp in $spec.SysProviders) {
            if (-not $sysProvidersToQuery.Contains($sp)) { $sysProvidersToQuery.Add($sp) }
        }

        foreach ($pat in $spec.LogPatterns) {
            $logs = @(Get-WinEvent -ListLog $pat -Force -ErrorAction SilentlyContinue)
            foreach ($lg in $logs) {
                if (-not $lg.IsEnabled) {
                    $disabledChannels.Add($lg.LogName)
                    continue
                }
                $enabledChannels++
                try {
                    $f = @{ LogName = $lg.LogName; StartTime = $startTime }
                    if ($LvlMode -ne 'All') { $f['Level'] = $levels }
                    $evs = Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction SilentlyContinue
                    foreach ($ev in $evs) {
                        $totalEvents++
                        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                        if ($sev -in @('Critical', 'Error')) { $errorEvents++ }
                        $msg = if ($ev.Message) { $ev.Message } else { '' }
                        $out.Add([PSCustomObject]@{
                            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                            Severity    = $sev
                            Subsystem   = $pk
                            LogChannel  = $lg.LogName
                            EventId     = $ev.Id
                            Provider    = $ev.ProviderName
                            Summary     = ($msg -split "`r?`n")[0]
                            RawMessage  = $msg
                        })
                    }
                }
                catch {
                    $warns.Add("Failed querying '$($lg.LogName)': $($_.Exception.Message)")
                }
            }
        }
    }

    # Query matching System log providers (always active even when Operational/Analytic channels are off)
    if ($sysProvidersToQuery.Count -gt 0) {
        try {
            $sysFilter = @{ LogName = 'System'; ProviderName = $sysProvidersToQuery.ToArray(); StartTime = $startTime }
            if ($LvlMode -ne 'All') { $sysFilter['Level'] = $levels }
            $sysEvs = Get-WinEvent -FilterHashtable $sysFilter -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $sysEvs) {
                $totalEvents++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                if ($sev -in @('Critical', 'Error')) { $errorEvents++ }
                $sub = if ($ev.ProviderName -like '*DNS*') { 'DNS-Client' }
                       elseif ($ev.ProviderName -like '*NDIS*') { 'NDIS' }
                       elseif ($ev.ProviderName -like '*Tcpip*') { 'TCPIP' }
                       elseif ($ev.ProviderName -like '*Srv*' -or $ev.ProviderName -like '*Lanman*') { 'SMBServer' }
                       else { 'WFP' }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    Subsystem   = $sub
                    LogChannel  = 'System'
                    EventId     = $ev.Id
                    Provider    = $ev.ProviderName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    if ($disabledChannels.Count -gt 0) {
        $warns.Add("Disabled channels on target (enable via Event Viewer / wevtutil if needed): $(($disabledChannels.ToArray() | Select-Object -Unique) -join ', ')")
    }

    return [PSCustomObject]@{
        Rows            = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        EnabledChannels = $enabledChannels
        DisabledCount   = ($disabledChannels.ToArray() | Select-Object -Unique).Count
        TotalEvents     = $totalEvents
        ErrorEvents     = $errorEvents
        Warnings        = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $Providers, $LevelFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Subsystem';   label = 'Subsystem';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogChannel';  label = 'Log Channel';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Provider';    label = 'Provider';     type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'net_events_total';     label = 'Matching Events';  value = $rows.Count;                  unit = 'events';   severity = 'info' }
        @{ key = 'net_events_errors';    label = 'Errors/Critical';  value = $res.Data.ErrorEvents;        unit = 'events';   severity = if ($res.Data.ErrorEvents -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'net_channels_enabled'; label = 'Enabled Channels'; value = $res.Data.EnabledChannels;    unit = 'channels'; severity = 'info' }
        @{ key = 'net_channels_off';     label = 'Disabled Logs';    value = $res.Data.DisabledCount;      unit = 'channels'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.8-network-event-logs' -Category 'Networking' -SubCategory 'Network Subsystem Event Logs' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.8-network-event-logs' -Category 'Networking' -SubCategory 'Network Subsystem Event Logs' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
