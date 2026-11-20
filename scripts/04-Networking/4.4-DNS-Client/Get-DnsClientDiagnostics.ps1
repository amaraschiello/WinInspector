#Requires -Version 5.1
<#
.SYNOPSIS
    Audits DNS Client configuration, Dnscache service state, DNS Client Event Log errors (1014, 8015, etc.), and optional name resolution test.
.NOTES
    Category:  04-Networking / 4.4-DNS-Client
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
    [string]$TestHostName = '',

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
    param($Hours, $TestHost, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $svc = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'Unknown' }

    # Configured DNS servers
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }
    foreach ($d in $dnsServers) {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Info'
            RecordType  = 'DNS Config'
            Interface   = $d.InterfaceAlias
            DnsServer   = ($d.ServerAddresses -join ', ')
            EventId     = 0
            Summary     = "Configured IPv4 DNS Servers on $($d.InterfaceAlias): $($d.ServerAddresses -join ', ')"
            RawMessage  = ($d | Format-List | Out-String)
        })
    }

    # Optional live Resolve-DnsName check from the target server
    if (-not [string]::IsNullOrWhiteSpace($TestHost)) {
        try {
            $resDns = Resolve-DnsName -Name $TestHost -ErrorAction Stop
            $ips = ($resDns | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join ', '
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = 'Info'
                RecordType  = 'Resolution Test'
                Interface   = $TestHost
                DnsServer   = $ips
                EventId     = 0
                Summary     = "Resolved '$TestHost' -> $ips"
                RawMessage  = ($resDns | Format-Table -AutoSize | Out-String)
            })
        }
        catch {
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = 'Error'
                RecordType  = 'Resolution Test'
                Interface   = $TestHost
                DnsServer   = 'Failed'
                EventId     = 0
                Summary     = "Failed to resolve '$TestHost': $($_.Exception.Message)"
                RawMessage  = $_.Exception.Message
            })
        }
    }

    # System log DNS Client Events (e.g. 1014 timeouts, 8015/8016 registration failures)
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-DNS-Client'
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    $dnsErrCount = 0
    foreach ($ev in $evs) {
        $dnsErrCount++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'DNS Event'
            Interface   = 'DNS Client'
            DnsServer   = ''
            EventId     = $ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    try {
        $dnsOpEvs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $dnsOpEvs) {
            $dnsErrCount++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'DNS-Client/Operational'
                Interface   = $ev.ProviderName
                DnsServer   = ''
                EventId     = $ev.Id
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows        = @($out | Select-Object -First $Max)
        SvcState    = $svcState
        DnsErrCount = $dnsErrCount
        ConfigCount = @($dnsServers).Count
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $TestHostName, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Interface';   label = 'Interface/Host';type = 'string';  filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DnsServer';   label = 'DNS Server/IP';type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dnscache_svc'; label = 'Dnscache Service';   value = $res.Data.SvcState;    unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'critical' } }
        @{ key = 'dns_configs';  label = 'Interfaces w/ DNS';  value = $res.Data.ConfigCount; unit = 'NICs';   severity = 'info' }
        @{ key = 'dns_events';   label = 'DNS Client Warnings';value = $res.Data.DnsErrCount; unit = 'events'; severity = if ($res.Data.DnsErrCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.4-dns-client' -Category 'Networking' -SubCategory 'DNS Client' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.4-dns-client' -Category 'Networking' -SubCategory 'DNS Client' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
