#Requires -Version 5.1
<#
.SYNOPSIS
    Audits WLAN AutoConfig service, wireless interface status (netsh wlan), and WLAN-AutoConfig Operational events.
.NOTES
    Category:  04-Networking / 4.5-Wireless
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
    $warns = New-Object System.Collections.Generic.List[string]

    $wlansvc = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
    if (-not $wlansvc) {
        $warns.Add("WLAN AutoConfig service (WlanSvc) is not installed on '$env:COMPUTERNAME' (typical for headless servers).")
        return [PSCustomObject]@{ Rows = @(); WlanInstalled = $false; SvcState = 'Not Installed'; EventCount = 0; Warnings = $warns.ToArray() }
    }

    $netshText = (& netsh wlan show interfaces 2>&1) -join "`n"
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($wlansvc.Status -eq 'Running') { 'Info' } else { 'Warning' }
        RecordType  = 'WLAN Status'
        EventId     = 0
        Source      = 'WlanSvc'
        Summary     = "WlanSvc: $($wlansvc.Status) | $(($netshText -split "`r?`n" | Where-Object { $_ -match 'SSID|State|Signal' } | Select-Object -First 3) -join ' | ')"
        RawMessage  = $netshText
    })

    $evCount = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $evCount++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'WLAN Event'
                EventId     = $ev.Id
                Source      = $ev.ProviderName
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows          = @($out.ToArray() | Select-Object -First $Max)
        WlanInstalled = $true
        SvcState      = [string]$wlansvc.Status
        EventCount    = $evCount
        Warnings      = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'wlan_svc';    label = 'WlanSvc';       value = $res.Data.SvcState;   unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'info' } }
        @{ key = 'wlan_events'; label = 'WLAN Warnings'; value = $res.Data.EventCount; unit = 'events'; severity = if ($res.Data.EventCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($res.Data.WlanInstalled) { 'Success' } else { 'Partial' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.5-wireless' -Category 'Networking' -SubCategory 'Wireless (WLAN)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.5-wireless' -Category 'Networking' -SubCategory 'Wireless (WLAN)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
