#Requires -Version 5.1
<#
.SYNOPSIS
    Audits USB devices/controllers with errors and Kernel-PnP / USBHUB enumeration & disconnect events.
.NOTES
    Category:  02-Hardware / 2.5-USB-Devices
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

    $usbDevs = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='USB'" -ErrorAction SilentlyContinue)
    $faultyUsb = 0
    foreach ($u in $usbDevs) {
        $isErr = ($u.ConfigManagerErrorCode -ne 0)
        if ($isErr) { $faultyUsb++ }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($isErr) { 'Error' } else { 'Info' }
            RecordType  = 'USB Device'
            EventId     = 0
            DeviceName  = $u.Name
            Status      = if ($isErr) { "ErrorCode $($u.ConfigManagerErrorCode)" } else { $u.Status }
            Summary     = "$($u.Name) | Status: $($u.Status) | ErrorCode: $($u.ConfigManagerErrorCode)"
            RawMessage  = ($u | Select-Object Name, DeviceID, Status, ConfigManagerErrorCode, Manufacturer | Format-List | Out-String)
        })
    }

    $pnpEvents = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-Kernel-PnP', 'USBHUB', 'USBHUB3', 'USBXHCI')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $evs) {
        $pnpEvents++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'PnP / USB Event'
            EventId     = $ev.Id
            DeviceName  = $ev.ProviderName
            Status      = $sev
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{ Rows = @($out.ToArray() | Select-Object -First $Max); UsbCount = $usbDevs.Count; FaultyUsb = $faultyUsb; PnpEvents = $pnpEvents }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DeviceName';  label = 'Device/Source';type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Status';      label = 'Status';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'usb_devices'; label = 'USB Devices';     value = $res.Data.UsbCount;  unit = 'devices'; severity = 'info' }
        @{ key = 'usb_faults';  label = 'Faulty USB Devs'; value = $res.Data.FaultyUsb; unit = 'devices'; severity = if ($res.Data.FaultyUsb -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'pnp_events';  label = 'PnP/USB Warnings';value = $res.Data.PnpEvents; unit = 'events';  severity = if ($res.Data.PnpEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.5-usb-devices' -Category 'Hardware' -SubCategory 'USB Devices' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.5-usb-devices' -Category 'Hardware' -SubCategory 'USB Devices' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
