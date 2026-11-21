#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Motherboard/Chipset, BIOS firmware info, PCI/Bus device errors (ConfigManagerErrorCode != 0), and WHEA-Logger bus/PCIe events.
.NOTES
    Category:  02-Hardware / 2.3-Motherboard-Chipset
    Protocols: WinRM, CIM-DCOM
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

    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    if ($bb) {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Info'
            RecordType  = 'Baseboard / BIOS'
            EventId     = 0
            DeviceName  = "$($bb.Manufacturer) $($bb.Product)"
            ErrorCode   = '0'
            Summary     = "Board: $($bb.Manufacturer) $($bb.Product) | BIOS: $($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate))"
            RawMessage  = ($bb | Format-List | Out-String) + "`n" + ($bios | Format-List | Out-String)
        })
    }

    # PnP Devices with ConfigManagerErrorCode != 0
    $badDevs = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction SilentlyContinue)
    foreach ($d in $badDevs) {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Error'
            RecordType  = 'Faulty PnP Device'
            EventId     = 0
            DeviceName  = $d.Name
            ErrorCode   = [string]$d.ConfigManagerErrorCode
            Summary     = "Device '$($d.Name)' ($($d.PNPClass)) reporting ConfigManagerErrorCode=$($d.ConfigManagerErrorCode)"
            RawMessage  = ($d | Select-Object Name, DeviceID, PNPClass, Status, ConfigManagerErrorCode | Format-List | Out-String)
        })
    }

    # WHEA-Logger & HAL/ACPI/PCI bus events
    $wheaCount = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-WHEA-Logger', 'Microsoft-Windows-HAL', 'ACPI', 'pci')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $evs) {
        $wheaCount++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Hardware/Bus Event'
            EventId     = $ev.Id
            DeviceName  = $ev.ProviderName
            ErrorCode   = [string]$ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        FaultyDevs   = $badDevs.Count
        BusEvents    = $wheaCount
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
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DeviceName';  label = 'Device/Source';type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ErrorCode';   label = 'Code';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'faulty_pnp_devices'; label = 'Faulty PnP Devices';  value = $res.Data.FaultyDevs; unit = 'devices'; severity = if ($res.Data.FaultyDevs -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'bus_whea_events';    label = 'Bus / WHEA Events';   value = $res.Data.BusEvents;  unit = 'events';  severity = if ($res.Data.BusEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.3-motherboard-chipset' -Category 'Hardware' -SubCategory 'Motherboard & Chipset' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.3-motherboard-chipset' -Category 'Hardware' -SubCategory 'Motherboard & Chipset' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
