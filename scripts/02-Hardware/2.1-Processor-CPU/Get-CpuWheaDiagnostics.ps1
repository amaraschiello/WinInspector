#Requires -Version 5.1
<#
.SYNOPSIS
    Audits CPU inventory, utilization, thermal zones (if exposed), and WHEA-Logger processor/machine-check events.
.NOTES
    Category:  02-Hardware / 2.1-Processor-CPU
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
    $warns = New-Object System.Collections.Generic.List[string]

    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
    $avgLoad = 0
    foreach ($c in $cpus) {
        $load = if ($null -ne $c.LoadPercentage) { [int]$c.LoadPercentage } else { 0 }
        $avgLoad += $load
        $sev = if ($load -ge 90) { 'Critical' } elseif ($load -ge 75) { 'Warning' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'CPU Socket'
            EventId     = 0
            Source      = $c.DeviceID
            LoadPct     = $load
            Summary     = "$($c.Name) | Cores: $($c.NumberOfCores) / Logical: $($c.NumberOfLogicalProcessors) | Clock: $($c.CurrentClockSpeed)/$($c.MaxClockSpeed) MHz | Load: $load%"
            RawMessage  = ($c | Select-Object DeviceID, Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, CurrentClockSpeed, MaxClockSpeed, LoadPercentage, Status | Format-List | Out-String)
        })
    }
    if ($cpus.Count -gt 0) { $avgLoad = [math]::Round($avgLoad / $cpus.Count, 1) }

    # Thermal Zones (best-effort; often unavailable in VMs)
    try {
        $therms = @(Get-CimInstance -Namespace 'root/WMI' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        foreach ($t in $therms) {
            $celsius = [math]::Round(($t.CurrentTemperature / 10.0) - 273.15, 1)
            $sev = if ($celsius -ge 85) { 'Critical' } elseif ($celsius -ge 75) { 'Warning' } else { 'Info' }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'Thermal Sensor'
                EventId     = 0
                Source      = $t.InstanceName
                LoadPct     = $celsius
                Summary     = "Thermal Zone '$($t.InstanceName)': $celsius C"
                RawMessage  = "InstanceName: $($t.InstanceName)`nTemperatureC: $celsius"
            })
        }
    } catch {}

    # WHEA & Kernel-Processor-Power events
    $wheaCount = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = @('Microsoft-Windows-WHEA-Logger', 'Microsoft-Windows-Kernel-Processor-Power')
            Level        = @(1, 2, 3)
            StartTime    = $startTime
        } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            if ($ev.ProviderName -like '*WHEA*') { $wheaCount++ }
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'CPU/WHEA Event'
                EventId     = $ev.Id
                Source      = $ev.ProviderName
                LoadPct     = 0
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    }
    catch {
        $warns.Add("WHEA event query warning: $($_.Exception.Message)")
    }

    return [PSCustomObject]@{
        Rows       = @($out.ToArray() | Select-Object -First $Max)
        CpuSockets = $cpus.Count
        AvgLoad    = $avgLoad
        WheaErrors = $wheaCount
        Warnings   = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LoadPct';     label = 'Load/Temp';    type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'cpu_sockets'; label = 'CPU Sockets';  value = $res.Data.CpuSockets; unit = 'sockets'; severity = 'info' }
        @{ key = 'cpu_load';    label = 'Avg CPU Load'; value = $res.Data.AvgLoad;    unit = '%';       severity = if ($res.Data.AvgLoad -ge 85) { 'warning' } else { 'ok' } }
        @{ key = 'whea_errors'; label = 'WHEA Errors';  value = $res.Data.WheaErrors; unit = 'events';  severity = if ($res.Data.WheaErrors -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.1-processor-cpu' -Category 'Hardware' -SubCategory 'Processor (CPU)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.1-processor-cpu' -Category 'Hardware' -SubCategory 'Processor (CPU)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
