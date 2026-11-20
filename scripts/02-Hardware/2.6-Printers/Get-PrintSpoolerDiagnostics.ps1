#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Print Spooler service state, configured printers & queues, and PrintService Admin/Operational errors.
.NOTES
    Category:  02-Hardware / 2.6-Printers
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

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $spoolerState = if ($spooler) { [string]$spooler.Status } else { 'Missing' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($spoolerState -eq 'Running') { 'Info' } else { 'Warning' }
        RecordType  = 'Spooler Service'
        EventId     = 0
        PrinterName = 'Spooler'
        DriverName  = ''
        Summary     = "Print Spooler Service Status: $spoolerState"
        RawMessage  = ($spooler | Format-List | Out-String)
    })

    $printerCount = 0
    $errPrinters = 0
    try {
        foreach ($p in (Get-Printer -ErrorAction Stop)) {
            $printerCount++
            $hasErr = ($p.PrinterStatus -ne 'Normal')
            if ($hasErr) { $errPrinters++ }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = if ($hasErr) { 'Warning' } else { 'Info' }
                RecordType  = 'Printer Queue'
                EventId     = 0
                PrinterName = $p.Name
                DriverName  = $p.DriverName
                Summary     = "Printer '$($p.Name)' | Status: $($p.PrinterStatus) | Port: $($p.PortName) | Driver: $($p.DriverName)"
                RawMessage  = ($p | Format-List | Out-String)
            })
        }
    } catch {}

    $printErrs = 0
    foreach ($logName in @('Microsoft-Windows-PrintService/Admin', 'Microsoft-Windows-PrintService/Operational')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $printErrs++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'PrintService Event'
                    EventId     = $ev.Id
                    PrinterName = $ev.ProviderName
                    DriverName  = $logName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        SpoolerState = $spoolerState
        PrinterCount = $printerCount
        PrintErrs    = $printErrs
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';          type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'PrinterName'; label = 'Printer/Src';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DriverName';  label = 'Driver/Log';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'spooler_status'; label = 'Spooler Service';     value = $res.Data.SpoolerState; unit = '';         severity = if ($res.Data.SpoolerState -eq 'Running') { 'ok' } else { 'warning' } }
        @{ key = 'printers_total'; label = 'Installed Printers';  value = $res.Data.PrinterCount; unit = 'printers'; severity = 'info' }
        @{ key = 'print_errors';   label = 'PrintService Errors'; value = $res.Data.PrintErrs;    unit = 'events';   severity = if ($res.Data.PrintErrs -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.6-printers' -Category 'Hardware' -SubCategory 'Printers & Spooler' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.6-printers' -Category 'Hardware' -SubCategory 'Printers & Spooler' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
