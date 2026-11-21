#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Print Spooler service health, spool directory backlog, and operational status of all configured printers via Get-Printer.
.NOTES
    Category:  06-Print-Management / 6.1-Printer-Status
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
    [string]$PrinterName = '',

    [Parameter()]
    [ValidateSet('All', 'IssuesOnly', 'Normal', 'Offline', 'Error', 'Paused')]
    [string]$StatusFilter = 'All',

    [Parameter()]
    [ValidateRange(10, 2000)]
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
    param($NameFilter, $FilterStatus, $Max)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $spoolerCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction SilentlyContinue
    $spoolerState = if ($spooler) { [string]$spooler.Status } else { 'Missing' }
    $spoolerStart = if ($spoolerCim) { [string]$spoolerCim.StartMode } else { 'Unknown' }

    # Inspect default spool directory for stuck .SPL / .SHD files
    $spoolDir = "$env:SystemRoot\System32\spool\PRINTERS"
    try {
        $regPrint = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -Name 'DefaultSpoolDirectory' -ErrorAction SilentlyContinue
        if ($regPrint -and -not [string]::IsNullOrWhiteSpace([string]$regPrint.DefaultSpoolDirectory)) {
            $spoolDir = [string]$regPrint.DefaultSpoolDirectory
        }
    } catch {}

    $spoolFilesCount = 0
    $spoolSizeMb = 0.0
    if (Test-Path -LiteralPath $spoolDir) {
        try {
            $files = @(Get-ChildItem -LiteralPath $spoolDir -File -ErrorAction SilentlyContinue)
            $spoolFilesCount = $files.Count
            $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
            if ($null -ne $totalBytes) {
                $spoolSizeMb = [math]::Round(($totalBytes / 1MB), 2)
            }
        } catch {}
    }

    $spoolerSev = if ($spoolerState -ne 'Running') { 'Critical' } elseif ($spoolFilesCount -gt 50) { 'Warning' } else { 'Info' }
    $out.Add([PSCustomObject]@{
        Severity      = $spoolerSev
        PrinterName   = 'Print Spooler (Service)'
        PrinterStatus = $spoolerState
        JobCount      = $spoolFilesCount
        Shared        = $false
        ShareName     = ''
        Published     = $false
        DriverName    = "StartMode: $spoolerStart"
        PortName      = $spoolDir
        Location      = ''
        Type          = 'Service'
        Comment       = "Spool Dir: $spoolFilesCount file(s), $spoolSizeMb MB"
        RawDetails    = "Service: Spooler | Status: $spoolerState | StartMode: $spoolerStart | SpoolDirectory: $spoolDir | SpoolFiles: $spoolFilesCount ($spoolSizeMb MB)"
    })

    $totalPrinters = 0
    $healthyPrinters = 0
    $issuePrinters = 0
    $totalJobs = 0

    try {
        $printers = @(Get-Printer -Full -ErrorAction Stop)
    }
    catch {
        try {
            $printers = @(Get-Printer -ErrorAction Stop)
        }
        catch {
            $printers = @()
            $warns.Add("Get-Printer failed: $($_.Exception.Message)")
        }
    }

    foreach ($p in $printers) {
        $pName = [string]$p.Name
        if (-not [string]::IsNullOrWhiteSpace($NameFilter) -and ($pName -notlike "*$NameFilter*")) {
            continue
        }

        $statusStr = [string]$p.PrinterStatus
        $jobs = if ($null -ne $p.JobCount) { [int]$p.JobCount } else { 0 }
        $isNormal = ($statusStr -eq 'Normal')

        $totalPrinters++
        $totalJobs += $jobs
        if ($isNormal) { $healthyPrinters++ } else { $issuePrinters++ }

        $include = switch ($FilterStatus) {
            'IssuesOnly' { -not $isNormal }
            'Normal'     { $isNormal }
            'Offline'    { $statusStr -match 'Offline' }
            'Error'      { $statusStr -match 'Error|Paper|Toner|Door|Jammed|OutOfMemory|ServerUnknown' }
            'Paused'     { $statusStr -match 'Paused' }
            default      { $true }
        }
        if (-not $include) { continue }

        $sev = if ($statusStr -match 'Error|Jammed|ServerUnknown|NotAvailable|OutOfMemory') {
            'Error'
        }
        elseif (-not $isNormal) {
            'Warning'
        }
        elseif ($jobs -gt 20) {
            'Warning'
        }
        else {
            'Info'
        }

        $isPublished = $false
        try { if ($null -ne $p.Published) { $isPublished = [bool]$p.Published } } catch {}

        $out.Add([PSCustomObject]@{
            Severity      = $sev
            PrinterName   = $pName
            PrinterStatus = $statusStr
            JobCount      = $jobs
            Shared        = [bool]$p.Shared
            ShareName     = [string]$p.ShareName
            Published     = $isPublished
            DriverName    = [string]$p.DriverName
            PortName      = [string]$p.PortName
            Location      = [string]$p.Location
            Type          = [string]$p.Type
            Comment       = [string]$p.Comment
            RawDetails    = ($p | Format-List * | Out-String)
        })
    }

    return [PSCustomObject]@{
        Rows            = @($out.ToArray() | Select-Object -First $Max)
        SpoolerState    = $spoolerState
        TotalPrinters   = $totalPrinters
        HealthyPrinters = $healthyPrinters
        IssuePrinters   = $issuePrinters
        TotalJobs       = $totalJobs
        SpoolFilesCount = $spoolFilesCount
        Warnings        = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($PrinterName.Trim(), $StatusFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';      label = 'Severity';       type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'PrinterName';   label = 'Printer Name';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'PrinterStatus'; label = 'Status';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'JobCount';      label = 'Jobs';           type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Shared';        label = 'Shared';         type = 'boolean';  filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ShareName';     label = 'Share Name';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'DriverName';    label = 'Driver';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'PortName';      label = 'Port';           type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Location';      label = 'Location';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $false }
        @{ key = 'Published';     label = 'AD Published';   type = 'boolean';  filterable = $true;  facet = $true;  defaultVisible = $false }
        @{ key = 'Type';          label = 'Type';           type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $false }
        @{ key = 'Comment';       label = 'Comment / Note'; type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawDetails';    label = 'Full Details';   type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'spooler_status';   label = 'Spooler Service';      value = $res.Data.SpoolerState;    unit = '';         severity = if ($res.Data.SpoolerState -eq 'Running') { 'ok' } else { 'critical' } }
        @{ key = 'printers_total';   label = 'Total Printers';       value = $res.Data.TotalPrinters;   unit = 'printers'; severity = 'info' }
        @{ key = 'printers_healthy'; label = 'Healthy (Normal)';     value = $res.Data.HealthyPrinters; unit = 'printers'; severity = 'ok' }
        @{ key = 'printers_issues';  label = 'Printers w/ Issues';   value = $res.Data.IssuePrinters;   unit = 'printers'; severity = if ($res.Data.IssuePrinters -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'queued_jobs';      label = 'Queued Print Jobs';    value = $res.Data.TotalJobs;       unit = 'jobs';     severity = if ($res.Data.TotalJobs -gt 50) { 'warning' } else { 'info' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.1-printer-status' -Category 'Print Management' -SubCategory 'Printer Status & Operational Overview' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.1-printer-status' -Category 'Print Management' -SubCategory 'Printer Status & Operational Overview' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
