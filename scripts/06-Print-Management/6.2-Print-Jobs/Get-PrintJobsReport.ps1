#Requires -Version 5.1
<#
.SYNOPSIS
    Queries active, queued, paused, and errored print jobs across all printers using Get-Printer and Get-PrintJob.
.NOTES
    Category:  06-Print-Management / 6.2-Print-Jobs
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
    [string]$UserName = '',

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$StuckThresholdMinutes = 15,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($NameFilter, $UserFilter, $StuckMin, $Max)
    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $totalJobs = 0
    $errorJobs = 0
    $stuckJobs = 0
    $totalBytes = [long]0
    $printersWithJobs = 0

    try {
        $printers = @(Get-Printer -ErrorAction Stop)
    }
    catch {
        $printers = @()
        $warns.Add("Get-Printer failed: $($_.Exception.Message)")
    }

    foreach ($p in $printers) {
        $pName = [string]$p.Name
        if (-not [string]::IsNullOrWhiteSpace($NameFilter) -and ($pName -notlike "*$NameFilter*")) {
            continue
        }

        $jobs = @()
        try {
            $jobs = @(Get-PrintJob -PrinterName $pName -ErrorAction SilentlyContinue)
        } catch {}

        if ($jobs.Count -gt 0) {
            $printersWithJobs++
        }

        foreach ($j in $jobs) {
            $uName = [string]$j.UserName
            if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and ($uName -notlike "*$UserFilter*")) {
                continue
            }

            $totalJobs++
            $jobSize = if ($null -ne $j.Size) { [long]$j.Size } else { [long]0 }
            $totalBytes += $jobSize
            $sizeMb = [math]::Round(($jobSize / 1MB), 2)

            $submitted = $j.SubmittedTime
            $ageMin = if ($null -ne $submitted) { [math]::Round(($now - $submitted).TotalMinutes, 1) } else { 0.0 }
            $statusStr = [string]$j.JobStatus
            $isErrStatus = ($statusStr -match 'Error|Blocked|Offline|PaperOut|UserIntervention|Restart')
            $isPaused = ($statusStr -match 'Paused')
            $isStuck = ($ageMin -ge $StuckMin)

            if ($isErrStatus) { $errorJobs++ }
            if ($isStuck) { $stuckJobs++ }

            $sev = if ($isErrStatus) {
                'Error'
            }
            elseif ($isStuck -or $isPaused) {
                'Warning'
            }
            else {
                'Info'
            }

            $out.Add([PSCustomObject]@{
                SubmittedTime = if ($null -ne $submitted) { $submitted.ToUniversalTime().ToString('o') } else { $now.ToUniversalTime().ToString('o') }
                Severity      = $sev
                PrinterName   = $pName
                JobId         = [int]$j.Id
                DocumentName  = [string]$j.DocumentName
                UserName      = $uName
                JobStatus     = $statusStr
                Pages         = "$($j.PagesPrinted)/$($j.TotalPages)"
                SizeMB        = $sizeMb
                AgeMinutes    = $ageMin
                Position      = [int]$j.Position
                RawDetails    = ($j | Format-List * | Out-String)
            })
        }
    }

    $totalSizeMb = [math]::Round(($totalBytes / 1MB), 2)

    return [PSCustomObject]@{
        Rows             = @($out.ToArray() | Select-Object -First $Max)
        TotalJobs        = $totalJobs
        ErrorJobs        = $errorJobs
        StuckJobs        = $stuckJobs
        PrintersWithJobs = $printersWithJobs
        TotalSizeMB      = $totalSizeMb
        Warnings         = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($PrinterName.Trim(), $UserName.Trim(), $StuckThresholdMinutes, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'SubmittedTime'; label = 'Submitted';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';      label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'PrinterName';   label = 'Printer';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'JobId';         label = 'Job ID';       type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'DocumentName';  label = 'Document';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'UserName';      label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'JobStatus';     label = 'Job Status';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Pages';         label = 'Pages';        type = 'string';   filterable = $false; facet = $false; defaultVisible = $true }
        @{ key = 'SizeMB';        label = 'Size (MB)';    type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'AgeMinutes';    label = 'Age (min)';    type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Position';      label = 'Queue Pos';    type = 'number';   filterable = $false; facet = $false; defaultVisible = $false }
        @{ key = 'RawDetails';    label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'jobs_total';    label = 'Active/Queued Jobs';   value = $res.Data.TotalJobs;        unit = 'jobs';     severity = 'info' }
        @{ key = 'jobs_error';    label = 'Errored/Blocked Jobs'; value = $res.Data.ErrorJobs;        unit = 'jobs';     severity = if ($res.Data.ErrorJobs -gt 0) { 'error' } else { 'ok' } }
        @{ key = 'jobs_stuck';    label = "Stuck Jobs (>${StuckThresholdMinutes}m)"; value = $res.Data.StuckJobs; unit = 'jobs'; severity = if ($res.Data.StuckJobs -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'printers_busy'; label = 'Queues With Jobs';     value = $res.Data.PrintersWithJobs; unit = 'printers'; severity = 'info' }
        @{ key = 'spool_mb';      label = 'Total Spool Size';     value = $res.Data.TotalSizeMB;      unit = 'MB';       severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.2-print-jobs' -Category 'Print Management' -SubCategory 'Print Jobs & Queue Activity' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.2-print-jobs' -Category 'Print Management' -SubCategory 'Print Jobs & Queue Activity' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
