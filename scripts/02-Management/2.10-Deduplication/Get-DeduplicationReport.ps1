#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Windows Data Deduplication volume status, savings rate, and calculates total raw logical
    storage required if deduplication were not enabled.
.NOTES
    Category:  02-Management / 2.10-Deduplication
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    $out = New-Object System.Collections.Generic.List[object]
    $totSavedGB = 0.0
    $totUsedGB  = 0.0
    $totRawGB   = 0.0

    if (-not (Get-Command Get-DedupVolume -ErrorAction SilentlyContinue)) {
        $out.Add([PSCustomObject]@{
            Severity       = 'Info'
            Volume         = 'N/A'
            Enabled        = 'False'
            CapacityGB     = 0
            UsedGB         = 0
            SavedSpaceGB   = 0
            RawWithoutDedupGB = 0
            SavingsRatePct = 0
            ExceedsCap     = 'N/A'
            Summary        = 'Data Deduplication feature/cmdlets (Deduplication module) not installed on this machine.'
            RawMessage     = 'Install FS-Data-Deduplication role feature on Windows Server to inspect deduplicated volumes.'
        })
        return [PSCustomObject]@{ Rows = $out.ToArray(); SavedGB = 0; RawGB = 0 }
    }

    $vols = @(Get-DedupVolume -ErrorAction SilentlyContinue)
    $statuses = @{}
    foreach ($st in @(Get-DedupStatus -ErrorAction SilentlyContinue)) {
        $statuses[[string]$st.Volume] = $st
    }

    foreach ($dv in $vols) {
        $volKey = [string]$dv.Volume
        $st = if ($statuses.ContainsKey($volKey)) { $statuses[$volKey] } else { $null }
        $capGB  = if ($dv.Capacity) { [math]::Round([double]$dv.Capacity / 1GB, 2) } else { 0 }
        $freeGB = if ($dv.FreeSpace) { [math]::Round([double]$dv.FreeSpace / 1GB, 2) } else { 0 }
        $usedGB = [math]::Round([Math]::Max(0, $capGB - $freeGB), 2)
        $savedGB = if ($st -and $st.SavedSpace) { [math]::Round([double]$st.SavedSpace / 1GB, 2) } elseif ($dv.SavingsSize) { [math]::Round([double]$dv.SavingsSize / 1GB, 2) } else { 0 }
        $rawNoDedupGB = [math]::Round($usedGB + $savedGB, 2)
        $ratePct = if ($st -and $null -ne $st.SavingsRate) { [math]::Round([double]$st.SavingsRate, 1) } elseif ($rawNoDedupGB -gt 0) { [math]::Round(($savedGB / $rawNoDedupGB) * 100, 1) } else { 0 }
        $exceeds = if ($capGB -gt 0 -and $rawNoDedupGB -gt $capGB) { "YES (+$([math]::Round($rawNoDedupGB - $capGB, 2)) GB over capacity)" } else { 'No' }

        $totSavedGB += $savedGB
        $totUsedGB  += $usedGB
        $totRawGB   += $rawNoDedupGB

        $out.Add([PSCustomObject]@{
            Severity          = if ($exceeds -like 'YES*') { 'Warning' } else { 'Info' }
            Volume            = $volKey
            Enabled           = [string]$dv.Enabled
            CapacityGB        = $capGB
            UsedGB            = $usedGB
            SavedSpaceGB      = $savedGB
            RawWithoutDedupGB = $rawNoDedupGB
            SavingsRatePct    = $ratePct
            ExceedsCap        = $exceeds
            Summary           = "$volKey | Used: $usedGB GB | Saved: $savedGB GB ($ratePct%) | Raw Without Dedup: $rawNoDedupGB GB / $capGB GB"
            RawMessage        = (($dv | Format-List | Out-String) + "`n" + ($st | Format-List | Out-String))
        })
    }

    return [PSCustomObject]@{
        Rows    = $out.ToArray()
        SavedGB = [math]::Round($totSavedGB, 2)
        RawGB   = [math]::Round($totRawGB, 2)
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';          label = 'Status';               type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Volume';            label = 'Volume';               type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Enabled';           label = 'Dedup Enabled';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'CapacityGB';        label = 'Capacity (GB)';        type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'UsedGB';            label = 'Actual Used (GB)';     type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'SavedSpaceGB';      label = 'Saved Space (GB)';     type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawWithoutDedupGB'; label = 'Raw w/o Dedup (GB)';   type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'SavingsRatePct';    label = 'Savings %';            type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'ExceedsCap';        label = 'Over Capacity w/o Dedup'; type = 'string'; filterable = $true; facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';        label = 'Full Details';         type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'dedup_saved'; label = 'Total Dedup Savings';     value = $res.Data.SavedGB; unit = 'GB'; severity = 'ok' }
        @{ key = 'dedup_raw';   label = 'Total Raw w/o Dedup';     value = $res.Data.RawGB;   unit = 'GB'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.10-deduplication' -Category 'Management' -SubCategory 'Disk Deduplication & Raw Storage' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.10-deduplication' -Category 'Management' -SubCategory 'Disk Deduplication & Raw Storage' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
