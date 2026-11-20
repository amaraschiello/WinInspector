#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Component Store health (read-only DISM /CheckHealth), recent CBS.log WRP/corruption entries, and Windows Reliability Monitor records.
.NOTES
    Category:  22-Recovery-Maintenance
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

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    # 1. Read-only DISM Component Store CheckHealth
    $compHealth = 'Unknown'
    try {
        $dismOut = (& dism.exe /Online /Cleanup-Image /CheckHealth 2>&1) -join "`n"
        if ($dismOut -match 'No component store corruption detected') { $compHealth = 'Healthy' }
        elseif ($dismOut -match 'repairable') { $compHealth = 'Repairable Corruption' }
        elseif ($dismOut -match 'error|elevated') { $compHealth = 'Check Requires Elevation' }
        else { $compHealth = 'Checked' }

        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($compHealth -eq 'Repairable Corruption') { 'Critical' } elseif ($compHealth -eq 'Check Requires Elevation') { 'Warning' } else { 'Info' }
            RecordType  = 'DISM CheckHealth'
            Source      = 'DISM'
            ProductName = 'Component Store'
            Summary     = "Component Store State: $compHealth"
            RawMessage  = $dismOut
        })
    }
    catch {
        $warns.Add("DISM CheckHealth note: $($_.Exception.Message)")
    }

    # 2. Recent CBS.log Error / Corrupt / Cannot repair lines (tail last 400 lines)
    $cbsErrors = 0
    $cbsPath = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    if (Test-Path -LiteralPath $cbsPath) {
        try {
            $lines = Get-Content -LiteralPath $cbsPath -Tail 400 -ErrorAction Stop | Where-Object { $_ -match 'Cannot repair member file|CSI Payload File Missing|Corrupt|Failed to|HRESULT' } | Select-Object -Last 40
            foreach ($line in $lines) {
                $cbsErrors++
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($line -match 'Cannot repair|Corrupt') { 'Error' } else { 'Warning' }
                    RecordType  = 'CBS.log Finding'
                    Source      = 'SFC / CBS'
                    ProductName = 'WRP'
                    Summary     = if ($line.Length -gt 200) { $line.Substring(0, 197) + '...' } else { $line }
                    RawMessage  = $line
                })
            }
        }
        catch {
            $warns.Add("Could not read CBS.log: $($_.Exception.Message)")
        }
    }

    # 3. Reliability Monitor Records (Application / Windows Failures)
    $relFailCount = 0
    try {
        $relRecs = Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop |
            Where-Object { $_.TimeGenerated -ge $startTime } |
            Sort-Object TimeGenerated -Descending |
            Select-Object -First 100
        foreach ($r in $relRecs) {
            $relFailCount++
            $out.Add([PSCustomObject]@{
                TimeCreated = $r.TimeGenerated.ToUniversalTime().ToString('o')
                Severity    = 'Warning'
                RecordType  = 'Reliability Record'
                Source      = $r.SourceName
                ProductName = $r.ProductName
                Summary     = "$($r.ProductName): $($r.Message)"
                RawMessage  = ($r | Format-List | Out-String)
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        CompHealth   = $compHealth
        CbsErrors    = $cbsErrors
        RelFailCount = $relFailCount
        Warnings     = $warns.ToArray()
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
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProductName'; label = 'Component';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dism_health';      label = 'Component Store';  value = $res.Data.CompHealth;   unit = '';        severity = if ($res.Data.CompHealth -eq 'Healthy') { 'ok' } elseif ($res.Data.CompHealth -like '*Corruption*') { 'critical' } else { 'info' } }
        @{ key = 'cbs_findings';     label = 'CBS.log Findings'; value = $res.Data.CbsErrors;    unit = 'lines';   severity = if ($res.Data.CbsErrors -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'reliability_recs'; label = 'Reliability Recs'; value = $res.Data.RelFailCount; unit = 'records'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '22.1-sfc-dism' -Category 'Recovery & Maintenance' -SubCategory 'SFC, DISM & Reliability' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '22.1-sfc-dism' -Category 'Recovery & Maintenance' -SubCategory 'SFC, DISM & Reliability' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
