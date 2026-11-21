#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows OS Licensing & Activation state (KMS/MAK/ADBA via SoftwareLicensingProduct) and Security-SPP Application events.
.NOTES
    Category:  19-Licensing-Activation
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
Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $statusLookup = @{
        0 = 'Unlicensed'
        1 = 'Licensed'
        2 = 'OOB Grace'
        3 = 'OOT Grace'
        4 = 'Non-Genuine Grace'
        5 = 'Notification'
        6 = 'Extended Grace'
    }

    $licState = 'Unknown'
    $prods = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue)
    foreach ($p in $prods) {
        $stName = if ($statusLookup.ContainsKey([int]$p.LicenseStatus)) { $statusLookup[[int]$p.LicenseStatus] } else { "Status $($p.LicenseStatus)" }
        $licState = $stName
        $sev = if ($p.LicenseStatus -eq 1) { 'Info' } elseif ($p.LicenseStatus -in @(2, 3, 6)) { 'Warning' } else { 'Critical' }
        $kms = if ($p.KeyManagementServiceMachine) { $p.KeyManagementServiceMachine } else { 'N/A (MAK/Retail/OEM)' }
        $graceDays = [math]::Round($p.GracePeriodRemaining / 1440, 1)

        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'License Status'
            EventId     = 0
            ProductName = $p.Name
            LicenseState = $stName
            Summary     = "$($p.Name) | Status: $stName | Channel: $($p.ProductKeyChannel) | KMS: $kms | GraceDays: $graceDays"
            RawMessage  = ($p | Select-Object Name, Description, LicenseStatus, ProductKeyChannel, PartialProductKey, KeyManagementServiceMachine, KeyManagementServicePort, GracePeriodRemaining | Format-List | Out-String)
        })
    }

    $sppErrs = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Microsoft-Windows-Security-SPP'
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $sppErrs++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated  = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity     = $sev
            RecordType   = 'Security-SPP Event'
            EventId      = $ev.Id
            ProductName  = $ev.ProviderName
            LicenseState = $sev
            Summary      = ($msg -split "`r?`n")[0]
            RawMessage   = $msg
        })
    }

    return [PSCustomObject]@{ Rows = @($out.ToArray() | Select-Object -First $Max); LicState = $licState; SppErrs = $sppErrs }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated';  label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';     label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';   label = 'Type';          type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';      label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ProductName';  label = 'Product/Src';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LicenseState'; label = 'License State'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';      label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';   label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'os_license_state'; label = 'Windows License'; value = $res.Data.LicState; unit = '';       severity = if ($res.Data.LicState -eq 'Licensed') { 'ok' } else { 'critical' } }
        @{ key = 'spp_errors';       label = 'SPP Warnings';    value = $res.Data.SppErrs;  unit = 'events'; severity = if ($res.Data.SppErrs -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '19.1-licensing' -Category 'Licensing & Activation' -SubCategory 'KMS / MAK / SPP' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '19.1-licensing' -Category 'Licensing & Activation' -SubCategory 'KMS / MAK / SPP' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
