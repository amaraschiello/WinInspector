#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Intune MDM enrollment registry state, IntuneManagementExtension service, and DeviceManagement-Enterprise-Diagnostics-Provider events.
.NOTES
    Category:  14-Cloud-and-Identity / 14.2-Intune
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/NullSpace-BitCradle/Intune_PowerShell_Scripts
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

    $ime = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
    $imeState = if ($ime) { [string]$ime.Status } else { 'Not Installed' }

    $enrollments = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    } | Where-Object {
        ($_.PSObject.Properties['ProviderID'] -and $_.ProviderID) -or ($_.PSObject.Properties['UPN'] -and $_.UPN)
    })

    $enrolledStatus = if ($enrollments.Count -gt 0) {
        $pidVal = if ($enrollments[0].PSObject.Properties['ProviderID']) { $enrollments[0].ProviderID } else { 'MDM' }
        "Enrolled ($pidVal)"
    } else { 'Not Enrolled' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'MDM / IME Status'
        EventId     = 0
        Source      = 'Intune/MDM'
        Summary     = "MDM Status: $enrolledStatus | IntuneManagementExtension: $imeState"
        RawMessage  = ($enrollments | Format-List | Out-String)
    })

    $mdmErrors = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
            Level     = @(1, 2, 3)
            StartTime = $startTime
        } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $mdmErrors++
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'MDM Admin Event'
                EventId     = $ev.Id
                Source      = $ev.ProviderName
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows           = @($out.ToArray() | Select-Object -First $Max)
        EnrolledStatus = $enrolledStatus
        ImeState       = $imeState
        MdmErrors      = $mdmErrors
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
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
        @{ key = 'mdm_enrolled'; label = 'MDM Enrollment'; value = $res.Data.EnrolledStatus; unit = '';       severity = 'info' }
        @{ key = 'ime_service';  label = 'IME Service';    value = $res.Data.ImeState;       unit = '';       severity = 'info' }
        @{ key = 'mdm_errors';   label = 'MDM Warnings';   value = $res.Data.MdmErrors;      unit = 'events'; severity = if ($res.Data.MdmErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '14.2-intune' -Category 'Cloud & Identity' -SubCategory 'Intune / MDM' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '14.2-intune' -Category 'Cloud & Identity' -SubCategory 'Intune / MDM' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
