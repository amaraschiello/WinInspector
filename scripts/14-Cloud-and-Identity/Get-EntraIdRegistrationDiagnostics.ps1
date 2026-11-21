#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses Microsoft Entra ID (Azure AD) Join / Hybrid Join state via dsregcmd /status and User Device Registration events.
.NOTES
    Category:  14-Cloud-and-Identity / 14.1-Entra-ID
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/Azure-Samples/DSRegTool
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

    $dsregRaw = (& dsregcmd.exe /status 2>&1) -join "`n"
    $azureAdJoined = if ($dsregRaw -match 'AzureAdJoined\s*:\s*(\S+)') { $Matches[1] } else { 'Unknown' }
    $domainJoined  = if ($dsregRaw -match 'DomainJoined\s*:\s*(\S+)') { $Matches[1] } else { 'Unknown' }
    $tenantName    = if ($dsregRaw -match 'TenantName\s*:\s*(.+)') { $Matches[1].Trim() } else { '' }
    $prtStatus     = if ($dsregRaw -match 'AzureAdPrt\s*:\s*(\S+)') { $Matches[1] } else { 'Unknown' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'dsregcmd /status'
        EventId     = 0
        Source      = 'dsregcmd'
        Summary     = "AzureAdJoined: $azureAdJoined | DomainJoined: $domainJoined | AzureAdPrt: $prtStatus | Tenant: $tenantName"
        RawMessage  = $dsregRaw
    })

    $regErrors = 0
    foreach ($logName in @('Microsoft-Windows-User Device Registration/Admin', 'Microsoft-Windows-AAD/Operational')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $regErrors++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = if ($logName -like '*AAD*') { 'AAD Token Event' } else { 'Device Reg Event' }
                    EventId     = $ev.Id
                    Source      = $ev.ProviderName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows          = @($out.ToArray() | Select-Object -First $Max)
        AzureAdJoined = $azureAdJoined
        DomainJoined  = $domainJoined
        PrtStatus     = $prtStatus
        RegErrors     = $regErrors
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
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'entra_joined';  label = 'Entra Joined';   value = $res.Data.AzureAdJoined; unit = '';       severity = 'info' }
        @{ key = 'domain_joined'; label = 'Domain Joined';  value = $res.Data.DomainJoined;  unit = '';       severity = 'info' }
        @{ key = 'entra_prt';     label = 'AzureAdPrt';     value = $res.Data.PrtStatus;     unit = '';       severity = 'info' }
        @{ key = 'entra_errors';  label = 'Reg/AAD Errors'; value = $res.Data.RegErrors;     unit = 'events'; severity = if ($res.Data.RegErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '14.1-entra-id' -Category 'Cloud & Identity' -SubCategory 'Microsoft Entra ID' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '14.1-entra-id' -Category 'Cloud & Identity' -SubCategory 'Microsoft Entra ID' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
