#Requires -Version 5.1
<#
.SYNOPSIS
    Inspects Credential Guard & Virtualization-Based Security (Win32_DeviceGuard) and DeviceGuard Operational events.
.NOTES
    Category:  06-Security / 6.2-Credential-Guard
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

    $vbsState = 'Unknown'
    $credGuardRunning = $false
    $hvciRunning = $false

    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbsState = switch ($dg.VirtualizationBasedSecurityStatus) {
            0 { 'Not Enabled' }
            1 { 'Enabled (Not Running)' }
            2 { 'Enabled & Running' }
            default { [string]$dg.VirtualizationBasedSecurityStatus }
        }
        $running = @($dg.SecurityServicesRunning)
        $configured = @($dg.SecurityServicesConfigured)
        $credGuardRunning = ($running -contains 1)
        $hvciRunning = ($running -contains 2)

        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($credGuardRunning) { 'Info' } else { 'Warning' }
            RecordType  = 'DeviceGuard State'
            EventId     = 0
            Source      = 'Win32_DeviceGuard'
            Summary     = "VBS: $vbsState | Credential Guard Running: $credGuardRunning | HVCI Running: $hvciRunning | Configured: [$($configured -join ',')] | Running: [$($running -join ',')]"
            RawMessage  = ($dg | Format-List | Out-String)
        })
    }
    catch {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = 'Warning'
            RecordType  = 'DeviceGuard State'
            EventId     = 0
            Source      = 'Win32_DeviceGuard'
            Summary     = "Unable to query Win32_DeviceGuard: $($_.Exception.Message)"
            RawMessage  = $_.Exception.Message
        })
    }

    $dgEvents = 0
    foreach ($logName in @('Microsoft-Windows-DeviceGuard/Operational', 'Microsoft-Windows-Lsa/Operational')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $dgEvents++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'DeviceGuard/LSA Event'
                    EventId     = $ev.Id
                    Source      = $ev.ProviderName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows             = @($out.ToArray() | Select-Object -First $Max)
        VbsState         = $vbsState
        CredGuardRunning = $credGuardRunning
        HvciRunning      = $hvciRunning
        DgEvents         = $dgEvents
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
        @{ key = 'vbs_status';       label = 'VBS Status';       value = $res.Data.VbsState; unit = ''; severity = 'info' }
        @{ key = 'credential_guard'; label = 'Credential Guard'; value = if ($res.Data.CredGuardRunning) { 'Running' } else { 'Off' }; unit = ''; severity = if ($res.Data.CredGuardRunning) { 'ok' } else { 'warning' } }
        @{ key = 'hvci_status';      label = 'HVCI';             value = if ($res.Data.HvciRunning) { 'Running' } else { 'Off' };      unit = ''; severity = if ($res.Data.HvciRunning) { 'ok' } else { 'info' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.2-credential-guard' -Category 'Security' -SubCategory 'Credential Guard' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.2-credential-guard' -Category 'Security' -SubCategory 'Credential Guard' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
