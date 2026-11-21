#Requires -Version 5.1
<#
.SYNOPSIS
    Audits IIS Websites, Application Pools, SSL Bindings, and WAS / W3SVC System error events.
    Gracefully reports if IIS is not installed on the target server.
.NOTES
    Category:  15-Web-Services / 15.1-IIS
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
    [int]$HoursBack = 72,

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
    $warns = New-Object System.Collections.Generic.List[string]

    $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if (-not $w3svc) {
        $warns.Add("IIS (W3SVC) is not installed on '$env:COMPUTERNAME'.")
        return [PSCustomObject]@{ Rows = @(); IisInstalled = $false; StoppedSites = 0; StoppedPools = 0; WasErrors = 0; Warnings = $warns.ToArray() }
    }

    $stoppedSites = 0
    $stoppedPools = 0

    try {
        if (Get-Module -ListAvailable -Name IISAdministration) {
            Import-Module IISAdministration -ErrorAction Stop
            foreach ($site in (Get-IISSite -ErrorAction SilentlyContinue)) {
                if ($site.State -ne 'Started') { $stoppedSites++ }
                $bindings = ($site.Bindings | ForEach-Object { "$($_.Protocol)://$($_.BindingInformation)" }) -join ', '
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($site.State -eq 'Started') { 'Info' } else { 'Error' }
                    RecordType  = 'IIS Website'
                    Name        = $site.Name
                    State       = [string]$site.State
                    EventId     = 0
                    Summary     = "Site '$($site.Name)' (ID $($site.Id)) is $($site.State) | Bindings: $bindings"
                    RawMessage  = "Name: $($site.Name)`nId: $($site.Id)`nState: $($site.State)`nBindings: $bindings"
                })
            }
            foreach ($pool in (Get-IISAppPool -ErrorAction SilentlyContinue)) {
                if ($pool.State -ne 'Started') { $stoppedPools++ }
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($pool.State -eq 'Started') { 'Info' } else { 'Critical' }
                    RecordType  = 'App Pool'
                    Name        = $pool.Name
                    State       = [string]$pool.State
                    EventId     = 0
                    Summary     = "AppPool '$($pool.Name)' is $($pool.State) | CLR: $($pool.ManagedRuntimeVersion) | Identity: $($pool.ProcessModel.IdentityType)"
                    RawMessage  = ($pool | Select-Object Name, State, ManagedRuntimeVersion, ManagedPipelineMode, AutoStart | Format-List | Out-String)
                })
            }
        }
        elseif (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($site in (Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue)) {
                if ($site.State -ne 'Started') { $stoppedSites++ }
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($site.State -eq 'Started') { 'Info' } else { 'Error' }
                    RecordType  = 'IIS Website'
                    Name        = $site.Name
                    State       = [string]$site.State
                    EventId     = 0
                    Summary     = "Site '$($site.Name)' (ID $($site.Id)) is $($site.State) | Path: $($site.PhysicalPath)"
                    RawMessage  = ($site | Format-List | Out-String)
                })
            }
            foreach ($pool in (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)) {
                if ($pool.State -ne 'Started') { $stoppedPools++ }
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($pool.State -eq 'Started') { 'Info' } else { 'Critical' }
                    RecordType  = 'App Pool'
                    Name        = $pool.Name
                    State       = [string]$pool.State
                    EventId     = 0
                    Summary     = "AppPool '$($pool.Name)' is $($pool.State) | CLR: $($pool.managedRuntimeVersion)"
                    RawMessage  = ($pool | Format-List | Out-String)
                })
            }
        }
        else {
            $warns.Add("Neither IISAdministration nor WebAdministration PowerShell module is available; showing W3SVC/WAS events only.")
        }
    }
    catch {
        $warns.Add("Could not enumerate IIS Sites/Pools (may require Administrator rights): $($_.Exception.Message)")
    }

    $wasErrors = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-WAS', 'Microsoft-Windows-W3SVC', 'Microsoft-Windows-IIS-W3SVC-WP', 'HTTP')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $wasErrors++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'WAS/W3SVC Event'
            Name        = $ev.ProviderName
            State       = $sev
            EventId     = $ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows         = @($out | Select-Object -First $Max)
        IisInstalled = $true
        StoppedSites = $stoppedSites
        StoppedPools = $stoppedPools
        WasErrors    = $wasErrors
        Warnings     = $warns.ToArray()
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
        @{ key = 'Name';        label = 'Site/Pool/Src';type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';       label = 'State';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'iis_installed'; label = 'IIS Role';         value = if ($res.Data.IisInstalled) { 'Installed' } else { 'Not Installed' }; unit = ''; severity = 'info' }
        @{ key = 'stopped_sites'; label = 'Stopped Sites';    value = $res.Data.StoppedSites; unit = 'sites';  severity = if ($res.Data.StoppedSites -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'stopped_pools'; label = 'Stopped AppPools'; value = $res.Data.StoppedPools; unit = 'pools';  severity = if ($res.Data.StoppedPools -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'was_errors';    label = 'WAS/W3SVC Events'; value = $res.Data.WasErrors;    unit = 'events'; severity = if ($res.Data.WasErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($res.Data.IisInstalled) { 'Success' } else { 'Partial' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '15.1-iis' -Category 'Web Services' -SubCategory 'IIS' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '15.1-iis' -Category 'Web Services' -SubCategory 'IIS' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
