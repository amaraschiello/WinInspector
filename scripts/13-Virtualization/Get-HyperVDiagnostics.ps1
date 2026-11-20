#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Hyper-V VM inventory, VM states, checkpoints, VMMS/Hypervisor Admin error events (gracefully reports if Hyper-V is absent).
.NOTES
    Category:  13-Virtualization / 13.1-Hyper-V
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/dschunk/windows-it-toolkit
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

    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    if (-not $vmms) {
        $warns.Add("Hyper-V Virtual Machine Management service (vmms) is not installed on '$env:COMPUTERNAME'.")
        return [PSCustomObject]@{ Rows = @(); Installed = $false; VmCount = 0; RunningVms = 0; HvErrors = 0; Warnings = $warns.ToArray() }
    }

    $vmCount = 0
    $runningVms = 0
    try {
        if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
            foreach ($vm in @(Get-VM -ErrorAction Stop)) {
                $vmCount++
                if ($vm.State -eq 'Running') { $runningVms++ }
                $sev = if ($vm.Status -ne 'Operating normally' -and $vm.State -eq 'Running') { 'Warning' } else { 'Info' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'Virtual Machine'
                    Name        = $vm.Name
                    State       = "$($vm.State) ($($vm.Status))"
                    EventId     = 0
                    Summary     = "VM '$($vm.Name)' | State: $($vm.State) | CPU: $($vm.ProcessorCount) | MemAssigned: $([math]::Round($vm.MemoryAssigned/1MB,0)) MB | Uptime: $($vm.Uptime)"
                    RawMessage  = ($vm | Select-Object Name, State, Status, CPUUsage, MemoryAssigned, Uptime, Generation, Version, ReplicationState | Format-List | Out-String)
                })
            }
        }
        else {
            $warns.Add("Hyper-V PowerShell module not loaded; showing VMMS/Hypervisor event logs only.")
        }
    }
    catch {
        $warns.Add("Could not query Hyper-V VMs: $($_.Exception.Message)")
    }

    $hvErrors = 0
    foreach ($logName in @('Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Hypervisor-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $hvErrors++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'Hyper-V Event'
                    Name        = $ev.ProviderName
                    State       = $sev
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows       = @($out.ToArray() | Select-Object -First $Max)
        Installed  = $true
        VmCount    = $vmCount
        RunningVms = $runningVms
        HvErrors   = $hvErrors
        Warnings   = $warns.ToArray()
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
        @{ key = 'Name';        label = 'VM / Source';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';       label = 'State';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'hv_installed'; label = 'Hyper-V Role';  value = if ($res.Data.Installed) { 'Installed' } else { 'Not Installed' }; unit = ''; severity = 'info' }
        @{ key = 'hv_vms';       label = 'Total VMs';     value = $res.Data.VmCount;    unit = 'VMs';    severity = 'info' }
        @{ key = 'hv_running';   label = 'Running VMs';   value = $res.Data.RunningVms; unit = 'VMs';    severity = 'info' }
        @{ key = 'hv_errors';    label = 'Hyper-V Errors';value = $res.Data.HvErrors;   unit = 'events'; severity = if ($res.Data.HvErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($res.Data.Installed) { 'Success' } else { 'Partial' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '13.1-hyper-v' -Category 'Virtualization' -SubCategory 'Hyper-V' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '13.1-hyper-v' -Category 'Virtualization' -SubCategory 'Hyper-V' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
