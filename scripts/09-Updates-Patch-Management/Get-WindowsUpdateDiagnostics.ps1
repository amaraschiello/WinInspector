#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows Update Client events (19, 20, 25), accurate pending reboot flags
    (CBS, WU, ComputerRename, SCCM), WSUS registry settings, and recent HotFixes.
.NOTES
    Category:  09-Updates-Patch-Management
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
    [ValidateRange(1, 2160)]
    [int]$HoursBack = 720,

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

    # Accurate Pending Reboot Check (excludes noisy/non-reboot PendingFileRenameOperations)
    $pendingReasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $pendingReasons.Add('CBS RebootPending')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress') {
        $pendingReasons.Add('CBS RebootInProgress')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $pendingReasons.Add('WU RebootRequired')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting') {
        $pendingReasons.Add('WU PostRebootReporting')
    }

    # Pending Computer Rename
    try {
        $actName = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
        $pendName = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
        if ($actName -and $pendName -and ($actName -ne $pendName)) {
            $pendingReasons.Add("ComputerRename ($actName -> $pendName)")
        }
    } catch {}

    # SCCM / MECM Client SDK Pending Reboot (if SCCM agent is installed)
    try {
        $ccmReboot = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -MethodName 'DetermineIfRebootPending' -ErrorAction Stop
        if ($ccmReboot -and ($ccmReboot.RebootPending -or $ccmReboot.IsHardRebootPending)) {
            $pendingReasons.Add('SCCM/MECM Client RebootPending')
        }
    } catch {}

    # Inspect PendingFileRenameOperations as informational only (routine temp/spooler/app renames do NOT require an OS reboot)
    $pfrEntries = @()
    try {
        $pfr = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($pfr -and $pfr.PSObject.Properties['PendingFileRenameOperations'] -and $null -ne $pfr.PendingFileRenameOperations) {
            $pfrEntries = @($pfr.PendingFileRenameOperations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
    } catch {}

    $rebootPending = ($pendingReasons.Count -gt 0)

    # WSUS Configuration
    $wuKey = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $wsusServer = if ($wuKey -and $wuKey.PSObject.Properties['WUServer'] -and $wuKey.WUServer) { $wuKey.WUServer } else { 'Windows Update (Direct / Not Configured via GPO)' }

    $pfrNote = if ($pfrEntries.Count -gt 0) { " | Queued File Renames (Info): $($pfrEntries.Count) entry(s)" } else { '' }
    $pfrDetail = if ($pfrEntries.Count -gt 0) { "`nPendingFileRenameOperations (Informational - does not by itself require reboot):`n" + (($pfrEntries | Select-Object -First 20) -join "`n") } else { '' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($rebootPending) { 'Warning' } else { 'Info' }
        RecordType  = 'Update Status'
        EventId     = 0
        KbOrSource  = 'System State'
        Status      = if ($rebootPending) { 'Reboot Pending' } else { 'No Pending Reboot' }
        Summary     = "WSUS: $wsusServer | Pending Reboot: $(if ($rebootPending) { $pendingReasons.ToArray() -join ', ' } else { 'No' })$pfrNote"
        RawMessage  = "WSUS Server: $wsusServer`nRebootPending: $rebootPending`nReasons: $($pendingReasons.ToArray() -join ', ')$pfrDetail"
    })

    # Recent HotFixes
    $hotfixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 20)
    foreach ($hf in $hotfixes) {
        $dt = if ($hf.InstalledOn) { ([datetime]$hf.InstalledOn).ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }
        $out.Add([PSCustomObject]@{
            TimeCreated = $dt
            Severity    = 'Info'
            RecordType  = 'Installed HotFix'
            EventId     = 0
            KbOrSource  = $hf.HotFixID
            Status      = $hf.Description
            Summary     = "$($hf.HotFixID) ($($hf.Description)) installed by $($hf.InstalledBy)"
            RawMessage  = ($hf | Format-List | Out-String)
        })
    }

    # WindowsUpdateClient Operational Events
    $failCount = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
        Id        = @(19, 20, 25, 31)
        StartTime = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        if ($ev.Id -in @(20, 25, 31)) { $failCount++ }
        $sev = switch ($ev.Id) { 20 { 'Error' } 25 { 'Error' } 31 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'WU Client Event'
            EventId     = $ev.Id
            KbOrSource  = $ev.ProviderName
            Status      = if ($ev.Id -eq 19) { 'Installed' } elseif ($ev.Id -eq 20) { 'Install Failed' } else { "Event $($ev.Id)" }
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows          = @($out.ToArray() | Select-Object -First $Max)
        RebootPending = $rebootPending
        FailCount     = $failCount
        HotFixCount   = $hotfixes.Count
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
        @{ key = 'KbOrSource';  label = 'KB / Source';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Status';      label = 'Status';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'reboot_pending'; label = 'Pending Reboot';     value = if ($res.Data.RebootPending) { 'Yes' } else { 'No' }; unit = '';       severity = if ($res.Data.RebootPending) { 'warning' } else { 'ok' } }
        @{ key = 'wu_failures';    label = 'Update Failures';    value = $res.Data.FailCount;                                  unit = 'events'; severity = if ($res.Data.FailCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'recent_hotfix';  label = 'Recent HotFixes';    value = $res.Data.HotFixCount;                                unit = 'KBs';    severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '9.1-windows-update' -Category 'Updates & Patch Management' -SubCategory 'Windows Update & WSUS' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '9.1-windows-update' -Category 'Updates & Patch Management' -SubCategory 'Windows Update & WSUS' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
