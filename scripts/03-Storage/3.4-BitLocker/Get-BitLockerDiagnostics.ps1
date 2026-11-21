#Requires -Version 5.1
<#
.SYNOPSIS
    Audits BitLocker volume protection/encryption state, key protectors, TPM presence, and BitLocker-API/Driver events.
.NOTES
    Category:  03-Storage / 3.4-BitLocker
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
    [int]$MaxResults = 250,

    [Parameter()]
    [switch]$QueryAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$effectiveMax = if ($QueryAll) { 2147483647 } else { $MaxResults }
Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $encryptedCount = 0
    $suspendedCount = 0

    try {
        $vols = @(Get-BitLockerVolume -ErrorAction Stop)
        foreach ($v in $vols) {
            if ($v.VolumeStatus -like '*Encrypted*') { $encryptedCount++ }
            if ($v.ProtectionStatus -eq 'Off' -and $v.VolumeStatus -like '*Encrypted*') { $suspendedCount++ }
            $protectors = ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
            $sev = if ($v.ProtectionStatus -eq 'Off' -and $v.VolumeStatus -like '*Encrypted*') { 'Warning' } elseif ($v.LockStatus -eq 'Locked') { 'Critical' } else { 'Info' }
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'BitLocker Volume'
                MountPoint  = $v.MountPoint
                Status      = "$($v.VolumeStatus) / Prot:$($v.ProtectionStatus)"
                EventId     = 0
                Summary     = "$($v.MountPoint) | $($v.VolumeStatus) ($($v.EncryptionPercentage)%) | Protection: $($v.ProtectionStatus) | Protectors: $protectors"
                RawMessage  = ($v | Select-Object MountPoint, VolumeStatus, ProtectionStatus, LockStatus, EncryptionMethod, EncryptionPercentage | Format-List | Out-String) + "`nKeyProtectors: $protectors"
            })
        }
    }
    catch {
        $warns.Add("BitLocker module/status unavailable (may require Administrator rights or BitLocker feature installed): $($_.Exception.Message)")
    }

    $blEvents = 0
    foreach ($logName in @('Microsoft-Windows-BitLocker/BitLocker Management', 'Microsoft-Windows-BitLocker-DrivePreparationTool/Admin')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $blEvents++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'BitLocker Event'
                    MountPoint  = $ev.ProviderName
                    Status      = $sev
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows           = @($out.ToArray() | Select-Object -First $Max)
        EncryptedCount = $encryptedCount
        SuspendedCount = $suspendedCount
        BlEvents       = $blEvents
        Warnings       = $warns.ToArray()
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
        @{ key = 'MountPoint';  label = 'Volume/Src';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Status';      label = 'Status';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'bl_encrypted'; label = 'Encrypted Volumes';    value = $res.Data.EncryptedCount; unit = 'vols';   severity = 'info' }
        @{ key = 'bl_suspended'; label = 'Protection Suspended'; value = $res.Data.SuspendedCount; unit = 'vols';   severity = if ($res.Data.SuspendedCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'bl_events';    label = 'BitLocker Warnings';   value = $res.Data.BlEvents;       unit = 'events'; severity = if ($res.Data.BlEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($warnings.Count -gt 0 -and $rows.Count -eq 0) { 'Partial' } else { 'Success' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '3.4-bitlocker' -Category 'Storage' -SubCategory 'BitLocker' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '3.4-bitlocker' -Category 'Storage' -SubCategory 'BitLocker' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
