#Requires -Version 5.1
<#
.SYNOPSIS
    Audits User Profile Service (corrupt/temporary/roaming profiles), ProfileList .bak entries, and FSLogix Apps/Services/ODFC events.
.NOTES
    Category:  07-User-Profiles
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/Big-Hat-Group-Inc/FSLogixRunbookTemplate
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
    [string]$UserName = '',

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
    param($Hours, $UserFilter, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $bakProfiles = 0
    $tempProfiles = 0

    $profKeys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue
    foreach ($pk in $profKeys) {
        $props = Get-ItemProperty -LiteralPath $pk.PSPath -ErrorAction SilentlyContinue
        $imgPath = [string]$props.ProfileImagePath
        if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and $imgPath -notlike "*$UserFilter*") { continue }

        $isBak  = ($pk.PSChildName -like '*.bak')
        $isTemp = ($imgPath -like '*\Users\TEMP*' -or ([int]$props.State -band 0x80))
        if ($isBak)  { $bakProfiles++ }
        if ($isTemp) { $tempProfiles++ }

        if ($isBak -or $isTemp) {
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = if ($isBak) { 'Error' } else { 'Warning' }
                RecordType  = if ($isBak) { 'Corrupt/Backup Profile (.bak)' } else { 'Temporary Profile' }
                EventId     = 0
                UserName    = $imgPath
                Source      = 'ProfileList Registry'
                Summary     = "SID $($pk.PSChildName) -> $imgPath (State=$($props.State))"
                RawMessage  = ($props | Format-List | Out-String)
            })
        }
    }

    # User Profile Service Events (Application + Operational)
    $profEvents = 0
    $appEvs = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Microsoft-Windows-User Profiles Service'
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue
    foreach ($ev in $appEvs) {
        if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and $ev.Message -notlike "*$UserFilter*") { continue }
        $profEvents++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'User Profile Event'
            EventId     = $ev.Id
            UserName    = if ($ev.UserId) { try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $ev.UserId.Value } } else { '' }
            Source      = $ev.ProviderName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    # FSLogix Operational Logs (if installed)
    $fslogixSvc = Get-Service -Name frxsvc -ErrorAction SilentlyContinue
    $fslogixState = if ($fslogixSvc) { [string]$fslogixSvc.Status } else { 'Not Installed' }
    if ($fslogixSvc) {
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($fslogixSvc.Status -eq 'Running') { 'Info' } else { 'Error' }
            RecordType  = 'FSLogix Service'
            EventId     = 0
            UserName    = ''
            Source      = 'frxsvc'
            Summary     = "FSLogix Apps Services (frxsvc): $($fslogixSvc.Status)"
            RawMessage  = ($fslogixSvc | Format-List | Out-String)
        })
        foreach ($fLog in @('Microsoft-FSLogix-Apps/Operational', 'Microsoft-FSLogix-Apps/Admin', 'Microsoft-FSLogix-CloudCache/Operational')) {
            try {
                $evs = Get-WinEvent -FilterHashtable @{ LogName = $fLog; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
                foreach ($ev in $evs) {
                    if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and $ev.Message -notlike "*$UserFilter*") { continue }
                    $profEvents++
                    $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                    $msg = if ($ev.Message) { $ev.Message } else { '' }
                    $out.Add([PSCustomObject]@{
                        TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                        Severity    = $sev
                        RecordType  = 'FSLogix Event'
                        EventId     = $ev.Id
                        UserName    = ''
                        Source      = $ev.ProviderName
                        Summary     = ($msg -split "`r?`n")[0]
                        RawMessage  = $msg
                    })
                }
            } catch {}
        }
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        BakProfiles  = $bakProfiles
        TempProfiles = $tempProfiles
        ProfEvents   = $profEvents
        FslogixState = $fslogixState
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $UserName, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User/Path';    type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'bak_profiles';   label = '.bak Profiles';   value = $res.Data.BakProfiles;  unit = 'profiles'; severity = if ($res.Data.BakProfiles -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'temp_profiles';  label = 'Temp Profiles';   value = $res.Data.TempProfiles; unit = 'profiles'; severity = if ($res.Data.TempProfiles -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'profile_events'; label = 'Profile Errors';  value = $res.Data.ProfEvents;   unit = 'events';   severity = if ($res.Data.ProfEvents -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'fslogix_svc';    label = 'FSLogix Service'; value = $res.Data.FslogixState; unit = '';         severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '7.1-user-profiles' -Category 'User Profiles' -SubCategory 'Profiles & FSLogix' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '7.1-user-profiles' -Category 'User Profiles' -SubCategory 'Profiles & FSLogix' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
