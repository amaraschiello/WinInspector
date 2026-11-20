#Requires -Version 5.1
<#
.SYNOPSIS
    Audits AppIDSvc service state, AppLocker effective policy counts, and AppLocker block/audit events (8003, 8004, 8006, 8007, 8021, 8022).
.NOTES
    Category:  06-Security / 6.3-AppLocker
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/microsoft/AaronLocker
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

    $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'Missing' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'AppIDSvc State'
        EventId     = 0
        Channel     = 'Service'
        UserName    = ''
        FilePath    = ''
        Summary     = "Application Identity (AppIDSvc) Service Status: $svcState"
        RawMessage  = ($svc | Format-List | Out-String)
    })

    $blockedCount = 0
    $auditCount   = 0
    $channels = @(
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/Packaged app-Execution',
        'Microsoft-Windows-AppLocker/Packaged app-Deployment'
    )

    foreach ($ch in $channels) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $ch; Id = @(8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $isBlock = ($ev.Id -in @(8004, 8007, 8022, 8025))
                if ($isBlock) { $blockedCount++ } else { $auditCount++ }

                $m = @{}
                try {
                    $x = [xml]$ev.ToXml()
                    if ($x.Event.UserData.RuleAndFileData) {
                        $m['FilePath'] = [string]$x.Event.UserData.RuleAndFileData.FilePath
                    }
                } catch {}

                $user = if ($ev.UserId) { try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $ev.UserId.Value } } else { '' }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = if ($isBlock) { 'Error' } else { 'Warning' }
                    RecordType  = if ($isBlock) { 'Blocked' } else { 'Audited (Would Block)' }
                    EventId     = $ev.Id
                    Channel     = ($ch -replace '^Microsoft-Windows-AppLocker/', '')
                    UserName    = $user
                    FilePath    = [string]$m['FilePath']
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        SvcState     = $svcState
        BlockedCount = $blockedCount
        AuditCount   = $auditCount
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Action';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Channel';     label = 'Channel';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'FilePath';    label = 'File Path';    type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'appidsvc_state';    label = 'AppIDSvc';          value = $res.Data.SvcState;     unit = '';       severity = if ($res.Data.SvcState -eq 'Running') { 'ok' } else { 'info' } }
        @{ key = 'applocker_blocked'; label = 'Blocked Events';    value = $res.Data.BlockedCount; unit = 'events'; severity = if ($res.Data.BlockedCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'applocker_audit';   label = 'Audit Events';      value = $res.Data.AuditCount;   unit = 'events'; severity = if ($res.Data.AuditCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.3-applocker' -Category 'Security' -SubCategory 'AppLocker' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.3-applocker' -Category 'Security' -SubCategory 'AppLocker' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
