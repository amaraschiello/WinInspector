#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Automatic Windows Services that are stopped plus Service Control Manager crash/failure events (7000, 7001, 7009, 7023, 7024, 7031, 7034).
.NOTES
    Category:  08-Windows-Services
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
    [int]$HoursBack = 72,

    [Parameter()]
    [string]$ServiceFilter = '',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $SvcFilter, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    $stoppedAuto = 0
    foreach ($s in $services) {
        if (-not [string]::IsNullOrWhiteSpace($SvcFilter)) {
            if ($s.Name -notlike "*$SvcFilter*" -and $s.DisplayName -notlike "*$SvcFilter*") { continue }
        }
        else {
            # Default: surface Auto-start services that are NOT Running
            if (-not ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running')) { continue }
        }

        if ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running') { $stoppedAuto++ }
        $sev = if ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running') { 'Error' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Service State'
            ServiceName = $s.Name
            DisplayName = $s.DisplayName
            State       = "$($s.State) ($($s.StartMode))"
            RunAsUser   = $s.StartName
            EventId     = 0
            Summary     = "Service '$($s.DisplayName)' ($($s.Name)) is $($s.State) [StartMode=$($s.StartMode), Account=$($s.StartName)]"
            RawMessage  = ($s | Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ExitCode | Format-List | Out-String)
        })
    }

    $scmIds = @(7000, 7001, 7009, 7022, 7023, 7024, 7031, 7034)
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Service Control Manager'
        Id           = $scmIds
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    $scmErrCount = 0
    foreach ($ev in $evs) {
        $svcName = ''
        try {
            $x = [xml]$ev.ToXml()
            $p1 = $x.Event.EventData.Data | Select-Object -First 1
            if ($p1) { $svcName = if ($p1 -is [System.Xml.XmlElement]) { $p1.InnerText } else { [string]$p1 } }
        } catch {}

        if (-not [string]::IsNullOrWhiteSpace($SvcFilter) -and $svcName -notlike "*$SvcFilter*" -and $ev.Message -notlike "*$SvcFilter*") { continue }

        $scmErrCount++
        $sev = if ($ev.Id -in @(7031, 7034, 7000, 7001, 7009)) { 'Critical' } else { 'Error' }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'SCM Event'
            ServiceName = $svcName
            DisplayName = $svcName
            State       = "Event $($ev.Id)"
            RunAsUser   = ''
            EventId     = $ev.Id
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{
        Rows         = @($out | Select-Object -First $Max)
        StoppedAuto  = $stoppedAuto
        ScmErrCount  = $scmErrCount
        TotalSvc     = @($services).Count
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $ServiceFilter, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';          type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ServiceName'; label = 'Service';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';       label = 'State/Event';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RunAsUser';   label = 'Log On As';     type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'total_services';    label = 'Total Services';      value = $res.Data.TotalSvc;    unit = 'svcs';   severity = 'info' }
        @{ key = 'stopped_auto_svcs'; label = 'Stopped Auto Svcs';   value = $res.Data.StoppedAuto; unit = 'svcs';   severity = if ($res.Data.StoppedAuto -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'scm_failures';      label = 'SCM Crash/Fail Evts'; value = $res.Data.ScmErrCount; unit = 'events'; severity = if ($res.Data.ScmErrCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '8.1-windows-services' -Category 'Windows Services' -SubCategory 'Service Control Manager' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '8.1-windows-services' -Category 'Windows Services' -SubCategory 'Service Control Manager' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
