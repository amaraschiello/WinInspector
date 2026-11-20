#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows SmartScreen configuration and Microsoft-Windows-SmartScreen Operational events.
.NOTES
    Category:  06-Security / 6.5-SmartScreen
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

    $ssReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
    $ssPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
    $polLevel = if ($ssPol -and $ssPol.PSObject.Properties['ShellSmartScreenLevel']) { $ssPol.ShellSmartScreenLevel } else { $null }
    $polEnable = if ($ssPol -and $ssPol.PSObject.Properties['EnableSmartScreen']) { $ssPol.EnableSmartScreen } else { $null }
    $regVal = if ($ssReg -and $ssReg.PSObject.Properties['SmartScreenEnabled']) { $ssReg.SmartScreenEnabled } else { $null }
    $ssMode = if ($polLevel) { "Policy: $polLevel" } elseif ($regVal) { $regVal } else { 'Default/Unconfigured' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = 'SmartScreen Config'
        EventId     = 0
        Source      = 'Registry'
        Summary     = "SmartScreen Mode: $ssMode"
        RawMessage  = "SmartScreenEnabled: $regVal`nPolicy EnableSmartScreen: $polEnable`nPolicy Level: $polLevel"
    })

    $ssEvents = 0
    foreach ($logName in @('Microsoft-Windows-SmartScreen/Debug', 'Microsoft-Windows-Security-Mitigations/KernelMode', 'Microsoft-Windows-Security-Mitigations/UserMode')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3, 4); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $ssEvents++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = $logName
                    EventId     = $ev.Id
                    Source      = $ev.ProviderName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{ Rows = @($out.ToArray() | Select-Object -First $Max); SsMode = $ssMode; SsEvents = $ssEvents }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Channel/Type'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Source';      label = 'Source';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'smartscreen_mode';   label = 'SmartScreen Mode'; value = $res.Data.SsMode;   unit = '';       severity = 'info' }
        @{ key = 'smartscreen_events'; label = 'Mitigation Events';value = $res.Data.SsEvents; unit = 'events'; severity = if ($res.Data.SsEvents -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.5-smartscreen' -Category 'Security' -SubCategory 'SmartScreen & Mitigations' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.5-smartscreen' -Category 'Security' -SubCategory 'SmartScreen & Mitigations' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
