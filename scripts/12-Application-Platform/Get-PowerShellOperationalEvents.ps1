#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Microsoft-Windows-PowerShell/Operational and PowerShellCore/Operational for script/module errors and execution policy status.
.NOTES
    Category:  12-Application-Platform / 12.3-PowerShell
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

    $execPol = try { [string](Get-ExecutionPolicy -ErrorAction SilentlyContinue) } catch { 'Unknown' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        Channel     = 'Host Config'
        EventId     = 0
        UserName    = ''
        Summary     = "PSVersion: $($PSVersionTable.PSVersion) | ExecutionPolicy: $execPol"
        RawMessage  = ($PSVersionTable | Out-String) + "`nExecutionPolicy: $execPol"
    })

    $errCount = 0
    foreach ($logName in @('Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational', 'Windows PowerShell')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $errCount++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $user = if ($ev.UserId) { try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $ev.UserId.Value } } else { '' }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    Channel     = $logName
                    EventId     = $ev.Id
                    UserName    = $user
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows     = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        ExecPol  = $execPol
        ErrCount = $errCount
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Channel';     label = 'Log Channel';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'ps_exec_policy'; label = 'Execution Policy'; value = $res.Data.ExecPol;  unit = '';       severity = 'info' }
        @{ key = 'ps_errors';      label = 'PS Errors/Warns';  value = $res.Data.ErrCount; unit = 'events'; severity = if ($res.Data.ErrCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '12.3-powershell' -Category 'Application Platform' -SubCategory 'PowerShell Operational' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '12.3-powershell' -Category 'Application Platform' -SubCategory 'PowerShell Operational' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
