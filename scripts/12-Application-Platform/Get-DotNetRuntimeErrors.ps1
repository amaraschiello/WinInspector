#Requires -Version 5.1
<#
.SYNOPSIS
    Queries .NET Runtime CLR crashes (1026), unhandled exceptions (1023/1025), and installed .NET Framework / .NET runtime versions.
.NOTES
    Category:  12-Application-Platform / 12.1-DotNet
    Protocols: WinRM, RPC
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

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    $fxVersion = if ($ndp -and $ndp.Version) { "$($ndp.Version) (Release $($ndp.Release))" } else { 'Unknown' }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        RecordType  = '.NET Inventory'
        EventId     = 0
        Source      = '.NET Framework 4.x'
        Application = 'CLR'
        Summary     = ".NET Framework v4 Full: $fxVersion"
        RawMessage  = ($ndp | Format-List | Out-String)
    })

    $clrErrors = 0
    $evs = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = @('.NET Runtime', '.NET Runtime Optimization Service', 'ASP.NET*')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $evs) {
        $clrErrors++
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $appLine = ($msg -split "`r?`n" | Where-Object { $_ -like 'Application:*' } | Select-Object -First 1)
        $appName = if ($appLine) { ($appLine -replace '^Application:\s*', '').Trim() } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'CLR Event'
            EventId     = $ev.Id
            Source      = $ev.ProviderName
            Application = $appName
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    return [PSCustomObject]@{ Rows = @($out.ToArray() | Select-Object -First $Max); FxVersion = $fxVersion; ClrErrors = $clrErrors }
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
        @{ key = 'Source';      label = 'Provider';     type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Application'; label = 'Application';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dotnet_fx_ver'; label = '.NET 4.x Version'; value = $res.Data.FxVersion; unit = '';       severity = 'info' }
        @{ key = 'dotnet_errors'; label = '.NET Errors';      value = $res.Data.ClrErrors; unit = 'events'; severity = if ($res.Data.ClrErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '12.1-dotnet' -Category 'Application Platform' -SubCategory '.NET Runtime' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '12.1-dotnet' -Category 'Application Platform' -SubCategory '.NET Runtime' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
