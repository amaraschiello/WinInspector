#Requires -Version 5.1
<#
.SYNOPSIS
    Lists Volume Shadow Copies (Win32_ShadowCopy), Shadow Storage allocation, and VSS Writer states.
.NOTES
    Category:  02-Management / 2.11-Shadow-Copies
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    $out = New-Object System.Collections.Generic.List[object]
    $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue)
    foreach ($sh in $shadows) {
        $inst = if ($sh.InstallDate) { $sh.InstallDate.ToUniversalTime().ToString('o') } else { '' }
        $out.Add([PSCustomObject]@{
            Kind       = 'Shadow Copy'
            Volume     = [string]$sh.VolumeName
            Id         = [string]$sh.ID
            CreatedUtc = $inst
            State      = [string]$sh.State
            Summary    = "Shadow Copy on $($sh.VolumeName) | Created: $inst | Device: $($sh.DeviceObject)"
            RawMessage = ($sh | Format-List | Out-String)
        })
    }

    $storRaw = (& vssadmin.exe list shadowstorage 2>&1 | Out-String)
    $out.Add([PSCustomObject]@{
        Kind       = 'Shadow Storage'
        Volume     = 'All Volumes'
        Id         = 'vssadmin list shadowstorage'
        CreatedUtc = ''
        State      = 'Report'
        Summary    = ($storRaw -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 4) -join ' | '
        RawMessage = $storRaw
    })

    $writersRaw = (& vssadmin.exe list writers 2>&1 | Out-String)
    $out.Add([PSCustomObject]@{
        Kind       = 'VSS Writers'
        Volume     = 'System'
        Id         = 'vssadmin list writers'
        CreatedUtc = ''
        State      = if ($writersRaw -match 'No error') { 'Healthy' } else { 'Check' }
        Summary    = 'VSS Writers health report (click row for full writer states)'
        RawMessage = $writersRaw
    })

    return [PSCustomObject]@{ Rows = $out.ToArray(); ShadowCount = $shadows.Count }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Kind';       label = 'Type';         type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Volume';     label = 'Volume';       type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Id';         label = 'Shadow ID';    type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'CreatedUtc'; label = 'Created (UTC)';type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'State';      label = 'State';        type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'vss_count'; label = 'Shadow Copies'; value = $res.Data.ShadowCount; unit = 'snapshots'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.11-shadow-copies' -Category 'Management' -SubCategory 'Volume Shadow Copies (VSS)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.11-shadow-copies' -Category 'Management' -SubCategory 'Volume Shadow Copies (VSS)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
