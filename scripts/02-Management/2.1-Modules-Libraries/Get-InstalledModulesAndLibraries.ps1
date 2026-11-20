#Requires -Version 5.1
<#
.SYNOPSIS
    Audits installed PowerShell modules, PackageManagement packages, and .NET/runtime libraries.
.NOTES
    Category:  02-Management / 2.1-Modules-Libraries
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [string]$NameFilter = '',
    [Parameter()] [ValidateRange(10, 2000)] [int]$MaxResults = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($FilterText, $Max)
    $out = New-Object System.Collections.Generic.List[object]

    $mods = @(Get-Module -ListAvailable -ErrorAction SilentlyContinue)
    $modCount = $mods.Count
    foreach ($m in $mods) {
        if ($FilterText -and $m.Name -notlike "*$FilterText*") { continue }
        $out.Add([PSCustomObject]@{
            Kind        = 'PowerShell Module'
            Name        = $m.Name
            Version     = [string]$m.Version
            ModuleType  = [string]$m.ModuleType
            Path        = $m.ModuleBase
            Summary     = "PS Module $($m.Name) v$($m.Version) ($($m.ModuleType))"
            RawMessage  = ($m | Format-List Name,Version,ModuleType,ModuleBase,Author,Description | Out-String)
        })
        if ($out.Count -ge $Max) { break }
    }

    if ($out.Count -lt $Max -and (Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        try {
            $pkgs = @(Get-Package -ErrorAction SilentlyContinue)
            foreach ($p in $pkgs) {
                if ($FilterText -and $p.Name -notlike "*$FilterText*") { continue }
                $out.Add([PSCustomObject]@{
                    Kind        = "Package ($($p.ProviderName))"
                    Name        = $p.Name
                    Version     = [string]$p.Version
                    ModuleType  = [string]$p.ProviderName
                    Path        = [string]$p.Source
                    Summary     = "$($p.ProviderName): $($p.Name) v$($p.Version)"
                    RawMessage  = ($p | Format-List Name,Version,ProviderName,Source,Status | Out-String)
                })
                if ($out.Count -ge $Max) { break }
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows     = $out.ToArray()
        ModCount = $modCount
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($NameFilter, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Kind';       label = 'Type';         type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';       label = 'Name';         type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Version';    label = 'Version';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'ModuleType'; label = 'Provider/Type';type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Path';       label = 'Path/Source';  type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'ps_modules';  label = 'Installed PS Modules'; value = $res.Data.ModCount; unit = 'modules'; severity = 'info' }
        @{ key = 'total_items'; label = 'Displayed Items';      value = $rows.Count;        unit = 'items';   severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.1-ps-modules-libraries' -Category 'Management' -SubCategory 'PowerShell Modules & Libraries' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.1-ps-modules-libraries' -Category 'Management' -SubCategory 'PowerShell Modules & Libraries' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
