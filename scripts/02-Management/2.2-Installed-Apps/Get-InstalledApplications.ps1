#Requires -Version 5.1
<#
.SYNOPSIS
    Reports installed applications using Registry/WMI native MSI/EXE uninstall keys and winget (when installed).
.NOTES
    Category:  02-Management / 2.2-Installed-Apps
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [string]$AppFilter = '',
    [Parameter()] [ValidateRange(10, 2000)] [int]$MaxResults = 400,

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
    param($FilterText, $Max)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $getProp = {
        param($obj, [string]$propName)
        $p = $obj.PSObject.Properties[$propName]
        if ($null -ne $p -and $null -ne $p.Value) { [string]$p.Value } else { '' }
    }

    $regPaths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x64/Native' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x86' }
    )

    foreach ($rp in $regPaths) {
        foreach ($item in @(Get-ItemProperty -Path $rp.Path -ErrorAction SilentlyContinue)) {
            $name = & $getProp $item 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($FilterText -and $name -notlike "*$FilterText*") { continue }
            $ver = & $getProp $item 'DisplayVersion'
            $key = "$name|$ver"
            if (-not $seen.Add($key)) { continue }

            $uninst = & $getProp $item 'UninstallString'
            $instType = if ($uninst -match 'msiexec') { 'MSI' } else { 'EXE / Native' }
            $pub = & $getProp $item 'Publisher'
            $dt  = & $getProp $item 'InstallDate'

            $out.Add([PSCustomObject]@{
                Source          = "Registry ($($rp.Arch))"
                InstallerType   = $instType
                Name            = $name
                Version         = $ver
                Publisher       = $pub
                InstallDate     = $dt
                Summary         = "$name $(if ($ver) { "v$ver" }) | $pub ($instType)"
                RawMessage      = ($item | Format-List DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString | Out-String)
            })
            if ($out.Count -ge $Max) { break }
        }
    }

    # Optional winget list (if available on host)
    $wingetExe = Get-Command winget.exe -ErrorAction SilentlyContinue
    $wingetCount = 0
    if ($wingetExe -and $out.Count -lt $Max) {
        try {
            $wgRaw = & $wingetExe.Source list --accept-source-agreements 2>$null
            foreach ($line in @($wgRaw)) {
                $ln = [string]$line
                if ([string]::IsNullOrWhiteSpace($ln) -or $ln -match '^[-\\\s/]+$' -or $ln -match '^Name\s+Id\s+Version') { continue }
                if ($FilterText -and $ln -notlike "*$FilterText*") { continue }
                $parts = @($ln.Trim() -split '\s{2,}')
                if ($parts.Count -ge 3) {
                    $wName = $parts[0]
                    $wId   = $parts[1]
                    $wVer  = $parts[2]
                    $wingetCount++
                    if ($seen.Add("$wName|$wVer")) {
                        $out.Add([PSCustomObject]@{
                            Source        = 'WinGet'
                            InstallerType = 'WinGet'
                            Name          = $wName
                            Version       = $wVer
                            Publisher     = $wId
                            InstallDate   = ''
                            Summary       = "WinGet: $wName ($wId) v$wVer"
                            RawMessage    = $ln
                        })
                    }
                }
                if ($out.Count -ge $Max) { break }
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows        = $out.ToArray()
        WingetAvail = ($null -ne $wingetExe)
        WingetCount = $wingetCount
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($AppFilter, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Source';        label = 'Source';         type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'InstallerType'; label = 'Installer';      type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';          label = 'Application';    type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Version';       label = 'Version';        type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Publisher';     label = 'Publisher / ID'; type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'InstallDate';   label = 'Install Date';   type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';       label = 'Summary';        type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';    label = 'Full Details';   type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'apps_total';   label = 'Installed Apps';   value = $rows.Count;                                        unit = 'apps'; severity = 'info' }
        @{ key = 'winget_avail'; label = 'WinGet Available'; value = $(if ($res.Data.WingetAvail) { 'Yes' } else { 'No' }); unit = '';     severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.2-installed-apps' -Category 'Management' -SubCategory 'Installed Applications (Winget & Native)' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.2-installed-apps' -Category 'Management' -SubCategory 'Installed Applications (Winget & Native)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
