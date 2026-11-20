#Requires -Version 5.1
<#
.SYNOPSIS
    Reports applied Local & Group Policy settings (gpresult /R, applied GPOs, and HKLM\SOFTWARE\Policies).
.NOTES
    Category:  02-Management / 2.6-Policy-Settings
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [ValidateRange(10, 2000)] [int]$MaxResults = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Max)
    $out = New-Object System.Collections.Generic.List[object]

    $gpRaw = (& gpresult.exe /R /SCOPE COMPUTER 2>&1 | Out-String)
    $out.Add([PSCustomObject]@{
        Source     = 'gpresult (/SCOPE COMPUTER)'
        KeyPath    = 'Computer RSoP'
        Setting    = 'Applied Computer Group Policy Summary'
        Value      = ($gpRaw -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 8) -join ' | '
        Summary    = 'Computer Group Policy RSoP Summary (click row for full gpresult output)'
        RawMessage = $gpRaw
    })

    $policyRoots = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
    )
    foreach ($root in $policyRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sub in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue)) {
            if ($out.Count -ge $Max) { break }
            $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
                $out.Add([PSCustomObject]@{
                    Source     = 'Policy Registry'
                    KeyPath    = $sub.Name
                    Setting    = $p.Name
                    Value      = [string]$p.Value
                    Summary    = "$($p.Name) = $($p.Value)"
                    RawMessage = "Key: $($sub.Name)`nSetting: $($p.Name)`nValue: $($p.Value)"
                })
                if ($out.Count -ge $Max) { break }
            }
        }
    }

    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)

    $schema = @(
        @{ key = 'Source';     label = 'Source';       type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Setting';    label = 'Policy/Item';  type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Value';      label = 'Value';        type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'KeyPath';    label = 'Registry/Path';type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'policy_entries'; label = 'Policy Settings Found'; value = $rows.Count; unit = 'settings'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.6-local-group-policy' -Category 'Management' -SubCategory 'Local & Group Policy Settings' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.6-local-group-policy' -Category 'Management' -SubCategory 'Local & Group Policy Settings' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
