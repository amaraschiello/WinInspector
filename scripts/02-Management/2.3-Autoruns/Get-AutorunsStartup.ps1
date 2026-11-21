#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Autoruns: Registry Run/RunOnce, Startup folders, Boot/Logon Scheduled Tasks, and Auto-Start Services.
.NOTES
    Category:  02-Management / 2.3-Autoruns
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [ValidateRange(10, 2000)] [int]$MaxResults = 300,

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
    param($Max)
    $out = New-Object System.Collections.Generic.List[object]

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($rk in $runKeys) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $out.Add([PSCustomObject]@{
                Category   = 'Registry Run/RunOnce'
                Trigger    = 'User Logon / Startup'
                Name       = $p.Name
                Command    = [string]$p.Value
                Location   = $rk
                State      = 'Enabled'
                Summary    = "$($p.Name) -> $($p.Value)"
                RawMessage = "Registry: $rk`nName: $($p.Name)`nCommand: $($p.Value)"
            })
        }
    }

    # Startup Folders
    $startupDirs = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($sd in $startupDirs) {
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $sd -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                Category   = 'Startup Folder'
                Trigger    = 'User Logon'
                Name       = $f.Name
                Command    = $f.FullName
                Location   = $sd
                State      = 'Enabled'
                Summary    = "Startup item: $($f.Name)"
                RawMessage = $f.FullName
            })
        }
    }

    # Boot / Logon Scheduled Tasks
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' })
        foreach ($t in $tasks) {
            $trigTypes = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '
            if ($trigTypes -notmatch 'BootTrigger|LogonTrigger') { continue }
            $acts = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; '
            $out.Add([PSCustomObject]@{
                Category   = 'Scheduled Task'
                Trigger    = $trigTypes
                Name       = "$($t.TaskPath)$($t.TaskName)"
                Command    = $acts
                Location   = $t.TaskPath
                State      = [string]$t.State
                Summary    = "$($t.TaskName) [$trigTypes] -> $acts"
                RawMessage = ($t | Format-List TaskName,TaskPath,State,Author,Description | Out-String)
            })
            if ($out.Count -ge $Max) { break }
        }
    } catch {}

    # Auto-start Services
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue)) {
        if ($out.Count -ge $Max) { break }
        $out.Add([PSCustomObject]@{
            Category   = 'Auto Service'
            Trigger    = 'System Boot'
            Name       = $s.Name
            Command    = [string]$s.PathName
            Location   = [string]$s.StartName
            State      = [string]$s.State
            Summary    = "$($s.DisplayName) ($($s.State)) -> $($s.PathName)"
            RawMessage = ($s | Format-List Name,DisplayName,State,StartMode,StartName,PathName | Out-String)
        })
    }

    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)

    $schema = @(
        @{ key = 'Category';   label = 'Category';     type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Trigger';    label = 'Trigger';      type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';       label = 'Entry Name';   type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'State';      label = 'State';        type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Command';    label = 'Image / Cmd';  type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Location';   label = 'Location';     type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'autorun_total'; label = 'Startup / Autorun Entries'; value = $rows.Count; unit = 'entries'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.3-autoruns' -Category 'Management' -SubCategory 'Autoruns & Startup Analysis' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.3-autoruns' -Category 'Management' -SubCategory 'Autoruns & Startup Analysis' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
