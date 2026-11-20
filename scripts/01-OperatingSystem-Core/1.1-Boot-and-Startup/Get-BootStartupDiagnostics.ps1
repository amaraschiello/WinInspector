#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Boot & Startup diagnostics (BIOS/UEFI, Secure Boot, TPM, Kernel-Boot & Driver init events).
.NOTES
    Category:  01-OperatingSystem-Core / 1.1-Boot-and-Startup
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

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    # OS & Firmware snapshot
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $lastBoot = if ($os) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { (Get-Date).ToUniversalTime().ToString('o') }

    $secureBoot = 'Unknown'
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBoot = if (Confirm-SecureBootUEFI) { 'Enabled' } else { 'Disabled' }
        }
    }
    catch { $secureBoot = 'Unsupported/Legacy BIOS' }

    $tpmStatus = 'Not Present'
    try {
        $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $tpmStatus = "Present (Enabled=$($tpm.IsEnabled_InitialValue), Activated=$($tpm.IsActivated_InitialValue), Spec=$($tpm.SpecVersion))"
        }
    }
    catch { $tpmStatus = 'Access Denied / Unavailable' }

    $out.Add([PSCustomObject]@{
        TimeCreated = $lastBoot
        Severity    = 'Info'
        Category    = 'Boot State'
        LogSource   = 'BIOS / Firmware'
        EventId     = 0
        Component   = if ($bios) { "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)" } else { 'Unknown' }
        Summary     = "Last Boot: $lastBoot | Secure Boot: $secureBoot | TPM: $tpmStatus"
        RawMessage  = "OS: $($os.Caption) $($os.Version)`nLastBootUpTime: $lastBoot`nBIOS: $($bios.SMBIOSBIOSVersion)`nSecureBoot: $secureBoot`nTPM: $tpmStatus"
    })

    # Kernel-Boot Operational & System boot/driver events
    $channels = @(
        @{ Log = 'Microsoft-Windows-Kernel-Boot/Operational'; Levels = @(1, 2, 3, 4); MaxPerLog = [math]::Min($Max, 100) }
        @{ Log = 'System'; Providers = @('Microsoft-Windows-Kernel-Boot', 'Microsoft-Windows-Kernel-General', 'Service Control Manager', 'Microsoft-Windows-Kernel-PnP'); Levels = @(1, 2, 3); MaxPerLog = $Max }
    )

    foreach ($ch in $channels) {
        try {
            $f = @{ LogName = $ch.Log; StartTime = $startTime }
            if ($ch.ContainsKey('Providers')) { $f['ProviderName'] = $ch.Providers }
            if ($ch.ContainsKey('Levels'))    { $f['Level'] = $ch.Levels }
            $evs = Get-WinEvent -FilterHashtable $f -MaxEvents $ch.MaxPerLog -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '(No message)' }
                $firstLine = ($msg -split "`r?`n")[0]
                if ($firstLine.Length -gt 200) { $firstLine = $firstLine.Substring(0, 197) + '...' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    Category    = if ($ch.Log -like '*Kernel-Boot*') { 'Kernel-Boot' } else { 'System Boot/Driver' }
                    LogSource   = $ev.ProviderName
                    EventId     = $ev.Id
                    Component   = $ev.LogName
                    Summary     = $firstLine
                    RawMessage  = $msg
                })
            }
        }
        catch {
            $warns.Add("Could not read $($ch.Log): $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        Rows       = @($out | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        SecureBoot = $secureBoot
        Warnings   = $warns.ToArray()
    }
}

$fallbackRpc = {
    param($Target, $Cred, $Proto, $Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $evParams = @{ ComputerName = $Target; FilterHashtable = @{ LogName = 'System'; Level = @(1, 2, 3); StartTime = $startTime }; MaxEvents = $Max; ErrorAction = 'SilentlyContinue' }
    if ($null -ne $Cred) { $evParams['Credential'] = $Cred }
    $evs = Get-WinEvent @evParams
    foreach ($ev in $evs) {
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '(No message)' }
        $firstLine = ($msg -split "`r?`n")[0]
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            Category    = 'System Boot/Driver'
            LogSource   = $ev.ProviderName
            EventId     = $ev.Id
            Component   = $ev.LogName
            Summary     = $firstLine
            RawMessage  = $msg
        })
    }
    return [PSCustomObject]@{ Rows = $out.ToArray(); SecureBoot = 'N/A (RPC)'; Warnings = @() }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults) -FallbackScriptBlock $fallbackRpc
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }

    $rows = @($res.Data.Rows)
    $errCount  = @($rows | Where-Object { $_.Severity -in @('Critical', 'Error') }).Count
    $warnCount = @($rows | Where-Object { $_.Severity -eq 'Warning' }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';   type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';    type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Category';    label = 'Area';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';    type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogSource';   label = 'Source';      type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Component';   label = 'Component';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'boot_events';   label = 'Boot / Startup Records'; value = $rows.Count;          unit = 'records'; severity = 'info' }
        @{ key = 'boot_errors';   label = 'Errors / Critical';      value = $errCount;            unit = 'events';  severity = if ($errCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'boot_warnings'; label = 'Warnings';               value = $warnCount;           unit = 'events';  severity = if ($warnCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'secure_boot';   label = 'Secure Boot';            value = $res.Data.SecureBoot; unit = '';        severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '1.1-boot-startup' -Category 'Operating System & Core System' -SubCategory 'Boot & Startup' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '1.1-boot-startup' -Category 'Operating System & Core System' -SubCategory 'Boot & Startup' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
