#Requires -Version 5.1
<#
.SYNOPSIS
    Inventories installed printer drivers (v3 vs v4), printer ports (TCP/IP, WSD, Local), printer assignments, and Point & Print security policies.
.NOTES
    Category:  06-Print-Management / 6.3-Drivers-Ports
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
    [ValidateSet('All', 'Drivers', 'Ports', 'Policies')]
    [string]$ViewScope = 'All',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Scope, $Max)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    # Map driver and port usage counts from configured printers
    $driverUsage = @{}
    $portUsage   = @{}
    try {
        foreach ($p in @(Get-Printer -ErrorAction SilentlyContinue)) {
            $d = [string]$p.DriverName
            $pt = [string]$p.PortName
            if (-not [string]::IsNullOrWhiteSpace($d)) {
                if ($driverUsage.ContainsKey($d)) { $driverUsage[$d]++ } else { $driverUsage[$d] = 1 }
            }
            if (-not [string]::IsNullOrWhiteSpace($pt)) {
                if ($portUsage.ContainsKey($pt)) { $portUsage[$pt]++ } else { $portUsage[$pt] = 1 }
            }
        }
    } catch {}

    $driverCount = 0
    $v3Count = 0
    $v4Count = 0
    $portCount = 0
    $wsdCount = 0

    # Point & Print Security Policy (PrintNightmare hardening check)
    if ($Scope -in @('All', 'Policies')) {
        $pnpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        $restrictAdmin = 'NotConfigured (Default=1 on patched OS)'
        $noWarningPrompt = 'NotConfigured'
        if (Test-Path -LiteralPath $pnpPath) {
            try {
                $pnp = Get-ItemProperty -LiteralPath $pnpPath -ErrorAction SilentlyContinue
                if ($null -ne $pnp.RestrictDriverInstallationToAdministrators) {
                    $restrictAdmin = [string]$pnp.RestrictDriverInstallationToAdministrators
                }
                if ($null -ne $pnp.NoWarningNoElevationOnInstall) {
                    $noWarningPrompt = [string]$pnp.NoWarningNoElevationOnInstall
                }
            } catch {}
        }
        $pnpSev = if ($restrictAdmin -eq '0' -or $noWarningPrompt -eq '1') { 'Warning' } else { 'Info' }
        $out.Add([PSCustomObject]@{
            Severity     = $pnpSev
            RecordType   = 'Point & Print Policy'
            Name         = 'PointAndPrint Hardening'
            VersionOrMon = "RestrictToAdmins=$restrictAdmin"
            AddressOrEnv = "NoWarningElevation=$noWarningPrompt"
            AssignedCnt  = 0
            Details      = "RestrictDriverInstallationToAdministrators=$restrictAdmin | NoWarningNoElevationOnInstall=$noWarningPrompt"
            RawDetails   = "Registry: $pnpPath`nRestrictDriverInstallationToAdministrators = $restrictAdmin`nNoWarningNoElevationOnInstall = $noWarningPrompt"
        })
    }

    if ($Scope -in @('All', 'Drivers')) {
        try {
            foreach ($drv in @(Get-PrinterDriver -ErrorAction Stop)) {
                $driverCount++
                $maj = if ($null -ne $drv.MajorVersion) { [int]$drv.MajorVersion } else { 0 }
                if ($maj -eq 3) { $v3Count++ } elseif ($maj -eq 4) { $v4Count++ }
                $dName = [string]$drv.Name
                $usedBy = if ($driverUsage.ContainsKey($dName)) { [int]$driverUsage[$dName] } else { 0 }
                $verStr = if ($null -ne $drv.DriverVersion) { [string]$drv.DriverVersion } else { '' }
                $envStr = [string]$drv.PrinterEnvironment
                $mfg    = [string]$drv.Manufacturer

                $out.Add([PSCustomObject]@{
                    Severity     = 'Info'
                    RecordType   = 'Printer Driver'
                    Name         = $dName
                    VersionOrMon = "v$maj ($verStr)"
                    AddressOrEnv = "$envStr | $mfg"
                    AssignedCnt  = $usedBy
                    Details      = "Type v$maj | Env: $envStr | Used by $usedBy printer(s) | Inf: $($drv.InfPath)"
                    RawDetails   = ($drv | Format-List * | Out-String)
                })
            }
        }
        catch {
            $warns.Add("Get-PrinterDriver failed: $($_.Exception.Message)")
        }
    }

    if ($Scope -in @('All', 'Ports')) {
        try {
            foreach ($prt in @(Get-PrinterPort -ErrorAction Stop)) {
                $portCount++
                $ptName = [string]$prt.Name
                $mon    = [string]$prt.PortMonitor
                $hostAddr = ''
                try { if ($null -ne $prt.PrinterHostAddress) { $hostAddr = [string]$prt.PrinterHostAddress } } catch {}
                if ($mon -match 'WSD') { $wsdCount++ }
                $usedBy = if ($portUsage.ContainsKey($ptName)) { [int]$portUsage[$ptName] } else { 0 }

                $portNum = ''
                try { if ($null -ne $prt.PortNumber) { $portNum = ":$($prt.PortNumber)" } } catch {}
                $addrInfo = if (-not [string]::IsNullOrWhiteSpace($hostAddr)) { "$hostAddr$portNum" } else { [string]$prt.Description }
                $sev = if ($mon -match 'WSD' -and $usedBy -gt 0) { 'Warning' } else { 'Info' }

                $out.Add([PSCustomObject]@{
                    Severity     = $sev
                    RecordType   = 'Printer Port'
                    Name         = $ptName
                    VersionOrMon = $mon
                    AddressOrEnv = $addrInfo
                    AssignedCnt  = $usedBy
                    Details      = "Monitor: $mon | Target: $addrInfo | Used by $usedBy printer(s)"
                    RawDetails   = ($prt | Format-List * | Out-String)
                })
            }
        }
        catch {
            $warns.Add("Get-PrinterPort failed: $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        Rows        = @($out.ToArray() | Select-Object -First $Max)
        DriverCount = $driverCount
        V3Count     = $v3Count
        V4Count     = $v4Count
        PortCount   = $portCount
        WsdCount    = $wsdCount
        Warnings    = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($ViewScope, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';     label = 'Severity';       type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';   label = 'Category';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';         label = 'Name';           type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'VersionOrMon'; label = 'Version / Monitor'; type = 'string'; filterable = $true; facet = $true;  defaultVisible = $true }
        @{ key = 'AddressOrEnv'; label = 'Target / Env';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'AssignedCnt';  label = 'Printers Using'; type = 'number';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Details';      label = 'Details';        type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawDetails';   label = 'Full Details';   type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'drivers_total'; label = 'Installed Drivers'; value = $res.Data.DriverCount; unit = 'drivers'; severity = 'info' }
        @{ key = 'drivers_v3_v4'; label = 'Driver Mix (v3/v4)'; value = "$($res.Data.V3Count) / $($res.Data.V4Count)"; unit = ''; severity = 'info' }
        @{ key = 'ports_total';   label = 'Configured Ports';  value = $res.Data.PortCount;   unit = 'ports';   severity = 'info' }
        @{ key = 'ports_wsd';     label = 'WSD Ports';         value = $res.Data.WsdCount;    unit = 'ports';   severity = if ($res.Data.WsdCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '6.3-drivers-ports' -Category 'Print Management' -SubCategory 'Printer Drivers, Ports & Point-and-Print' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '6.3-drivers-ports' -Category 'Print Management' -SubCategory 'Printer Drivers, Ports & Point-and-Print' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
