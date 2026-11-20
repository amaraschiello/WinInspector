#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-flight connectivity & protocol discovery probe for WinInspector.
.DESCRIPTION
    Resolves DNS/FQDN, probes WinRM (5986/5985), RPC (135), SMB (445),
    and collects basic OS/Domain/Uptime metadata from the target server.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ComputerName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')]
    [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()

if (-not (Test-WinInspectorHostName -ComputerName $ComputerName)) {
    [ordered]@{
        reachable           = $false
        targetServer        = $ComputerName
        error               = "Invalid server hostname or FQDN format."
        durationMs          = $sw.ElapsedMilliseconds
    } | ConvertTo-Json -Depth 5 -Compress
    return
}

$isLocal = Test-WinInspectorIsLocal -ComputerName $ComputerName

# 1. DNS Resolution
$dnsResolved = $false
$resolvedFqdn = $ComputerName
$ipAddresses = @()
try {
    if ($isLocal) {
        $entry = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName())
        $dnsResolved = $true
        $resolvedFqdn = $entry.HostName
        $ipAddresses = @($entry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
    }
    else {
        $entry = [System.Net.Dns]::GetHostEntry($ComputerName)
        $dnsResolved = $true
        $resolvedFqdn = $entry.HostName
        $ipAddresses = @($entry.AddressList | Where-Object { $_.AddressFamily -in @('InterNetwork', 'InterNetworkV6') } | ForEach-Object { $_.IPAddressToString })
    }
}
catch {
    $warnings.Add("DNS lookup failed for '$ComputerName': $($_.Exception.Message)")
}

# 2. Port probes
$probeHost = if ($isLocal) { '127.0.0.1' } else { $ComputerName }
$port5986 = Test-WinInspectorTcpPort -ComputerName $probeHost -Port 5986 -TimeoutMs 1200
$port5985 = Test-WinInspectorTcpPort -ComputerName $probeHost -Port 5985 -TimeoutMs 1200
$port135  = Test-WinInspectorTcpPort -ComputerName $probeHost -Port 135  -TimeoutMs 1200
$port445  = Test-WinInspectorTcpPort -ComputerName $probeHost -Port 445  -TimeoutMs 1200

# 3. OS Fingerprint via CIM/Local
$osCaption    = $null
$osVersion    = $null
$domain       = $null
$lastBootUtc  = $null
$uptimeHours  = $null
$authSuccess  = $false
$protocolUsed = 'None'
$authError    = $null

$cimBundle = $null
try {
    $cimBundle = New-WinInspectorCimSession -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol
    $protocolUsed = $cimBundle.ProtocolUsed

    $cimArgs = @{ ErrorAction = 'Stop' }
    if ($null -ne $cimBundle.Session) {
        $cimArgs['CimSession'] = $cimBundle.Session
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem @cimArgs
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem @cimArgs

    $osCaption   = $os.Caption
    $osVersion   = "$($os.Version) (Build $($os.BuildNumber))"
    $domain      = $cs.Domain
    $lastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    $uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    $authSuccess = $true
}
catch {
    $authError = $_.Exception.Message
    $warnings.Add("OS/CIM query failed: $authError")
}
finally {
    if ($null -ne $cimBundle -and $null -ne $cimBundle.Session) {
        try { Remove-CimSession -CimSession $cimBundle.Session -ErrorAction SilentlyContinue } catch {}
    }
}

$recommended = if ($isLocal -and $null -eq $Credential) {
    'Local'
}
elseif ($port5986) { 'WinRM-HTTPS' }
elseif ($port5985) { 'WinRM-HTTP' }
elseif ($port135)  { 'CIM-DCOM' }
else               { 'None' }

$sw.Stop()

$executedAs = if ($null -ne $Credential) {
    $Credential.UserName
} else {
    try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
}

[ordered]@{
    reachable           = ($authSuccess -or $port5986 -or $port5985 -or $port135)
    authSuccess         = $authSuccess
    targetServer        = $ComputerName
    resolvedFqdn        = $resolvedFqdn
    ipAddresses         = $ipAddresses
    isLocal             = $isLocal
    dnsResolved         = $dnsResolved
    protocols           = [ordered]@{
        winrmHttps = $port5986
        winrmHttp  = $port5985
        rpcDcom    = $port135
        smb        = $port445
    }
    recommendedProtocol = $recommended
    protocolUsed        = $protocolUsed
    osInfo              = [ordered]@{
        caption     = $osCaption
        version     = $osVersion
        domain      = $domain
        lastBootUtc = $lastBootUtc
        uptimeHours = $uptimeHours
    }
    executedAs          = $executedAs
    warnings            = $warnings.ToArray()
    error               = $authError
    durationMs          = $sw.ElapsedMilliseconds
} | ConvertTo-Json -Depth 5 -Compress
