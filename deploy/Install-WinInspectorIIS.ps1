#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys WinInspector to IIS on a Windows Server central management host.
.DESCRIPTION
    Creates the IIS Application Pool, Website, copies web.config for either
    HttpPlatformHandler (default) or ARR Reverse Proxy, configures Windows Auth,
    and checks prerequisites (PowerShell 7, Pode module).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$SiteName = 'WinInspector',

    [Parameter()]
    [string]$PhysicalPath = 'C:\inetpub\WinInspector',

    [Parameter()]
    [ValidateSet('HttpPlatformHandler', 'ARR')]
    [string]$HostingMode = 'HttpPlatformHandler',

    [Parameter()]
    [int]$HttpsPort = 443,

    [Parameter()]
    [string]$HostHeader = '',

    [Parameter()]
    [string]$CertificateThumbprint = '',

    [Parameter()]
    [string]$ServiceAccount = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "=== WinInspector IIS Deployment ($HostingMode) ===" -ForegroundColor Cyan

# 1. Verify prerequisites
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    throw "IIS WebAdministration module not found. Install IIS Management Scripts and Tools first."
}
Import-Module WebAdministration

$pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) {
    Write-Warning "PowerShell 7 (pwsh.exe) not found in PATH. Install PowerShell 7 LTS before starting the site."
}
if (-not (Get-Module -ListAvailable -Name Pode)) {
    Write-Warning "Pode module is not installed. Run: Install-Module Pode -Scope AllUsers"
}

# 2. Ensure target path & logs folder exist
if (-not (Test-Path -LiteralPath $PhysicalPath)) {
    New-Item -Path $PhysicalPath -ItemType Directory -Force | Out-Null
}
New-Item -Path (Join-Path $PhysicalPath 'logs') -ItemType Directory -Force | Out-Null

# 3. Copy appropriate web.config
$repoRoot = Split-Path -Parent $PSScriptRoot
$templateName = if ($HostingMode -eq 'HttpPlatformHandler') { 'web.config.httpplatform' } else { 'web.config.arr' }
$templatePath = Join-Path $PSScriptRoot $templateName
$destWebConfig = Join-Path $PhysicalPath 'web.config'

$content = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
$content = $content.Replace('C:\inetpub\WinInspector', $PhysicalPath)
if ($pwshPath) {
    $content = $content.Replace('C:\Program Files\PowerShell\7\pwsh.exe', $pwshPath)
}
Set-Content -LiteralPath $destWebConfig -Value $content -Encoding UTF8
Write-Host "Wrote $destWebConfig from $templateName" -ForegroundColor Green

# 4. Create App Pool
if (-not (Test-Path "IIS:\AppPools\$SiteName")) {
    New-WebAppPool -Name $SiteName | Out-Null
}
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ''
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.loadUserProfile -Value $true
if (-not [string]::IsNullOrWhiteSpace($ServiceAccount)) {
    # Supports gMSA (e.g. CORP\gMSA-WinInspector$) with blank password
    Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.identityType -Value 3
    Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.userName -Value $ServiceAccount
    if ($ServiceAccount.EndsWith('$')) {
        Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.password -Value ''
    }
}

# 5. Create Website
if (-not (Test-Path "IIS:\Sites\$SiteName")) {
    $siteParams = @{
        Name            = $SiteName
        PhysicalPath    = $PhysicalPath
        ApplicationPool = $SiteName
        Port            = if ($CertificateThumbprint) { $HttpsPort } else { 8080 }
        Protocol        = if ($CertificateThumbprint) { 'https' } else { 'http' }
    }
    if ($HostHeader) { $siteParams['HostHeader'] = $HostHeader }
    New-Website @siteParams | Out-Null
}

if ($CertificateThumbprint) {
    $binding = Get-WebBinding -Name $SiteName -Protocol 'https'
    $binding.AddSslCertificate($CertificateThumbprint, 'My')
}

# 6. Configure Windows Auth (Disable Anonymous)
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Name enabled -Value $false -PSPath "IIS:\Sites\$SiteName"
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name enabled -Value $true -PSPath "IIS:\Sites\$SiteName"

Write-Host "`nDeployment complete!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Copy WinInspector folders (web/, server/, scripts/) into $PhysicalPath"
Write-Host "  2. If using Current User Kerberos Delegation, configure RBCD on target servers:"
Write-Host "     Set-ADComputer -Identity <TargetServer> -PrincipalsAllowedToDelegateToAccount <MgmtServerOrGMSA>"
Write-Host "  3. Restrict IIS Authorization Rules to your Admin AD Security Group."
