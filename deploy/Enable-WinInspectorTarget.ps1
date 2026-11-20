#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Onboards a target Windows Server for remote management by WinInspector.
.DESCRIPTION
    Enables WinRM, verifies firewall rules for WinRM and Remote Event Log Management,
    and optionally grants least-privilege diagnostic group memberships to a designated
    WinInspector service/gMSA account or admin group.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DiagnosticPrincipal = '',

    [Parameter()]
    [switch]$EnableWinRmHttps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable WinRM & Firewall Rules')) {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -ErrorAction SilentlyContinue
    Write-Host "WinRM and Remote Event Log firewall rules enabled on $env:COMPUTERNAME." -ForegroundColor Green
}

if ($EnableWinRmHttps -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure WinRM HTTPS Listener')) {
    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $cert) {
        Write-Warning "No valid Server Authentication certificate found in Cert:\LocalMachine\My for WinRM HTTPS."
    }
    else {
        $fqdn = [System.Net.Dns]::GetHostEntry('').HostName
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } -ValueSet @{ Hostname = $fqdn; CertificateThumbprint = $cert.Thumbprint } -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'WinRM HTTPS-In (WinInspector)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Write-Host "WinRM HTTPS listener configured on port 5986." -ForegroundColor Green
    }
}

if (-not [string]::IsNullOrWhiteSpace($DiagnosticPrincipal)) {
    $groups = @(
        'Event Log Readers',
        'Performance Monitor Users',
        'Distributed COM Users',
        'WinRMRemoteWMIUsers__'
    )
    foreach ($grp in $groups) {
        if (Get-LocalGroup -Name $grp -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess("$grp", "Add $DiagnosticPrincipal")) {
                try {
                    Add-LocalGroupMember -Group $grp -Member $DiagnosticPrincipal -ErrorAction Stop
                    Write-Host "Added '$DiagnosticPrincipal' to '$grp'." -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -notmatch 'already a member') {
                        Write-Warning "Could not add '$DiagnosticPrincipal' to '$grp': $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}
