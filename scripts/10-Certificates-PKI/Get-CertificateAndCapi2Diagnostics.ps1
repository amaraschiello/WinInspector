#Requires -Version 5.1
<#
.SYNOPSIS
    Audits LocalMachine certificates (expired & expiring within threshold) plus CAPI2 Operational errors (revocation/TLS/chain failures).
.NOTES
    Category:  10-Certificates-PKI
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
    [ValidateRange(1, 365)]
    [int]$ExpiringWithinDays = 45,

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 72,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250,

    [Parameter()]
    [switch]$QueryAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$effectiveMax = if ($QueryAll) { 2147483647 } else { $MaxResults }
Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($ExpDays, $Hours, $Max)
    $now = Get-Date
    $warnCutoff = $now.AddDays($ExpDays)
    $startTime = $now.AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $expiredCount = 0
    $expiringCount = 0

    $certs = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue
    foreach ($c in $certs) {
        $daysLeft = [math]::Round(($c.NotAfter - $now).TotalDays, 0)
        $status = if ($c.NotAfter -lt $now) { $expiredCount++; 'Expired' }
                  elseif ($c.NotAfter -le $warnCutoff) { $expiringCount++; 'Expiring Soon' }
                  else { 'Valid' }
        $sev = switch ($status) { 'Expired' { 'Critical' } 'Expiring Soon' { 'Warning' } default { 'Info' } }

        $out.Add([PSCustomObject]@{
            TimeCreated = $c.NotAfter.ToUniversalTime().ToString('o')
            Severity    = $sev
            RecordType  = 'Certificate'
            Subject     = $c.Subject
            Issuer      = $c.Issuer
            Status      = "$status ($daysLeft d)"
            Thumbprint  = $c.Thumbprint
            EventId     = 0
            Summary     = "$status | Expires: $($c.NotAfter.ToString('yyyy-MM-dd')) | HasPrivateKey: $($c.HasPrivateKey) | Friendly: $($c.FriendlyName)"
            RawMessage  = "Subject: $($c.Subject)`nIssuer: $($c.Issuer)`nThumbprint: $($c.Thumbprint)`nNotBefore: $($c.NotBefore)`nNotAfter: $($c.NotAfter)`nHasPrivateKey: $($c.HasPrivateKey)`nDNSNames: $($c.DnsNameList -join ', ')"
        })
    }

    $capiErrors = 0
    try {
        $logCfg = Get-WinEvent -ListLog 'Microsoft-Windows-CAPI2/Operational' -ErrorAction SilentlyContinue
        if ($logCfg -and -not $logCfg.IsEnabled) {
            $warns.Add("Microsoft-Windows-CAPI2/Operational log is currently disabled on this host (enable temporarily to capture TLS/CRL validation events).")
        }
        else {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CAPI2/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $capiErrors++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'CAPI2 Event'
                    Subject     = $ev.ProviderName
                    Issuer      = ''
                    Status      = $sev
                    Thumbprint  = ''
                    EventId     = $ev.Id
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        }
    } catch {}

    return [PSCustomObject]@{
        Rows          = @($out | Select-Object -First $Max)
        TotalCerts    = @($certs).Count
        ExpiredCount  = $expiredCount
        ExpiringCount = $expiringCount
        CapiErrors    = $capiErrors
        Warnings      = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($ExpiringWithinDays, $HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Expires / Time'; type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';       type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';           type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Status';      label = 'Status';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Subject';     label = 'Subject/Source'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Issuer';      label = 'Issuer';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Thumbprint';  label = 'Thumbprint';     type = 'string';   filterable = $true;  facet = $false; defaultVisible = $false }
        @{ key = 'EventId';     label = 'Event ID';       type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';        type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';   type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'total_certs';    label = 'Machine Certs';      value = $res.Data.TotalCerts;    unit = 'certs';  severity = 'info' }
        @{ key = 'expired_certs';  label = 'Expired Certs';      value = $res.Data.ExpiredCount;  unit = 'certs';  severity = if ($res.Data.ExpiredCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'expiring_certs'; label = "Expiring <=${ExpiringWithinDays}d"; value = $res.Data.ExpiringCount; unit = 'certs'; severity = if ($res.Data.ExpiringCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'capi2_errors';   label = 'CAPI2 Errors';       value = $res.Data.CapiErrors;    unit = 'events'; severity = if ($res.Data.CapiErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '10.1-certificates-pki' -Category 'Certificates & PKI' -SubCategory 'Certificates & CAPI2' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '10.1-certificates-pki' -Category 'Certificates & PKI' -SubCategory 'Certificates & CAPI2' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
