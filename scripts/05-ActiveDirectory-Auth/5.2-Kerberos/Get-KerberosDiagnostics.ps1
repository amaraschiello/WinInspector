#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses Kerberos issues: System Kerberos errors (SPN, delegation, KDC), Security Kerberos ticket failures (4768, 4769, 4771), and Domain Secure Channel check.
.NOTES
    Category:  05-ActiveDirectory-Auth / 5.2-Kerberos
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
    [ValidateRange(1, 720)]
    [int]$HoursBack = 48,

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 300,

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
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $domainState = if ($cs -and $cs.PartOfDomain) { "Domain Joined ($($cs.Domain))" } else { "Workgroup ($($cs.Workgroup))" }
    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = 'Info'
        LogName     = 'System State'
        EventId     = 0
        UserName    = ''
        ClientIp    = ''
        ServiceSpn  = $domainState
        ErrorCode   = ''
        Summary     = "Computer Membership: $domainState"
        RawMessage  = "Computer: $($cs.Name)`nPartOfDomain: $($cs.PartOfDomain)`nDomain: $($cs.Domain)"
    })

    # System log Kerberos & Netlogon errors
    $sysEvs = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = @('Microsoft-Windows-Security-Kerberos', 'Kerberos', 'NETLOGON', 'KDC')
        Level        = @(1, 2, 3)
        StartTime    = $startTime
    } -MaxEvents $Max -ErrorAction SilentlyContinue

    foreach ($ev in $sysEvs) {
        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
        $msg = if ($ev.Message) { $ev.Message } else { '' }
        $out.Add([PSCustomObject]@{
            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity    = $sev
            LogName     = 'System'
            EventId     = $ev.Id
            UserName    = ''
            ClientIp    = ''
            ServiceSpn  = $ev.ProviderName
            ErrorCode   = ''
            Summary     = ($msg -split "`r?`n")[0]
            RawMessage  = $msg
        })
    }

    # Security log Kerberos failures (4768, 4769, 4771 with non-zero Status)
    try {
        $secEvs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4768, 4769, 4771); StartTime = $startTime } -MaxEvents $Max -ErrorAction Stop
        foreach ($ev in $secEvs) {
            $m = @{}
            try {
                $x = [xml]$ev.ToXml()
                foreach ($n in $x.Event.EventData.Data) {
                    if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
                }
            } catch {}

            $status = if ($m.ContainsKey('Status')) { $m['Status'] } else { '' }
            if ($ev.Id -in @(4768, 4769) -and ($status -eq '0x0' -or [string]::IsNullOrEmpty($status))) { continue }

            $ip = if ($m.ContainsKey('IpAddress')) { $m['IpAddress'] -replace '^::ffff:', '' } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = 'Error'
                LogName     = 'Security'
                EventId     = $ev.Id
                UserName    = [string]$m['TargetUserName']
                ClientIp    = $ip
                ServiceSpn  = [string]$m['ServiceName']
                ErrorCode   = $status
                Summary     = "Kerberos Event $($ev.Id) failed for '$($m['TargetUserName'])' (Status: $status)"
                RawMessage  = if ($ev.Message) { $ev.Message } else { '' }
            })
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $warns.Add("Security log Kerberos query note: $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{ Rows = @($out | Select-Object -First $Max); DomainState = $domainState; Warnings = $warns.ToArray() }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)
    $errCount = @($rows | Where-Object { $_.Severity -in @('Critical', 'Error') }).Count

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogName';     label = 'Log';          type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientIp';    label = 'Client IP';    type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ServiceSpn';  label = 'SPN/Provider'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ErrorCode';   label = 'Error Code';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'domain_state'; label = 'Domain State';    value = $res.Data.DomainState; unit = '';       severity = 'info' }
        @{ key = 'kerb_errors';  label = 'Kerberos Errors'; value = $errCount;             unit = 'events'; severity = if ($errCount -gt 0) { 'critical' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '5.2-kerberos' -Category 'Active Directory & Authentication' -SubCategory 'Kerberos' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '5.2-kerberos' -Category 'Active Directory & Authentication' -SubCategory 'Kerberos' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
