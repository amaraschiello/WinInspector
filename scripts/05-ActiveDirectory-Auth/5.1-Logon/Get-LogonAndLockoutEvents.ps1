#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Windows Security Event Log for Logon Failures (4625), Account Lockouts (4740),
    Kerberos Pre-Auth Failures (4771), NTLM Validation (4776), and optional Successful Logons (4624).
    Supports identical full XML + Message parsing across both WinRM and RPC fallback.
.NOTES
    Category:  05-ActiveDirectory-Auth / 5.1-Logon
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
    [int]$HoursBack = 24,

    [Parameter()]
    [string]$UserName = '',

    [Parameter()]
    [string]$ClientHost = '',

    [Parameter()]
    [string[]]$EventIds = @('4625', '4740', '4771', '4776'),

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxResults = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$intIds = @($EventIds | ForEach-Object { [int]$_ })

# Shared parser ScriptBlock so WinRM (remote) and RPC (local) produce identical parsed columns
$parseEventsCore = {
    param($RawEvents, $Max, $UserFilter, $ClientFilter)

    $statusLookup = @{
        '0x0'        = 'Succeeded'
        '0xc0000064' = 'User name does not exist'
        '0xc000006a' = 'Bad password'
        '0xc000006d' = 'Bad username or password'
        '0xc000006e' = 'Account restriction'
        '0xc000006f' = 'Logon outside authorized hours'
        '0xc0000070' = 'Workstation restriction'
        '0xc0000071' = 'Password expired'
        '0xc0000072' = 'Account disabled'
        '0xc0000133' = 'Clock skew too great'
        '0xc000015b' = 'Logon type not granted'
        '0xc0000193' = 'Account expired'
        '0xc0000224' = 'Password must be changed'
        '0xc0000234' = 'Account locked out'
        '0x6'        = 'Kerberos Principal Unknown'
        '0xc'        = 'Kerberos Policy/Account Restriction'
        '0x12'       = 'Kerberos Client Credentials Revoked/Locked/Disabled'
        '0x17'       = 'Kerberos Password Expired'
        '0x18'       = 'Kerberos Pre-Auth Failed (Bad Password)'
        '0x25'       = 'Kerberos Clock Skew Too Great'
    }

    $logonTypeLookup = @{
        '2'  = '2 (Interactive)'
        '3'  = '3 (Network)'
        '4'  = '4 (Batch)'
        '5'  = '5 (Service)'
        '7'  = '7 (Unlock)'
        '8'  = '8 (NetworkCleartext)'
        '9'  = '9 (NewCredentials)'
        '10' = '10 (RemoteInteractive/RDP)'
        '11' = '11 (CachedInteractive)'
    }

    $out = New-Object System.Collections.Generic.List[object]

    foreach ($ev in @($RawEvents)) {
        $m = @{}
        try {
            $x = [xml]$ev.ToXml()
            if ($x -and $x.Event -and $x.Event.EventData -and $x.Event.EventData.Data) {
                foreach ($n in $x.Event.EventData.Data) {
                    if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) {
                        $m[$n.GetAttribute('Name')] = $n.InnerText
                    }
                }
            }
        } catch {}

        $msg = if ($ev.Message) { $ev.Message } else { '' }

        # Fallback regex extraction from Message text if XML attributes are absent
        if ($msg) {
            if (-not $m.ContainsKey('TargetUserName') -or [string]::IsNullOrWhiteSpace($m['TargetUserName'])) {
                if ($msg -match '(?m)(?:Logon Account|Account Name)\s*:\s*([^\r\n]+)') {
                    $acctMatch = $Matches[1].Trim()
                    if ($acctMatch -and $acctMatch -ne '-') { $m['TargetUserName'] = $acctMatch }
                }
            }
            if (-not $m.ContainsKey('IpAddress') -and -not $m.ContainsKey('ClientAddress')) {
                if ($msg -match '(?m)(?:Client Address|Source Network Address)\s*:\s*([^\r\n]+)') {
                    $ipMatch = $Matches[1].Trim()
                    if ($ipMatch -and $ipMatch -ne '-') { $m['IpAddress'] = $ipMatch }
                }
            }
            if (-not $m.ContainsKey('WorkstationName') -and -not $m.ContainsKey('Workstation')) {
                if ($msg -match '(?m)(?:Source Workstation|Workstation Name|Caller Computer Name)\s*:\s*([^\r\n]+)') {
                    $wsMatch = $Matches[1].Trim()
                    if ($wsMatch -and $wsMatch -ne '-') { $m['WorkstationName'] = $wsMatch }
                }
            }
            if (-not $m.ContainsKey('LogonType') -and $msg -match '(?m)Logon Type\s*:\s*(\d+)') {
                $m['LogonType'] = $Matches[1].Trim()
            }
            if (-not $m.ContainsKey('Status') -and -not $m.ContainsKey('ErrorCode')) {
                if ($msg -match '(?m)(?:Failure Code|Error Code|Status)\s*:\s*(0x[0-9a-fA-F]+)') {
                    $m['Status'] = $Matches[1].Trim()
                }
            }
            if (-not $m.ContainsKey('AuthenticationPackageName') -and -not $m.ContainsKey('PackageName')) {
                if ($msg -match '(?m)Authentication Package\s*:\s*([^\r\n]+)') {
                    $m['PackageName'] = $Matches[1].Trim()
                }
            }
        }

        # User
        $rawUser = if ($m.ContainsKey('TargetUserName')) { [string]$m['TargetUserName'] } else { '' }
        $rawDom  = if ($m.ContainsKey('TargetDomainName')) { [string]$m['TargetDomainName'] } else { '' }
        $user = if ($ev.Id -eq 4740) {
            $rawUser
        } elseif ($rawUser -and $rawDom -and $rawDom -ne '-' -and $rawUser -notlike '*\*') {
            "$rawDom\$rawUser"
        } else {
            $rawUser
        }

        # Client / Caller Workstation
        $client = ''
        if ($ev.Id -eq 4740 -and $rawDom -and $rawDom -ne '-') {
            $client = $rawDom
        }
        else {
            foreach ($k in @('WorkstationName', 'Workstation', 'CallerComputerName')) {
                if ($m.ContainsKey($k) -and $m[$k] -and $m[$k] -ne '-') { $client = [string]$m[$k]; break }
            }
        }

        # Source IP
        $ip = ''
        foreach ($k in @('IpAddress', 'ClientAddress')) {
            if ($m.ContainsKey($k) -and $m[$k] -and $m[$k] -ne '-') {
                $ip = ([string]$m[$k]).Trim() -replace '^::ffff:', ''
                break
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and ($user -notlike "*$UserFilter*")) { continue }
        if (-not [string]::IsNullOrWhiteSpace($ClientFilter) -and ($client -notlike "*$ClientFilter*" -and $ip -notlike "*$ClientFilter*")) { continue }

        # Logon Type / Auth Flow
        $ltRaw = if ($m.ContainsKey('LogonType')) { ([string]$m['LogonType']).Trim() } else { '' }
        $logonType = if ($ltRaw -and $logonTypeLookup.ContainsKey($ltRaw)) {
            $logonTypeLookup[$ltRaw]
        } elseif ($ltRaw) {
            $ltRaw
        } elseif ($ev.Id -eq 4771) {
            'Kerberos Pre-Auth'
        } elseif ($ev.Id -eq 4776) {
            'NTLM Validation'
        } elseif ($ev.Id -eq 4740) {
            'Account Lockout'
        } else { '' }

        # Status / Failure Code
        $codeRaw = ''
        if ($m.ContainsKey('SubStatus') -and $m['SubStatus'] -and $m['SubStatus'] -ne '0x0') { $codeRaw = ([string]$m['SubStatus']).Trim() }
        elseif ($m.ContainsKey('Status') -and $m['Status']) { $codeRaw = ([string]$m['Status']).Trim() }
        elseif ($m.ContainsKey('ErrorCode') -and $m['ErrorCode']) { $codeRaw = ([string]$m['ErrorCode']).Trim() }

        $codeKey = $codeRaw.ToLowerInvariant()
        $reason = if ($codeKey -and $statusLookup.ContainsKey($codeKey)) { "$codeRaw - $($statusLookup[$codeKey])" }
                  elseif ($ev.Id -eq 4740) { 'Account Locked Out' }
                  elseif ($ev.Id -eq 4624) { 'Logon Succeeded' }
                  elseif ($codeRaw) { $codeRaw }
                  else { ($msg -split "`r?`n")[0] }

        $sev = switch ($ev.Id) {
            4740 { 'Critical' }
            4625 { 'Error' }
            4771 { if ($codeKey -eq '0x0') { 'Info' } else { 'Error' } }
            4776 { if ($codeKey -and $codeKey -ne '0x0') { 'Error' } else { 'Info' } }
            default { 'Info' }
        }

        $pkg = if ($m.ContainsKey('AuthenticationPackageName') -and $m['AuthenticationPackageName']) { [string]$m['AuthenticationPackageName'] }
               elseif ($m.ContainsKey('PackageName') -and $m['PackageName']) { [string]$m['PackageName'] }
               elseif ($ev.Id -eq 4771) { 'Kerberos' }
               else { '' }

        $out.Add([PSCustomObject]@{
            TimeCreated   = $ev.TimeCreated.ToUniversalTime().ToString('o')
            Severity      = $sev
            EventId       = $ev.Id
            UserName      = $user
            ClientHost    = $client
            ClientIp      = $ip
            LogonType     = $logonType
            AuthPackage   = $pkg
            FailureReason = $reason
            RawMessage    = $msg
        })
        if ($out.Count -ge $Max) { break }
    }

    return $out.ToArray()
}

$remoteScript = {
    param($Hours, $Max, $Ids, $UserFilter, $ClientFilter, $ParserText)
    $startTime = (Get-Date).AddHours(-$Hours)
    $warns = New-Object System.Collections.Generic.List[string]
    $rows = @()
    $fetchLimit = if (-not [string]::IsNullOrWhiteSpace($UserFilter) -or -not [string]::IsNullOrWhiteSpace($ClientFilter)) {
        [math]::Min(5000, $Max * 5)
    } else { $Max }

    try {
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Ids; StartTime = $startTime } -MaxEvents $fetchLimit -ErrorAction Stop)
        $parserSb = [scriptblock]::Create($ParserText)
        $rows = @(& $parserSb $evs $Max $UserFilter $ClientFilter)
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $warns.Add("Unable to read Security Event Log (requires Administrator or Event Log Readers privileges): $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        Rows     = $rows
        Warnings = $warns.ToArray()
    }
}

$fallbackRpc = {
    param($Target, $Cred, $Proto, $Hours, $Max, $Ids, $UserFilter, $ClientFilter, $ParserText)
    $startTime = (Get-Date).AddHours(-$Hours)
    $warns = New-Object System.Collections.Generic.List[string]
    $rows = @()
    $fetchLimit = if (-not [string]::IsNullOrWhiteSpace($UserFilter) -or -not [string]::IsNullOrWhiteSpace($ClientFilter)) {
        [math]::Min(5000, $Max * 5)
    } else { $Max }

    try {
        $evParams = @{ ComputerName = $Target; FilterHashtable = @{ LogName = 'Security'; Id = $Ids; StartTime = $startTime }; MaxEvents = $fetchLimit; ErrorAction = 'Stop' }
        if ($null -ne $Cred) { $evParams['Credential'] = $Cred }
        $evs = @(Get-WinEvent @evParams)
        $parserSb = [scriptblock]::Create($ParserText)
        $rows = @(& $parserSb $evs $Max $UserFilter $ClientFilter)
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') { $warns.Add($_.Exception.Message) }
    }
    return [PSCustomObject]@{ Rows = $rows; Warnings = $warns.ToArray() }
}

try {
    $parserStr = $parseEventsCore.ToString()
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $MaxResults, $intIds, $UserName, $ClientHost, $parserStr) -FallbackScriptBlock $fallbackRpc
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $failCount    = @($rows | Where-Object { $_.EventId -in @(4625, 4771) -or ($_.EventId -eq 4776 -and $_.Severity -eq 'Error') }).Count
    $lockoutCount = @($rows | Where-Object { $_.EventId -eq 4740 }).Count
    $uniqueUsers  = @($rows | Where-Object { $_.UserName } | Select-Object -ExpandProperty UserName -Unique).Count
    $uniqueIps    = @($rows | Where-Object { $_.ClientIp } | Select-Object -ExpandProperty ClientIp -Unique).Count

    $schema = @(
        @{ key = 'TimeCreated';   label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';      label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';       label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';      label = 'User';          type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientHost';    label = 'Client/Caller'; type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientIp';      label = 'Source IP';     type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LogonType';     label = 'Logon Type';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'AuthPackage';   label = 'Package';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $false }
        @{ key = 'FailureReason'; label = 'Status/Reason'; type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';    label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'failed_logons';    label = 'Auth Failures (4625/4771/4776)'; value = $failCount;    unit = 'events'; severity = if ($failCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'account_lockouts'; label = 'Lockouts (4740)';                value = $lockoutCount; unit = 'events'; severity = if ($lockoutCount -gt 0) { 'critical' } else { 'ok' } }
        @{ key = 'impacted_users';   label = 'Unique Users';                   value = $uniqueUsers;  unit = 'users';  severity = 'info' }
        @{ key = 'source_ips';       label = 'Unique Source IPs';              value = $uniqueIps;    unit = 'IPs';    severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '5.1-logon' -Category 'Active Directory & Authentication' -SubCategory 'Logon & Lockouts' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '5.1-logon' -Category 'Active Directory & Authentication' -SubCategory 'Logon & Lockouts' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
