#Requires -Version 5.1
<#
.SYNOPSIS
    Inspects Windows Firewall profiles, Security Log WFP drops (5152/5157),
    WFP Operational events, and Windows Firewall log file (pfirewall.log) over SMB.
.NOTES
    Category:  04-Networking / 4.7-Firewall
    Protocols: WinRM, SMB
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
    [ValidateSet('All (Events + pfirewall.log)', 'pfirewall.log (SMB)', 'Event Logs Only')]
    [string]$LogSource = 'All (Events + pfirewall.log)',

    [Parameter()]
    [ValidateSet('All', 'DROP', 'ALLOW')]
    [string]$ActionFilter = 'All',

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    [Parameter()]
    [string]$IpFilter = '',

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
$allRows  = [System.Collections.Generic.List[object]]::new()

$enabledProfiles = 0
$dropCount       = 0
$pfirewallCount  = 0
$protocolUsed    = $Protocol
$configuredLogPaths = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $IpMatch, $ActFilter, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]
    $logPaths = New-Object System.Collections.Generic.List[string]

    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $enabledCnt = @($profiles | Where-Object { $_.Enabled }).Count
    foreach ($p in $profiles) {
        if ($p.LogFileName -and -not $logPaths.Contains($p.LogFileName)) {
            $logPaths.Add($p.LogFileName)
        }
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($p.Enabled) { 'Info' } else { 'Warning' }
            RecordType  = 'Firewall Profile'
            EventId     = 0
            Direction   = "In:$($p.DefaultInboundAction) / Out:$($p.DefaultOutboundAction)"
            Protocol    = ''
            SourceIp    = ''
            DestIp      = ''
            DestPort    = 0
            Application = $p.Name
            Summary     = "Profile '$($p.Name)': Enabled=$($p.Enabled), LogBlocked=$($p.LogBlocked), LogFile=$($p.LogFileName)"
            RawMessage  = ($p | Format-List | Out-String)
        })
    }

    $drops = 0
    if ($ActFilter -in @('All', 'DROP')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5152, 5157); StartTime = $startTime } -MaxEvents $Max -ErrorAction Stop
            foreach ($ev in $evs) {
                $m = @{}
                try {
                    $x = [xml]$ev.ToXml()
                    foreach ($n in $x.Event.EventData.Data) {
                        if ($n -is [System.Xml.XmlElement] -and $n.HasAttribute('Name')) { $m[$n.GetAttribute('Name')] = $n.InnerText }
                    }
                } catch {}

                $srcIp = if ($m.ContainsKey('SourceAddress')) { $m['SourceAddress'] } else { '' }
                $dstIp = if ($m.ContainsKey('DestAddress'))   { $m['DestAddress'] }   else { '' }
                $dstPt = if ($m.ContainsKey('DestPort'))      { [int]$m['DestPort'] } else { 0 }
                $app   = if ($m.ContainsKey('Application'))   { $m['Application'] }   else { '' }
                $dir   = if ($m['Direction'] -eq '%%14592')   { 'Inbound' } elseif ($m['Direction'] -eq '%%14593') { 'Outbound' } else { [string]$m['Direction'] }

                if (-not [string]::IsNullOrWhiteSpace($IpMatch)) {
                    if ($srcIp -notlike "*$IpMatch*" -and $dstIp -notlike "*$IpMatch*") { continue }
                }

                $drops++
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = 'Warning'
                    RecordType  = if ($ev.Id -eq 5152) { 'WFP Packet Drop' } else { 'WFP Connection Block' }
                    EventId     = $ev.Id
                    Direction   = $dir
                    Protocol    = [string]$m['Protocol']
                    SourceIp    = $srcIp
                    DestIp      = $dstIp
                    DestPort    = $dstPt
                    Application = $app
                    Summary     = "$dir blocked: $srcIp -> ${dstIp}:${dstPt} ($app)"
                    RawMessage  = if ($ev.Message) { $ev.Message } else { '' }
                })
            }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                $warns.Add("Security log (5152/5157) unavailable (may require Administrator rights or Filtering Platform Packet Drop auditing enabled): $($_.Exception.Message)")
            }
        }
    }

    try {
        $wfpEvs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WFP/Operational'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $wfpEvs) {
            $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = $sev
                RecordType  = 'WFP Operational'
                EventId     = $ev.Id
                Direction   = ''
                Protocol    = ''
                SourceIp    = ''
                DestIp      = ''
                DestPort    = 0
                Application = $ev.ProviderName
                Summary     = ($msg -split "`r?`n")[0]
                RawMessage  = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{
        Rows            = $out.ToArray()
        EnabledProfiles = $enabledCnt
        DropCount       = $drops
        LogPaths        = $logPaths.ToArray()
        Warnings        = $warns.ToArray()
    }
}

try {
    # 1. Event Logs & Firewall Profiles (WinRM)
    if ($LogSource -in @('All (Events + pfirewall.log)', 'Event Logs Only')) {
        try {
            $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $IpFilter, $ActionFilter, $effectiveMax)
            $protocolUsed = $res.ProtocolUsed
            $enabledProfiles = $res.Data.EnabledProfiles
            $dropCount += $res.Data.DropCount
            foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
            foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
            foreach ($lp in @($res.Data.LogPaths)) { $configuredLogPaths.Add($lp) }
            foreach ($r in @($res.Data.Rows)) { $allRows.Add($r) }
        }
        catch {
            if ($LogSource -eq 'Event Logs Only') { throw }
            $warnings.Add("WinRM Event/Profile query skipped ($($_.Exception.Message)); falling back to SMB pfirewall.log.")
        }
    }

    # 2. pfirewall.log via SMB (\\$Computer\c$\Windows\System32\LogFiles\Firewall\pfirewall.log or \\$Computer\c$\system32\LogFiles\Firewall\pfirewall.log)
    if ($LogSource -in @('All (Events + pfirewall.log)', 'pfirewall.log (SMB)')) {
        $cutoffUtc = (Get-Date).ToUniversalTime().AddHours(-$HoursBack)

        $smbResult = Invoke-WinInspectorSmbAction -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            param($RootPath)
            $foundFile = $null
            $candidates = [System.Collections.Generic.List[string]]::new()

            # Check user-specified and standard Windows Firewall log paths
            $candidates.Add((Join-Path $RootPath 'Windows\System32\LogFiles\Firewall\pfirewall.log'))
            $candidates.Add((Join-Path $RootPath 'system32\LogFiles\Firewall\pfirewall.log'))
            foreach ($cfgPath in $configuredLogPaths) {
                $rel = ($cfgPath -replace '^%SystemRoot%\\?', 'Windows\' -replace '^[A-Za-z]:\\', '').TrimStart('\')
                if ($rel) { $candidates.Add((Join-Path $RootPath $rel)) }
            }

            foreach ($c in ($candidates | Select-Object -Unique)) {
                if (Test-Path -LiteralPath $c -PathType Leaf -ErrorAction SilentlyContinue) {
                    $foundFile = $c
                    break
                }
            }

            if (-not $foundFile) {
                return [PSCustomObject]@{ Found = $false; Path = $candidates[0]; Lines = @(); Error = '' }
            }

            try {
                $lines = @(Get-Content -LiteralPath $foundFile -Tail 2500 -Encoding UTF8 -ErrorAction Stop)
                return [PSCustomObject]@{ Found = $true; Path = $foundFile; Lines = $lines; Error = '' }
            }
            catch {
                return [PSCustomObject]@{ Found = $true; Path = $foundFile; Lines = @(); Error = $_.Exception.Message }
            }
        }

        if (-not $smbResult.Found) {
            $warnings.Add("pfirewall.log not found at '\\$ComputerName\c$\Windows\System32\LogFiles\Firewall\pfirewall.log' or '\\$ComputerName\c$\system32\LogFiles\Firewall\pfirewall.log' (Firewall file logging may be disabled or C$ share inaccessible).")
        }
        elseif ($smbResult.Error) {
            $warnings.Add("Unable to read '$($smbResult.Path)' over SMB: $($smbResult.Error)")
        }
        else {
            if ($LogSource -eq 'pfirewall.log (SMB)') { $protocolUsed = 'SMB' }
            elseif ($protocolUsed -ne 'SMB') { $protocolUsed = "$protocolUsed + SMB" }

            $fields = @('date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'size', 'tcpflags', 'tcpsyn', 'tcpack', 'tcpwin', 'icmptype', 'icmpcode', 'info', 'path')
            $parsedEntries = [System.Collections.Generic.List[object]]::new()

            foreach ($line in @($smbResult.Lines)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                if ($line.StartsWith('#Fields:')) {
                    $fields = ($line.Substring(8).Trim() -split '\s+')
                    continue
                }
                if ($line.StartsWith('#')) { continue }

                $parts = $line.Trim() -split '\s+'
                if ($parts.Count -lt 6) { continue }

                $map = @{}
                for ($i = 0; $i -lt [math]::Min($fields.Count, $parts.Count); $i++) {
                    $map[$fields[$i]] = $parts[$i]
                }

                $action = if ($map.ContainsKey('action')) { $map['action'].ToUpperInvariant() } else { '' }
                if ($ActionFilter -ne 'All' -and $action -ne $ActionFilter) { continue }

                $srcIp = if ($map.ContainsKey('src-ip'))   { $map['src-ip'] }   else { '' }
                $dstIp = if ($map.ContainsKey('dst-ip'))   { $map['dst-ip'] }   else { '' }
                if (-not [string]::IsNullOrWhiteSpace($IpFilter)) {
                    if ($srcIp -notlike "*$IpFilter*" -and $dstIp -notlike "*$IpFilter*") { continue }
                }

                $dtRaw = "$($map['date']) $($map['time'])"
                $dtObj = $null
                $tsIso = $dtRaw
                if ([datetime]::TryParse($dtRaw, [ref]$dtObj)) {
                    $dtUtc = $dtObj.ToUniversalTime()
                    if ($dtUtc -lt $cutoffUtc) { continue }
                    $tsIso = $dtUtc.ToString('o')
                }

                $proto   = if ($map.ContainsKey('protocol')) { $map['protocol'] } else { '' }
                $srcPort = if ($map.ContainsKey('src-port')) { $map['src-port'] } else { '' }
                $dstPort = 0
                if ($map.ContainsKey('dst-port') -and $map['dst-port'] -match '^\d+$') { $dstPort = [int]$map['dst-port'] }
                $dirPath = if ($map.ContainsKey('path')) { $map['path'] } else { '' }
                $infoTxt = if ($map.ContainsKey('info')) { $map['info'] } else { '' }

                if ($action -eq 'DROP') { $dropCount++ }
                $pfirewallCount++

                $parsedEntries.Add([PSCustomObject]@{
                    TimeCreated = $tsIso
                    Severity    = if ($action -eq 'DROP') { 'Warning' } else { 'Info' }
                    RecordType  = "pfirewall.log ($action)"
                    EventId     = 0
                    Direction   = $dirPath
                    Protocol    = $proto
                    SourceIp    = $srcIp
                    DestIp      = $dstIp
                    DestPort    = $dstPort
                    Application = [System.IO.Path]::GetFileName($smbResult.Path)
                    Summary     = "$action $proto ($dirPath): ${srcIp}:${srcPort} -> ${dstIp}:${dstPort} $infoTxt"
                    RawMessage  = "File: $($smbResult.Path)`nLine: $line"
                })
            }

            # Keep newest entries first
            $newest = @($parsedEntries.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $effectiveMax)
            foreach ($r in $newest) { $allRows.Add($r) }
        }
    }

    $rows = @($allRows.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $effectiveMax)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Source/Type';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Direction';   label = 'Direction';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Protocol';    label = 'Protocol';     type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'SourceIp';    label = 'Source IP';    type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DestIp';      label = 'Dest IP';      type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'DestPort';    label = 'Dest Port';    type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Application'; label = 'App / Log';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'fw_profiles_on';  label = 'Active FW Profiles'; value = $enabledProfiles; unit = '/ 3';    severity = 'info' }
        @{ key = 'fw_drops';        label = 'Blocked / Drops';    value = $dropCount;       unit = 'events'; severity = if ($dropCount -gt 0) { 'warning' } else { 'ok' } }
        @{ key = 'pfirewall_lines'; label = 'pfirewall.log Rows'; value = $pfirewallCount;  unit = 'rows';   severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.7-firewall' -Category 'Networking' -SubCategory 'Firewall & pfirewall.log' -TargetServer $ComputerName -ProtocolUsed $protocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.7-firewall' -Category 'Networking' -SubCategory 'Firewall & pfirewall.log' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
