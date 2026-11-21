#Requires -Version 5.1
<#
.SYNOPSIS
    Reads Windows DHCP Server text logs over SMB (\\$Computer\c$\Windows\System32\dhcp\DhcpSrvLog-*.txt
    or \\$Computer\c$\system32\dhcp\DhcpSrvLog-*.txt) and queries DHCP Server Event Logs.
    Prefers the most recently modified file by default, with options to select 1–6 days ago or all 7 days.
.NOTES
    Category:  04-Networking / 4.9-DHCP-Server
    Protocols: SMB, WinRM, RPC
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
    [ValidateSet('Latest (Last Modified)', '1 Day Ago', '2 Days Ago', '3 Days Ago', '4 Days Ago', '5 Days Ago', '6 Days Ago', 'All Past 7 Days')]
    [string]$LogDay = 'Latest (Last Modified)',

    [Parameter()]
    [ValidateSet('All (SMB Logs + Event Logs)', 'SMB Text Logs Only', 'Event Logs Only')]
    [string]$LogSource = 'All (SMB Logs + Event Logs)',

    [Parameter()]
    [string]$ClientFilter = '',

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 168,

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxResults = 500,

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

$protocolUsed = $Protocol
$filesRead    = 0
$smbRows      = 0
$eventRows    = 0
$issueCount   = 0
$selectedFileLabel = 'None'

try {
    # 1. SMB DHCP Server Text Logs (DhcpSrvLog-*.txt)
    if ($LogSource -in @('All (SMB Logs + Event Logs)', 'SMB Text Logs Only')) {
        $smbRes = Invoke-WinInspectorSmbAction -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            param($RootPath)
            $dirCandidates = @(
                (Join-Path $RootPath 'Windows\System32\dhcp'),
                (Join-Path $RootPath 'system32\dhcp')
            ) | Select-Object -Unique

            $dhcpDir = $null
            foreach ($d in $dirCandidates) {
                if (Test-Path -LiteralPath $d -PathType Container -ErrorAction SilentlyContinue) {
                    $dhcpDir = $d
                    break
                }
            }

            if (-not $dhcpDir) {
                return [PSCustomObject]@{ FoundDir = $false; DirPath = $dirCandidates[0]; Files = @(); Selected = @(); Error = '' }
            }

            $files = @(Get-ChildItem -LiteralPath $dhcpDir -Filter 'Dhcp*SrvLog-*.txt' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            if ($files.Count -eq 0) {
                return [PSCustomObject]@{ FoundDir = $true; DirPath = $dhcpDir; Files = @(); Selected = @(); Error = '' }
            }

            $chosen = [System.Collections.Generic.List[object]]::new()
            if ($LogDay -eq 'Latest (Last Modified)') {
                $chosen.Add($files[0])
            }
            elseif ($LogDay -eq 'All Past 7 Days') {
                foreach ($f in $files) { $chosen.Add($f) }
            }
            elseif ($LogDay -match '^(\d)\s+Day') {
                $daysAgo = [int]$Matches[1]
                $targetDate = (Get-Date).AddDays(-$daysAgo)
                $dayTag = $targetDate.ToString('ddd', [System.Globalization.CultureInfo]::InvariantCulture)

                $byDate = $files | Where-Object { $_.LastWriteTime.Date -eq $targetDate.Date } | Select-Object -First 1
                if ($byDate) {
                    $chosen.Add($byDate)
                }
                else {
                    $byName = $files | Where-Object { $_.Name -like "*-$dayTag.txt" } | Select-Object -First 1
                    if ($byName) {
                        $chosen.Add($byName)
                    }
                    elseif ($daysAgo -lt $files.Count) {
                        $chosen.Add($files[$daysAgo])
                    }
                }
            }

            $filePayloads = [System.Collections.Generic.List[object]]::new()
            foreach ($cf in $chosen) {
                try {
                    $lines = @(Get-Content -LiteralPath $cf.FullName -Tail 2000 -Encoding UTF8 -ErrorAction Stop)
                    $filePayloads.Add([PSCustomObject]@{
                        Name          = $cf.Name
                        FullName      = $cf.FullName
                        LastWriteTime = $cf.LastWriteTime.ToUniversalTime().ToString('o')
                        Lines         = $lines
                        Error         = ''
                    })
                }
                catch {
                    $filePayloads.Add([PSCustomObject]@{
                        Name          = $cf.Name
                        FullName      = $cf.FullName
                        LastWriteTime = $cf.LastWriteTime.ToUniversalTime().ToString('o')
                        Lines         = @()
                        Error         = $_.Exception.Message
                    })
                }
            }

            return [PSCustomObject]@{
                FoundDir = $true
                DirPath  = $dhcpDir
                Files    = @($files | Select-Object Name, LastWriteTime)
                Selected = $filePayloads.ToArray()
                Error    = ''
            }
        }

        if (-not $smbRes.FoundDir) {
            $warnings.Add("DHCP Server log directory not found at '\\$ComputerName\c$\Windows\System32\dhcp' or '\\$ComputerName\c$\system32\dhcp' (DHCP Server role may not be installed or C$ share inaccessible).")
        }
        elseif (@($smbRes.Files).Count -eq 0) {
            $warnings.Add("No DhcpSrvLog-*.txt files found in '$($smbRes.DirPath)'.")
        }
        elseif (@($smbRes.Selected).Count -eq 0) {
            $warnings.Add("No DhcpSrvLog file matched '$LogDay' in '$($smbRes.DirPath)'.")
        }
        else {
            $protocolUsed = 'SMB'
            $selectedNames = [System.Collections.Generic.List[string]]::new()

            foreach ($fp in @($smbRes.Selected)) {
                if ($fp.Error) {
                    $warnings.Add("Could not read '$($fp.FullName)': $($fp.Error)")
                    continue
                }
                $filesRead++
                $selectedNames.Add($fp.Name)

                foreach ($line in @($fp.Lines)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    # DHCP CSV data lines start with 2-digit ID,Date,Time,...
                    if ($line -notmatch '^\d{1,3},') { continue }

                    $cols = $line -split ','
                    if ($cols.Count -lt 7) { continue }

                    $dhcpId   = [int]$cols[0]
                    $dtRaw    = "$($cols[1]) $($cols[2])"
                    $desc     = $cols[3].Trim()
                    $ipAddr   = $cols[4].Trim()
                    $hostName = $cols[5].Trim()
                    $macAddr  = $cols[6].Trim()
                    $userName = if ($cols.Count -ge 8) { $cols[7].Trim() } else { '' }
                    $dnsErr   = if ($cols.Count -ge 19) { $cols[18].Trim() } else { '' }

                    if (-not [string]::IsNullOrWhiteSpace($ClientFilter)) {
                        $cf = $ClientFilter.Trim()
                        if ($ipAddr -notlike "*$cf*" -and $hostName -notlike "*$cf*" -and $macAddr -notlike "*$cf*" -and $userName -notlike "*$cf*" -and $desc -notlike "*$cf*") {
                            continue
                        }
                    }

                    $dtObj = $null
                    $tsIso = $dtRaw
                    if ([datetime]::TryParse($dtRaw, [ref]$dtObj)) {
                        $tsIso = $dtObj.ToUniversalTime().ToString('o')
                    }

                    $sev = if ($dhcpId -in @(13, 14, 15, 22, 23, 31) -or $dhcpId -ge 50) {
                        $issueCount++
                        if ($dhcpId -in @(14, 15) -or $dhcpId -ge 50) { 'Error' } else { 'Warning' }
                    }
                    else { 'Info' }

                    $smbRows++
                    $allRows.Add([PSCustomObject]@{
                        TimeCreated = $tsIso
                        Severity    = $sev
                        SourceType  = "SMB Log ($($fp.Name))"
                        EventId     = $dhcpId
                        IpAddress   = $ipAddr
                        HostName    = $hostName
                        MacAddress  = $macAddr
                        UserName    = $userName
                        Summary     = "$desc | IP: $ipAddr | Host: $hostName | MAC: $macAddr$(if ($dnsErr -and $dnsErr -ne '0') { " | DnsErr: $dnsErr" })"
                        RawMessage  = "File: $($fp.FullName)`nLine: $line"
                    })
                }
            }

            if ($selectedNames.Count -gt 0) {
                $selectedFileLabel = ($selectedNames.ToArray() -join ', ')
            }
        }
    }

    # 2. DHCP Server Windows Event Logs
    if ($LogSource -in @('All (SMB Logs + Event Logs)', 'Event Logs Only')) {
        $evScript = {
            param($Hours, $FilterText, $Max)
            $startTime = (Get-Date).AddHours(-$Hours)
            $out = New-Object System.Collections.Generic.List[object]
            $warns = New-Object System.Collections.Generic.List[string]

            $dhcpSvc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
            if ($dhcpSvc) {
                $out.Add([PSCustomObject]@{
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    Severity    = if ($dhcpSvc.Status -eq 'Running') { 'Info' } else { 'Critical' }
                    SourceType  = 'DHCPServer Service'
                    EventId     = 0
                    IpAddress   = ''
                    HostName    = $env:COMPUTERNAME
                    MacAddress  = ''
                    UserName    = ''
                    Summary     = "DHCP Server Service (DHCPServer): $($dhcpSvc.Status)"
                    RawMessage  = ($dhcpSvc | Format-List | Out-String)
                })
            }

            $channels = @(Get-WinEvent -ListLog 'Microsoft-Windows-Dhcp-Server*', 'DhcpAdminEvents', 'Microsoft-Windows-DHCP Server Events*' -Force -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled })
            foreach ($ch in $channels) {
                try {
                    $evs = Get-WinEvent -FilterHashtable @{ LogName = $ch.LogName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
                    foreach ($ev in $evs) {
                        $msg = if ($ev.Message) { $ev.Message } else { '' }
                        if (-not [string]::IsNullOrWhiteSpace($FilterText) -and $msg -notlike "*$FilterText*") { continue }
                        $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                        $out.Add([PSCustomObject]@{
                            TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                            Severity    = $sev
                            SourceType  = $ch.LogName
                            EventId     = $ev.Id
                            IpAddress   = ''
                            HostName    = ''
                            MacAddress  = ''
                            UserName    = ''
                            Summary     = ($msg -split "`r?`n")[0]
                            RawMessage  = $msg
                        })
                    }
                } catch {}
            }

            # System log DHCP Server provider events
            try {
                $sysEvs = Get-WinEvent -FilterHashtable @{
                    LogName      = 'System'
                    ProviderName = @('Microsoft-Windows-DHCP-Server', 'DHCPServer')
                    Level        = @(1, 2, 3)
                    StartTime    = $startTime
                } -MaxEvents $Max -ErrorAction SilentlyContinue
                foreach ($ev in $sysEvs) {
                    $msg = if ($ev.Message) { $ev.Message } else { '' }
                    if (-not [string]::IsNullOrWhiteSpace($FilterText) -and $msg -notlike "*$FilterText*") { continue }
                    $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                    $out.Add([PSCustomObject]@{
                        TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                        Severity    = $sev
                        SourceType  = 'System (DHCPServer)'
                        EventId     = $ev.Id
                        IpAddress   = ''
                        HostName    = ''
                        MacAddress  = ''
                        UserName    = ''
                        Summary     = ($msg -split "`r?`n")[0]
                        RawMessage  = $msg
                    })
                }
            } catch {}

            return [PSCustomObject]@{ Rows = $out.ToArray(); Warnings = $warns.ToArray() }
        }

        try {
            $evRes = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $evScript -ArgumentList @($HoursBack, $ClientFilter, $effectiveMax)
            if ($LogSource -eq 'Event Logs Only') { $protocolUsed = $evRes.ProtocolUsed }
            elseif ($protocolUsed -eq 'SMB') { $protocolUsed = "SMB + $($evRes.ProtocolUsed)" }
            else { $protocolUsed = $evRes.ProtocolUsed }

            foreach ($w in @($evRes.Warnings)) { $warnings.Add($w) }
            foreach ($w in @($evRes.Data.Warnings)) { $warnings.Add($w) }
            foreach ($r in @($evRes.Data.Rows)) {
                $eventRows++
                if ($r.Severity -in @('Critical', 'Error', 'Warning')) { $issueCount++ }
                $allRows.Add($r)
            }
        }
        catch {
            if ($LogSource -eq 'Event Logs Only') { throw }
            $warnings.Add("DHCP Server Event Log query skipped ($($_.Exception.Message)).")
        }
    }

    $rows = @($allRows.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $effectiveMax)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'SourceType';  label = 'Log / File';   type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'ID';           type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'IpAddress';   label = 'Client IP';    type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'HostName';    label = 'Hostname';     type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'MacAddress';  label = 'MAC Address';  type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $false }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'dhcp_log_file';    label = 'Selected Log File'; value = $selectedFileLabel; unit = '';       severity = 'info' }
        @{ key = 'dhcp_smb_rows';    label = 'SMB Log Entries';   value = $smbRows;           unit = 'rows';   severity = 'info' }
        @{ key = 'dhcp_event_rows';  label = 'Event Log Entries'; value = $eventRows;         unit = 'events'; severity = 'info' }
        @{ key = 'dhcp_issues';      label = 'Warnings / NACKs';  value = $issueCount;        unit = 'events'; severity = if ($issueCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $status = if ($rows.Count -eq 0 -and $warnings.Count -gt 0) { 'Partial' } else { 'Success' }
    $sw.Stop()
    New-WinInspectorResult -ScriptId '4.9-dhcp-server' -Category 'Networking' -SubCategory 'DHCP Server Logs & Events' -TargetServer $ComputerName -ProtocolUsed $protocolUsed -DurationMs $sw.ElapsedMilliseconds -Status $status -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '4.9-dhcp-server' -Category 'Networking' -SubCategory 'DHCP Server Logs & Events' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
