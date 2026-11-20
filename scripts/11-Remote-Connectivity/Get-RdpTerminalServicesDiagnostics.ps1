#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses RDP / Terminal Services configuration (Port, NLA, fDenyTSConnections, TermService) and Session/Connection events (21, 23, 24, 25, 1149).
.NOTES
    Category:  11-Remote-Connectivity / 11.1-RDP
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/paulmann/RDP-Diagnostic-Tool
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
    [int]$HoursBack = 72,

    [Parameter()]
    [string]$UserName = '',

    [Parameter()]
    [ValidateRange(10, 2000)]
    [int]$MaxResults = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours, $UserFilter, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]

    $tsReg  = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $rdpTcp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    $svc    = Get-Service -Name TermService -ErrorAction SilentlyContinue

    $rdpEnabled = if ($tsReg) { ($tsReg.fDenyTSConnections -eq 0) } else { $false }
    $rdpPort    = if ($rdpTcp -and $rdpTcp.PortNumber) { $rdpTcp.PortNumber } else { 3389 }
    $nlaEnabled = if ($rdpTcp) { ($rdpTcp.UserAuthentication -eq 1) } else { $false }
    $svcState   = if ($svc) { [string]$svc.Status } else { 'Unknown' }

    $out.Add([PSCustomObject]@{
        TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
        Severity    = if ($rdpEnabled -and $svcState -eq 'Running') { 'Info' } else { 'Warning' }
        RecordType  = 'RDP Config'
        EventId     = 0
        EventAction = "TermService=$svcState"
        UserName    = ''
        ClientIp    = ''
        SessionId   = ''
        Summary     = "RDP Enabled: $rdpEnabled | Port: $rdpPort | NLA Required: $nlaEnabled | TermService: $svcState"
        RawMessage  = "fDenyTSConnections: $($tsReg.fDenyTSConnections)`nPortNumber: $rdpPort`nUserAuthentication (NLA): $nlaEnabled`nTermService: $svcState"
    })

    $channels = @(
        @{ Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids = @(21, 22, 23, 24, 25, 39, 40) }
        @{ Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149) }
    )

    foreach ($ch in $channels) {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = $ch.Log; Id = $ch.Ids; StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            $user = ''
            $ip   = ''
            $sid  = ''
            try {
                $x = [xml]$ev.ToXml()
                $ud = $x.Event.UserData
                if ($ud -and $ud.EventXML) {
                    if ($ud.EventXML.User)      { $user = [string]$ud.EventXML.User }
                    elseif ($ud.EventXML.Param1){ $user = if ($ud.EventXML.Param2) { "$($ud.EventXML.Param2)\$($ud.EventXML.Param1)" } else { [string]$ud.EventXML.Param1 } }
                    if ($ud.EventXML.Address)   { $ip = [string]$ud.EventXML.Address }
                    elseif ($ud.EventXML.Param3){ $ip = [string]$ud.EventXML.Param3 }
                    if ($ud.EventXML.SessionID) { $sid = [string]$ud.EventXML.SessionID }
                }
            } catch {}

            if (-not [string]::IsNullOrWhiteSpace($UserFilter) -and ($user -notlike "*$UserFilter*")) { continue }

            $action = switch ($ev.Id) {
                21   { 'Session Logon' }
                22   { 'Shell Start' }
                23   { 'Session Logoff' }
                24   { 'Session Disconnected' }
                25   { 'Session Reconnected' }
                39   { 'Session Disconnected by User' }
                40   { 'Session Disconnected (Reason)' }
                1149 { 'RDP Network Auth Succeeded' }
                default { "Event $($ev.Id)" }
            }

            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Severity    = if ($ev.Id -in @(24, 39, 40)) { 'Warning' } else { 'Info' }
                RecordType  = 'RDP Event'
                EventId     = $ev.Id
                EventAction = $action
                UserName    = $user
                ClientIp    = $ip
                SessionId   = $sid
                Summary     = "$action | User: $user | Client IP: $ip"
                RawMessage  = $msg
            })
        }
    }

    return [PSCustomObject]@{
        Rows       = @($out.ToArray() | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
        RdpEnabled = $rdpEnabled
        RdpPort    = $rdpPort
        NlaEnabled = $nlaEnabled
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $UserName, $MaxResults)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventAction'; label = 'Action';       type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientIp';    label = 'Client IP';    type = 'ip';       filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'SessionId';   label = 'Session ID';   type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'rdp_enabled'; label = 'RDP Enabled'; value = if ($res.Data.RdpEnabled) { 'Yes' } else { 'No' }; unit = '';       severity = if ($res.Data.RdpEnabled) { 'ok' } else { 'warning' } }
        @{ key = 'rdp_port';    label = 'RDP Port';    value = $res.Data.RdpPort;                                 unit = '';       severity = 'info' }
        @{ key = 'rdp_nla';     label = 'NLA';         value = if ($res.Data.NlaEnabled) { 'Required' } else { 'Disabled' }; unit = ''; severity = if ($res.Data.NlaEnabled) { 'ok' } else { 'warning' } }
        @{ key = 'rdp_events';  label = 'RDP Events';  value = [math]::Max(0, $rows.Count - 1);                   unit = 'events'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '11.1-rdp' -Category 'Remote Connectivity' -SubCategory 'RDP / Terminal Services' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '11.1-rdp' -Category 'Remote Connectivity' -SubCategory 'RDP / Terminal Services' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
