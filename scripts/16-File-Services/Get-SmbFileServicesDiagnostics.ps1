#Requires -Version 5.1
<#
.SYNOPSIS
    Audits SMB Server/Client configuration, SMB shares, active SMB sessions (Client/User), and SMBServer/SMBClient Connectivity events.
.NOTES
    Category:  16-File-Services / 16.1-SMB
    Protocols: WinRM
    ReadOnly:  True
    Reference: https://github.com/PowerShell/PrivateCloud.DiagnosticInfo
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
    param($Hours, $Max)
    $startTime = (Get-Date).AddHours(-$Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $warns = New-Object System.Collections.Generic.List[string]

    $shareCount = 0
    $sessionCount = 0
    $smb1Enabled = 'Unknown'

    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1Enabled = [string]$cfg.EnableSMB1Protocol
        $out.Add([PSCustomObject]@{
            TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
            Severity    = if ($cfg.EnableSMB1Protocol) { 'Warning' } else { 'Info' }
            RecordType  = 'SMB Server Config'
            EventId     = 0
            UserName    = ''
            ClientIp    = ''
            ShareOrSrc  = 'LanmanServer'
            Summary     = "SMB1=$($cfg.EnableSMB1Protocol) | SMB2/3=$($cfg.EnableSMB2Protocol) | EncryptData=$($cfg.EncryptData) | RequireSecuritySignature=$($cfg.RequireSecuritySignature)"
            RawMessage  = ($cfg | Format-List | Out-String)
        })

        foreach ($sh in @(Get-SmbShare -ErrorAction SilentlyContinue)) {
            $shareCount++
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = 'Info'
                RecordType  = 'SMB Share'
                EventId     = 0
                UserName    = ''
                ClientIp    = ''
                ShareOrSrc  = $sh.Name
                Summary     = "Share '$($sh.Name)' -> $($sh.Path) (Encrypt=$($sh.EncryptData))"
                RawMessage  = ($sh | Format-List | Out-String)
            })
        }

        $smbSessions = @(Get-SmbSession -ErrorAction SilentlyContinue)
        if ($Max -lt 2147483647) { $smbSessions = @($smbSessions | Select-Object -First 50) }
        foreach ($sess in $smbSessions) {
            $sessionCount++
            $out.Add([PSCustomObject]@{
                TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                Severity    = 'Info'
                RecordType  = 'Active SMB Session'
                EventId     = 0
                UserName    = $sess.ClientUserName
                ClientIp    = $sess.ClientComputerName
                ShareOrSrc  = "Dialect $($sess.Dialect)"
                Summary     = "Session from $($sess.ClientComputerName) as $($sess.ClientUserName) | OpenFiles: $($sess.NumOpens) | Dialect: $($sess.Dialect)"
                RawMessage  = ($sess | Format-List | Out-String)
            })
        }
    }
    catch {
        $warns.Add("SMB share/session query note (may require Administrator rights): $($_.Exception.Message)")
    }

    $smbErrors = 0
    foreach ($logName in @('Microsoft-Windows-SMBServer/Connectivity', 'Microsoft-Windows-SMBClient/Connectivity', 'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-SMBClient/Security')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents $Max -ErrorAction SilentlyContinue
            foreach ($ev in $evs) {
                $smbErrors++
                $sev = switch ($ev.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { 'Info' } }
                $msg = if ($ev.Message) { $ev.Message } else { '' }
                $out.Add([PSCustomObject]@{
                    TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                    Severity    = $sev
                    RecordType  = 'SMB Event'
                    EventId     = $ev.Id
                    UserName    = ''
                    ClientIp    = ''
                    ShareOrSrc  = $logName
                    Summary     = ($msg -split "`r?`n")[0]
                    RawMessage  = $msg
                })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Rows         = @($out.ToArray() | Select-Object -First $Max)
        ShareCount   = $shareCount
        SessionCount = $sessionCount
        Smb1Enabled  = $smb1Enabled
        SmbErrors    = $smbErrors
        Warnings     = $warns.ToArray()
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack, $effectiveMax)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    foreach ($w in @($res.Data.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';    type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'RecordType';  label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';     type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientIp';    label = 'Client';       type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ShareOrSrc';  label = 'Share/Log';    type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'smb_shares';   label = 'SMB Shares';      value = $res.Data.ShareCount;   unit = 'shares';   severity = 'info' }
        @{ key = 'smb_sessions'; label = 'Active Sessions'; value = $res.Data.SessionCount; unit = 'sessions'; severity = 'info' }
        @{ key = 'smb1_enabled'; label = 'SMB1 Enabled';    value = $res.Data.Smb1Enabled;  unit = '';         severity = if ($res.Data.Smb1Enabled -eq 'True') { 'warning' } else { 'ok' } }
        @{ key = 'smb_errors';   label = 'SMB Events';      value = $res.Data.SmbErrors;    unit = 'events';   severity = if ($res.Data.SmbErrors -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '16.1-smb' -Category 'File Services' -SubCategory 'SMB File Services' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '16.1-smb' -Category 'File Services' -SubCategory 'SMB File Services' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
