#Requires -Version 5.1
<#
.SYNOPSIS
    Queries active Terminal / RDP sessions on the target server using native qwinsta.exe
    (/server:ServerName) with WMI/CIM fallback (Win32_LogonSession + Win32_Process).
.NOTES
    Category:  11-Remote-Connectivity / 11.3-RDP-Sessions
    Protocols: RPC (qwinsta /server:), WinRM, CIM-DCOM
    ReadOnly:  True
    Reference: https://ss64.com/nt/query-session.html
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
    [string]$UserFilter = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

function Resolve-QwinstaPath {
    $candidates = @(
        (Join-Path $env:SystemRoot 'Sysnative\qwinsta.exe'),
        (Join-Path $env:SystemRoot 'System32\qwinsta.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf -ErrorAction SilentlyContinue) { return $c }
    }
    $cmd = Get-Command qwinsta.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function ConvertFrom-QwinstaOutput {
    param(
        [string[]]$Lines,
        [string]$FilterText = ''
    )

    $parsed = [System.Collections.Generic.List[object]]::new()
    $userColStart = 18

    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*SESSIONNAME\s+USERNAME\s+ID\s+STATE') {
            $idx = $line.IndexOf('USERNAME', [System.StringComparison]::OrdinalIgnoreCase)
            if ($idx -gt 0) { $userColStart = $idx }
            continue
        }

        if ($line -match '^(?<prefix>.*?)\s+(?<Id>\d+)\s+(?<State>Active|Conn|Disc|Listen|Down|Idle|Reset|Init)(?<rest>.*)$') {
            $rawPrefix = $Matches['prefix']
            $sessId    = [int]$Matches['Id']
            $stateVal  = $Matches['State']
            $rest      = $Matches['rest'].Trim()

            $isCurrent = $rawPrefix.TrimStart().StartsWith('>')
            $cleanPrefix = $rawPrefix.TrimStart(' ', '>')
            $prefixTokens = @($cleanPrefix.Trim() -split '\s+' | Where-Object { $_ })

            $sessName = ''
            $userName = ''
            if ($prefixTokens.Count -ge 2) {
                $sessName = $prefixTokens[0]
                $userName = $prefixTokens[1]
            }
            elseif ($prefixTokens.Count -eq 1) {
                $tok = $prefixTokens[0]
                $tokIdx = $rawPrefix.IndexOf($tok, [System.StringComparison]::Ordinal)
                if ($tokIdx -ge ($userColStart - 3)) {
                    $userName = $tok
                }
                else {
                    $sessName = $tok
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($FilterText)) {
                if ($userName -notlike "*$FilterText*" -and $sessName -notlike "*$FilterText*") { continue }
            }

            $restTokens = @($rest -split '\s+' | Where-Object { $_ })
            $typeVal   = if ($restTokens.Count -ge 1) { $restTokens[0] } else { '' }
            $deviceVal = if ($restTokens.Count -ge 2) { $restTokens[1] } else { '' }

            $canReset = ($sessId -gt 0) -and ($stateVal -in @('Active', 'Disc', 'Conn', 'Idle'))
            $sev = if ($stateVal -eq 'Active') { 'Info' } elseif ($stateVal -eq 'Disc') { 'Warning' } else { 'Info' }

            $parsed.Add([PSCustomObject]@{
                Severity    = $sev
                SessionName = $sessName
                UserName    = $userName
                SessionId   = $sessId
                LogonId     = ''
                State       = $stateVal
                Type        = $typeVal
                Device      = $deviceVal
                ResetMethod = 'rwinsta'
                IsCurrent   = $isCurrent
                CanReset    = $canReset
                Summary     = "ID $sessId | State: $stateVal | Session: $(if ($sessName) { $sessName } else { '(none)' }) | User: $(if ($userName) { $userName } else { '(none)' })"
                RawMessage  = $line
            })
        }
    }

    return $parsed.ToArray()
}

function Get-WmiTerminalSessionsFallback {
    param(
        [string]$Target,
        [System.Management.Automation.PSCredential]$Cred,
        [string]$Proto,
        [string]$FilterText
    )

    $cimBundle = $null
    $out = [System.Collections.Generic.List[object]]::new()
    try {
        $cimBundle = New-WinInspectorCimSession -ComputerName $Target -Credential $Cred -Protocol $Proto
        $cimArgs = @{ ErrorAction = 'Stop' }
        if ($null -ne $cimBundle.Session) { $cimArgs['CimSession'] = $cimBundle.Session }

        $logons = @(Get-CimInstance -ClassName Win32_LogonSession -Filter 'LogonType = 2 OR LogonType = 10 OR LogonType = 11' @cimArgs)
        foreach ($l in $logons) {
            $assocUser = Get-CimAssociatedInstance -InputObject $l -ResultClassName Win32_Account @cimArgs -ErrorAction SilentlyContinue | Select-Object -First 1
            $procs = @(Get-CimAssociatedInstance -InputObject $l -ResultClassName Win32_Process @cimArgs -ErrorAction SilentlyContinue)

            # Skip empty token/service logon sessions with 0 running processes
            if ($procs.Count -eq 0) { continue }

            $uName = if ($assocUser -and $assocUser.PSObject.Properties['Name']) {
                $dom = if ($assocUser.PSObject.Properties['Domain'] -and $assocUser.Domain) { "$($assocUser.Domain)\" } else { '' }
                "$dom$($assocUser.Name)"
            } else { "LogonId $($l.LogonId)" }
            if (-not [string]::IsNullOrWhiteSpace($FilterText) -and $uName -notlike "*$FilterText*") { continue }

            $tsProc = $procs | Where-Object { $_.PSObject.Properties['SessionId'] -and [int]$_.SessionId -gt 0 } | Select-Object -First 1
            if ($null -eq $tsProc) { continue }
            $sessIdNum = [int]$tsProc.SessionId
            $sessType = switch ([int]$l.LogonType) { 10 { 'RDP (RemoteInteractive)' } 11 { 'CachedInteractive' } default { 'Interactive' } }
            $sessName = if ($l.LogonType -eq 10) { "rdp-tcp#$sessIdNum" } else { 'console' }
            $startTm = if ($l.PSObject.Properties['StartTime']) { [string]$l.StartTime } else { '' }

            $out.Add([PSCustomObject]@{
                Severity    = 'Info'
                SessionName = $sessName
                UserName    = $uName
                SessionId   = $sessIdNum
                LogonId     = [string]$l.LogonId
                State       = 'Active'
                Type        = $sessType
                Device      = "$($procs.Count) procs (LogonId $($l.LogonId))"
                ResetMethod = 'WMI'
                IsCurrent   = ($sessIdNum -eq [System.Diagnostics.Process]::GetCurrentProcess().SessionId -and (Test-WinInspectorIsLocal -ComputerName $Target))
                CanReset    = ($sessIdNum -gt 0)
                Summary     = "Session $sessIdNum ($sessName) | LogonId $($l.LogonId) | User: $uName | Processes: $($procs.Count)"
                RawMessage  = "LogonId: $($l.LogonId)`nSessionId: $sessIdNum`nUser: $uName`nLogonType: $sessType`nProcessCount: $($procs.Count)`nStartTime: $startTm"
            })
        }
        return [PSCustomObject]@{ ProtocolUsed = "$($cimBundle.ProtocolUsed) (WMI)"; Rows = $out.ToArray() }
    }
    finally {
        if ($null -ne $cimBundle -and $null -ne $cimBundle.Session) {
            try { Remove-CimSession -CimSession $cimBundle.Session -ErrorAction SilentlyContinue } catch {}
        }
    }
}

try {
    $isLocal = Test-WinInspectorIsLocal -ComputerName $ComputerName
    $protocolUsed = 'RPC (qwinsta)'
    $rows = @()
    $rawLines = @()

    $qwinstaExe = Resolve-QwinstaPath

    if ($null -eq $Credential -and $null -ne $qwinstaExe) {
        $targetArg = if ($isLocal) { 'localhost' } else { $ComputerName.Trim() }
        $rawOut = if ($isLocal) { & $qwinstaExe 2>&1 } else { & $qwinstaExe "/server:$targetArg" 2>&1 }
        $exitCode = $LASTEXITCODE
        $rawLines = @($rawOut | ForEach-Object { [string]$_ })

        if ($exitCode -ne 0) {
            $errText = ($rawLines -join ' ').Trim()
            throw "qwinsta /server:$targetArg failed (ExitCode $exitCode): $errText"
        }

        $rows = @(ConvertFrom-QwinstaOutput -Lines $rawLines -FilterText $UserFilter)
    }
    elseif ($null -ne $Credential) {
        try {
            $remRes = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock {
                $exe = Join-Path $env:SystemRoot 'System32\qwinsta.exe'
                if (-not (Test-Path -LiteralPath $exe)) { return [PSCustomObject]@{ Found = $false; Lines = @(); ExitCode = -1 } }
                $out = & $exe 2>&1
                return [PSCustomObject]@{ Found = $true; Lines = @($out | ForEach-Object { [string]$_ }); ExitCode = $LASTEXITCODE }
            }
            $protocolUsed = $remRes.ProtocolUsed
            foreach ($w in @($remRes.Warnings)) { $warnings.Add($w) }
            if (-not $remRes.Data.Found) {
                $warnings.Add("qwinsta.exe not found on '$ComputerName'; using WMI Win32_LogonSession/Win32_Process.")
                $wmiRes = Get-WmiTerminalSessionsFallback -Target $ComputerName -Cred $Credential -Proto $Protocol -FilterText $UserFilter
                $rows = @($wmiRes.Rows)
                $protocolUsed = $wmiRes.ProtocolUsed
            } else {
                $rows = @(ConvertFrom-QwinstaOutput -Lines $remRes.Data.Lines -FilterText $UserFilter)
            }
        }
        catch {
            if ($Protocol -in @('Auto', 'CIM-DCOM', 'RPC')) {
                $warnings.Add("Remote qwinsta via WinRM failed ($($_.Exception.Message)); falling back to WMI using '$($Credential.UserName)'.")
                $wmiRes = Get-WmiTerminalSessionsFallback -Target $ComputerName -Cred $Credential -Proto 'CIM-DCOM' -FilterText $UserFilter
                $rows = @($wmiRes.Rows)
                $protocolUsed = $wmiRes.ProtocolUsed
            }
            else {
                throw
            }
        }
    }
    else {
        $warnings.Add("qwinsta.exe is not installed on '$env:COMPUTERNAME' (Windows Home); using WMI Win32_LogonSession + Win32_Process (WMI Kill enabled).")
        $wmiRes = Get-WmiTerminalSessionsFallback -Target $ComputerName -Cred $Credential -Proto $Protocol -FilterText $UserFilter
        $rows = @($wmiRes.Rows)
        $protocolUsed = $wmiRes.ProtocolUsed
    }

    $activeCount = @($rows | Where-Object { $_.State -eq 'Active' }).Count
    $discCount   = @($rows | Where-Object { $_.State -eq 'Disc' }).Count

    $schema = @(
        @{ key = 'Severity';    label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'SessionId';   label = 'Session ID';   type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'SessionName'; label = 'Session Name'; type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';         type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'State';       label = 'State';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Type';        label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Device';      label = 'Device/Procs'; type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Raw Output';   type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'rdp_sessions_total';  label = 'Active/Disc Sessions';  value = $rows.Count;   unit = 'sessions'; severity = 'info' }
        @{ key = 'rdp_sessions_active'; label = 'Active User Sessions';  value = $activeCount;  unit = 'active';   severity = 'info' }
        @{ key = 'rdp_sessions_disc';   label = 'Disconnected Sessions'; value = $discCount;    unit = 'disc';     severity = if ($discCount -gt 0) { 'warning' } else { 'ok' } }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '11.3-rdp-sessions' -Category 'Remote Connectivity' -SubCategory 'Active Terminal Sessions (qwinsta / WMI)' -TargetServer $ComputerName -ProtocolUsed $protocolUsed -DurationMs $sw.ElapsedMilliseconds -Status 'Success' -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '11.3-rdp-sessions' -Category 'Remote Connectivity' -SubCategory 'Active Terminal Sessions (qwinsta / WMI)' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings.ToArray() -Errors $errors.ToArray() | ConvertTo-WinInspectorJson
}
