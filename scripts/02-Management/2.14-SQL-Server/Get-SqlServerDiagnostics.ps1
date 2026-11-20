#Requires -Version 5.1
<#
.SYNOPSIS
    Audits SQL Server instances/services, TCP listeners, Databases/Recovery Models, active blocking SPIDs,
    and SQL Application Event Log errors (read-only).
.NOTES
    Category:  02-Management / 2.14-SQL-Server
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto',
    [Parameter()] [ValidateRange(1, 720)] [int]$HoursBack = 72
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    param($Hours)
    $out = New-Object System.Collections.Generic.List[object]
    $sqlSvcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLSERVERAGENT*' -or $_.Name -eq 'SQLBrowser' })

    foreach ($sv in $sqlSvcs) {
        $out.Add([PSCustomObject]@{
            Severity   = if ($sv.Status -ne 'Running' -and $sv.StartType -eq 'Automatic') { 'Warning' } else { 'Info' }
            Category   = 'SQL Service'
            Instance   = $sv.Name
            Detail     = "$($sv.DisplayName) ($($sv.StartType))"
            State      = [string]$sv.Status
            Summary    = "$($sv.Name): $($sv.Status) ($($sv.StartType))"
            RawMessage = ($sv | Format-List Name,DisplayName,Status,StartType | Out-String)
        })
    }

    # Named Pipes & SQL TCP Listeners
    foreach ($p in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in @(1433, 1434, 4022, 5022) })) {
        $proc = (Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $out.Add([PSCustomObject]@{
            Severity   = 'Info'
            Category   = 'SQL Listener'
            Instance   = "$($p.LocalAddress):$($p.LocalPort)"
            Detail     = "Process: $proc (PID $($p.OwningProcess))"
            State      = 'Listening'
            Summary    = "SQL TCP Listener on $($p.LocalAddress):$($p.LocalPort) ($proc)"
            RawMessage = ($p | Format-List | Out-String)
        })
    }

    # Read-only query via System.Data.SqlClient against local default/named instances (Trusted_Connection=True)
    $engineSvcs = @($sqlSvcs | Where-Object { ($_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*') -and $_.Status -eq 'Running' })
    foreach ($es in $engineSvcs) {
        $instName = if ($es.Name -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$($es.Name.Substring(6))" }
        $conn = $null
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection("Server=$instName;Database=master;Integrated Security=True;Connect Timeout=3;TrustServerCertificate=True;")
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "SELECT name, state_desc, recovery_model_desc, compatibility_level FROM sys.databases ORDER BY name;"
            $rdr = $cmd.ExecuteReader()
            while ($rdr.Read()) {
                $dbName = [string]$rdr['name']
                $stDesc = [string]$rdr['state_desc']
                $recMod = [string]$rdr['recovery_model_desc']
                $out.Add([PSCustomObject]@{
                    Severity   = if ($stDesc -ne 'ONLINE') { 'Warning' } else { 'Info' }
                    Category   = 'SQL Database'
                    Instance   = "$instName / $dbName"
                    Detail     = "Recovery: $recMod | Compat: $($rdr['compatibility_level'])"
                    State      = $stDesc
                    Summary    = "DB '$dbName' ($instName): $stDesc | $recMod"
                    RawMessage = "Instance: $instName`nDatabase: $dbName`nState: $stDesc`nRecovery: $recMod"
                })
            }
            $rdr.Close()

            $blkCmd = $conn.CreateCommand()
            $blkCmd.CommandText = "SELECT session_id, blocking_session_id, wait_type, wait_time, status, command FROM sys.dm_exec_requests WHERE blocking_session_id > 0;"
            $blkRdr = $blkCmd.ExecuteReader()
            while ($blkRdr.Read()) {
                $out.Add([PSCustomObject]@{
                    Severity   = 'Warning'
                    Category   = 'SQL Blocking SPID'
                    Instance   = "$instName SPID $($blkRdr['session_id'])"
                    Detail     = "Blocked by SPID $($blkRdr['blocking_session_id']) | Wait: $($blkRdr['wait_type']) ($($blkRdr['wait_time'])ms)"
                    State      = [string]$blkRdr['status']
                    Summary    = "SPID $($blkRdr['session_id']) blocked by $($blkRdr['blocking_session_id']) ($($blkRdr['wait_type']))"
                    RawMessage = "Blocking SPID $($blkRdr['blocking_session_id']) blocking $($blkRdr['session_id'])"
                })
            }
            $blkRdr.Close()
        }
        catch {
            $out.Add([PSCustomObject]@{
                Severity   = 'Warning'
                Category   = 'SQL Query'
                Instance   = $instName
                Detail     = $_.Exception.Message
                State      = 'Access/Conn Note'
                Summary    = "Could not query $instName via Integrated Security: $($_.Exception.Message)"
                RawMessage = $_.Exception.Message
            })
        }
        finally {
            if ($null -ne $conn) { try { $conn.Close(); $conn.Dispose() } catch {} }
        }
    }

    # SQL Application Event Log errors
    $startTime = (Get-Date).AddHours(-$Hours)
    try {
        foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = @(1, 2, 3); StartTime = $startTime } -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like '*MSSQL*' -or $_.ProviderName -like '*SQL*' })) {
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $out.Add([PSCustomObject]@{
                Severity   = if ($ev.Level -le 2) { 'Error' } else { 'Warning' }
                Category   = "SQL Event ($($ev.Id))"
                Instance   = $ev.ProviderName
                Detail     = $ev.TimeCreated.ToUniversalTime().ToString('o')
                State      = "Event $($ev.Id)"
                Summary    = ($msg -split "`r?`n")[0]
                RawMessage = $msg
            })
        }
    } catch {}

    return [PSCustomObject]@{ Rows = $out.ToArray(); ServiceCount = $sqlSvcs.Count }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript -ArgumentList @($HoursBack)
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity';   label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Category';   label = 'Category';     type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Instance';   label = 'Instance/DB';  type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'State';      label = 'State';        type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Detail';     label = 'Detail';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'sql_svcs';  label = 'SQL Services'; value = $res.Data.ServiceCount; unit = 'services'; severity = 'info' }
        @{ key = 'sql_items'; label = 'SQL Findings'; value = $rows.Count;            unit = 'items';    severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.14-sql-server' -Category 'Management' -SubCategory 'SQL Server Diagnostics' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.14-sql-server' -Category 'Management' -SubCategory 'SQL Server Diagnostics' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
