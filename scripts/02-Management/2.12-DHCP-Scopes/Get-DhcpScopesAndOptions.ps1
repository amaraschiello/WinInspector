#Requires -Version 5.1
<#
.SYNOPSIS
    Reports DHCP Server IPv4 Scopes, Scope Statistics (% InUse, Free), and Scope/Server DHCP Options.
.NOTES
    Category:  02-Management / 2.12-DHCP-Scopes
    Protocols: WinRM
    ReadOnly:  True
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ComputerName,
    [Parameter()] [System.Management.Automation.PSCredential]$Credential,
    [Parameter()] [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')] [string]$Protocol = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()

$remoteScript = {
    $out = New-Object System.Collections.Generic.List[object]
    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    $svcState = if ($svc) { [string]$svc.Status } else { 'NotInstalled' }

    if (-not (Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
        $out.Add([PSCustomObject]@{
            Severity   = 'Info'
            Type       = 'DHCP Server Role'
            ScopeId    = 'N/A'
            Name       = 'DhcpServer Module'
            State      = $svcState
            Options    = ''
            Summary    = "DHCPServer service: $svcState (DhcpServer PowerShell module not present)."
            RawMessage = "Install RSAT-DHCP / DHCP Server role to query scopes & options."
        })
        return [PSCustomObject]@{ Rows = $out.ToArray(); ScopeCount = 0; SvcState = $svcState }
    }

    # Server-level options
    try {
        foreach ($so in @(Get-DhcpServerv4OptionValue -ErrorAction SilentlyContinue)) {
            $vals = (@($so.Value) -join ', ')
            $out.Add([PSCustomObject]@{
                Severity   = 'Info'
                Type       = 'Server Option'
                ScopeId    = 'Server-Wide'
                Name       = "Option $($so.OptionId) ($($so.Name))"
                State      = 'Active'
                Options    = $vals
                Summary    = "Server Option $($so.OptionId) ($($so.Name)) = $vals"
                RawMessage = ($so | Format-List | Out-String)
            })
        }
    } catch {}

    $scopes = @(Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)
    foreach ($sc in $scopes) {
        $st = Get-DhcpServerv4ScopeStatistics -ScopeId $sc.ScopeId -ErrorAction SilentlyContinue
        $pct = if ($st) { [math]::Round([double]$st.PercentageInUse, 1) } else { 0 }
        $free = if ($st) { [int]$st.Free } else { 0 }
        $inUse = if ($st) { [int]$st.InUse } else { 0 }
        $opts = @()
        try {
            $opts = @(Get-DhcpServerv4OptionValue -ScopeId $sc.ScopeId -ErrorAction SilentlyContinue | ForEach-Object { "Opt$($_.OptionId)($($_.Name))=$(@($_.Value) -join ',')" })
        } catch {}
        $optStr = $opts -join ' | '
        $sev = if ($sc.State -ne 'Active' -or $pct -ge 90) { 'Warning' } else { 'Info' }

        $out.Add([PSCustomObject]@{
            Severity   = $sev
            Type       = 'IPv4 Scope'
            ScopeId    = [string]$sc.ScopeId
            Name       = $sc.Name
            State      = "$($sc.State) ($pct% used: $inUse / $($inUse + $free))"
            Options    = $optStr
            Summary    = "Scope $($sc.ScopeId) ($($sc.Name)) | Range: $($sc.StartRange)-$($sc.EndRange) | $pct% used ($free free)"
            RawMessage = (($sc | Format-List | Out-String) + "`n" + ($st | Format-List | Out-String) + "`nOptions:`n$($opts -join "`n")")
        })
    }

    return [PSCustomObject]@{ Rows = $out.ToArray(); ScopeCount = $scopes.Count; SvcState = $svcState }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Severity'; label = 'Severity';     type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Type';     label = 'Type';         type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ScopeId';  label = 'Scope ID';     type = 'string';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';     label = 'Name / Option';type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'State';    label = 'State / Usage';type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Options';  label = 'Values';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'dhcp_svc';    label = 'DHCPServer Service'; value = $res.Data.SvcState;   unit = '';       severity = 'info' }
        @{ key = 'dhcp_scopes'; label = 'IPv4 Scopes';        value = $res.Data.ScopeCount; unit = 'scopes'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.12-dhcp-scopes-options' -Category 'Management' -SubCategory 'DHCP Scopes & Options' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.12-dhcp-scopes-options' -Category 'Management' -SubCategory 'DHCP Scopes & Options' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
