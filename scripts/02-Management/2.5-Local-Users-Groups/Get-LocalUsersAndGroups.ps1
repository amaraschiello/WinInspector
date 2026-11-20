#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Local Users, Local Groups, and Local Group Memberships (including Administrators & RDP Users).
.NOTES
    Category:  02-Management / 2.5-Local-Users-Groups
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

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        foreach ($u in @(Get-LocalUser -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                ObjectType  = 'Local User'
                Name        = $u.Name
                Enabled     = [string]$u.Enabled
                LastLogon   = if ($u.LastLogon) { $u.LastLogon.ToUniversalTime().ToString('o') } else { 'Never' }
                Members     = ''
                Summary     = "User: $($u.Name) | Enabled: $($u.Enabled) | LastLogon: $(if ($u.LastLogon) { $u.LastLogon } else { 'Never' })"
                RawMessage  = ($u | Format-List Name,Enabled,FullName,Description,LastLogon,PasswordLastSet,PasswordExpires,SID | Out-String)
            })
        }

        foreach ($g in @(Get-LocalGroup -ErrorAction SilentlyContinue)) {
            $mems = @()
            try { $mems = @(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) ($($_.ObjectClass))" }) } catch {}
            $memStr = $mems -join '; '
            $out.Add([PSCustomObject]@{
                ObjectType  = 'Local Group'
                Name        = $g.Name
                Enabled     = 'Group'
                LastLogon   = ''
                Members     = $memStr
                Summary     = "Group: $($g.Name) | Members ($($mems.Count)): $memStr"
                RawMessage  = "Group: $($g.Name)`nDescription: $($g.Description)`nMembers:`n$($mems -join "`n")"
            })
        }
    }
    else {
        foreach ($u in @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
            $out.Add([PSCustomObject]@{
                ObjectType  = 'Local User'
                Name        = $u.Name
                Enabled     = [string](-not $u.Disabled)
                LastLogon   = ''
                Members     = ''
                Summary     = "User: $($u.Name) | Disabled: $($u.Disabled) | Lockout: $($u.Lockout)"
                RawMessage  = ($u | Format-List | Out-String)
            })
        }
    }

    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)

    $schema = @(
        @{ key = 'ObjectType'; label = 'Type';         type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Name';       label = 'Name';         type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Enabled';    label = 'Enabled';      type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'LastLogon';  label = 'Last Logon';   type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Members';    label = 'Members';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'ug_total'; label = 'Local Users & Groups'; value = $rows.Count; unit = 'objects'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.5-local-users-groups' -Category 'Management' -SubCategory 'Local Users & Groups' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.5-local-users-groups' -Category 'Management' -SubCategory 'Local Users & Groups' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
