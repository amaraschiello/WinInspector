#Requires -Version 5.1
<#
.SYNOPSIS
    Reports SMB Shares, Share & NTFS ACL permissions, and Open Files mapped to accessing users and processes.
.NOTES
    Category:  02-Management / 2.9-NTFS-Shares-OpenFiles
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

    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue)
    foreach ($sh in $shares) {
        $sharePerms = ''
        try {
            $sharePerms = (@(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue) | ForEach-Object { "$($_.AccountName):$($_.AccessRight)($($_.AccessControlType))" }) -join '; '
        } catch {}

        $ntfsPerms = ''
        if ($sh.Path -and (Test-Path -LiteralPath $sh.Path -ErrorAction SilentlyContinue)) {
            try {
                $acl = Get-Acl -LiteralPath $sh.Path -ErrorAction SilentlyContinue
                if ($acl) {
                    $ntfsPerms = (@($acl.Access) | Select-Object -First 10 | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)($($_.AccessControlType))" }) -join '; '
                }
            } catch {}
        }

        $out.Add([PSCustomObject]@{
            Kind       = 'Share & NTFS ACL'
            NameOrFile = $sh.Name
            Path       = $sh.Path
            UserOrAcct = $sharePerms
            Process    = 'SMB Server'
            Detail     = $ntfsPerms
            Summary    = "Share \\$env:COMPUTERNAME\$($sh.Name) ($($sh.Path)) | Share: $sharePerms"
            RawMessage = "Share: $($sh.Name)`nPath: $($sh.Path)`nShare ACL: $sharePerms`nNTFS ACL: $ntfsPerms"
        })
    }

    # Open SMB Files
    $openFiles = @(Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object -First 200)
    foreach ($of in $openFiles) {
        $out.Add([PSCustomObject]@{
            Kind       = 'SMB Open File'
            NameOrFile = [System.IO.Path]::GetFileName([string]$of.Path)
            Path       = [string]$of.Path
            UserOrAcct = "$($of.ClientUserName) @ $($of.ClientComputerName)"
            Process    = "SMB Session $($of.SessionId)"
            Detail     = "Locks: $($of.Locks) | ShareRelativePath: $($of.ShareRelativePath)"
            Summary    = "Open SMB File: $($of.Path) | User: $($of.ClientUserName) ($($of.ClientComputerName)) | Locks: $($of.Locks)"
            RawMessage = ($of | Format-List | Out-String)
        })
    }

    # Local processes with open file / handle counts (top 40 by HandleCount)
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Sort-Object HandleCount -Descending | Select-Object -First 40)) {
        $pPath = try { [string]$p.Path } catch { '' }
        $out.Add([PSCustomObject]@{
            Kind       = 'Process File Handles'
            NameOrFile = "$($p.ProcessName) (PID $($p.Id))"
            Path       = $pPath
            UserOrAcct = ''
            Process    = $p.ProcessName
            Detail     = "Handles: $($p.HandleCount) | Threads: $($p.Threads.Count)"
            Summary    = "$($p.ProcessName) (PID $($p.Id)) holds $($p.HandleCount) open handles"
            RawMessage = ($p | Format-List Id,ProcessName,HandleCount,Path,MainModule | Out-String)
        })
    }

    return [PSCustomObject]@{
        Rows          = $out.ToArray()
        ShareCount    = $shares.Count
        OpenFileCount = $openFiles.Count
    }
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data.Rows)

    $schema = @(
        @{ key = 'Kind';       label = 'Category';     type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'NameOrFile'; label = 'Share / File'; type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Path';       label = 'Path';         type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'UserOrAcct'; label = 'ACL / User';   type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Process';    label = 'Process';      type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Detail';     label = 'NTFS / Locks'; type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'smb_shares'; label = 'SMB Shares';     value = $res.Data.ShareCount;    unit = 'shares'; severity = 'info' }
        @{ key = 'open_files'; label = 'SMB Open Files'; value = $res.Data.OpenFileCount; unit = 'files';  severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.9-ntfs-shares-open-files' -Category 'Management' -SubCategory 'NTFS Shares, Permissions & Open Files' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.9-ntfs-shares-open-files' -Category 'Management' -SubCategory 'NTFS Shares, Permissions & Open Files' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
