#Requires -Version 5.1
<#
.SYNOPSIS
    Reports detailed Disk, Partition (GPT/MBR, offsets), and Volume (NTFS/ReFS, cluster size, capacity) information.
.NOTES
    Category:  02-Management / 2.4-Disk-Partitions
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

    foreach ($d in @(Get-Disk -ErrorAction SilentlyContinue)) {
        $out.Add([PSCustomObject]@{
            Kind           = 'Physical Disk'
            Identifier     = "Disk $($d.Number): $($d.FriendlyName)"
            StyleOrFs      = [string]$d.PartitionStyle
            BusOrType      = [string]$d.BusType
            SizeGB         = [math]::Round([double]$d.Size / 1GB, 2)
            FreeGB         = $null
            Health         = [string]$d.HealthStatus
            Summary        = "Disk $($d.Number) ($($d.FriendlyName)) | $($d.PartitionStyle) | $($d.BusType) | $([math]::Round($d.Size/1GB,1)) GB | $($d.HealthStatus)"
            RawMessage     = ($d | Format-List Number,FriendlyName,SerialNumber,BusType,PartitionStyle,OperationalStatus,HealthStatus,Size | Out-String)
        })
    }

    foreach ($p in @(Get-Partition -ErrorAction SilentlyContinue)) {
        $dl = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { '(No Drive Letter)' }
        $out.Add([PSCustomObject]@{
            Kind           = 'Partition'
            Identifier     = "Disk $($p.DiskNumber) Part $($p.PartitionNumber) ($dl)"
            StyleOrFs      = [string]$p.Type
            BusOrType      = if ($p.GptType) { [string]$p.GptType } else { "MBR $($p.MbrType)" }
            SizeGB         = [math]::Round([double]$p.Size / 1GB, 2)
            FreeGB         = $null
            Health         = if ($p.IsActive -or $p.IsBoot) { 'Boot/Active' } else { 'Normal' }
            Summary        = "Disk $($p.DiskNumber) Partition $($p.PartitionNumber) $dl | Type: $($p.Type) | $([math]::Round($p.Size/1GB,2)) GB"
            RawMessage     = ($p | Format-List DiskNumber,PartitionNumber,DriveLetter,Type,GptType,Size,Offset,IsBoot,IsSystem,IsActive | Out-String)
        })
    }

    foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue)) {
        $id = if ($v.DriveLetter) { "$($v.DriveLetter): ($($v.FileSystemLabel))" } else { "$($v.FileSystemLabel) $($v.UniqueId)" }
        $sz = [math]::Round([double]$v.Size / 1GB, 2)
        $fr = [math]::Round([double]$v.SizeRemaining / 1GB, 2)
        $out.Add([PSCustomObject]@{
            Kind           = 'Volume'
            Identifier     = $id.Trim()
            StyleOrFs      = [string]$v.FileSystemType
            BusOrType      = "Cluster $($v.AllocationUnitSize) B"
            SizeGB         = $sz
            FreeGB         = $fr
            Health         = [string]$v.HealthStatus
            Summary        = "Volume $id | $($v.FileSystemType) | $fr / $sz GB free | $($v.HealthStatus)"
            RawMessage     = ($v | Format-List DriveLetter,FileSystemLabel,FileSystemType,AllocationUnitSize,Size,SizeRemaining,HealthStatus,OperationalStatus,DedupMode | Out-String)
        })
    }

    return $out.ToArray()
}

try {
    $res = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock $remoteScript
    foreach ($w in @($res.Warnings)) { $warnings.Add($w) }
    $rows = @($res.Data)

    $schema = @(
        @{ key = 'Kind';       label = 'Object Type';  type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Identifier'; label = 'Disk / Vol';   type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'StyleOrFs';  label = 'Style / FS';   type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'BusOrType';  label = 'Bus / Detail'; type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'SizeGB';     label = 'Size (GB)';    type = 'number'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'FreeGB';     label = 'Free (GB)';    type = 'number'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Health';     label = 'Health/Flag';  type = 'string'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';    label = 'Summary';      type = 'string'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage'; label = 'Full Details'; type = 'string'; filterable = $false; facet = $false; defaultVisible = $false }
    )
    $metrics = @(
        @{ key = 'disk_items'; label = 'Disks / Partitions / Volumes'; value = $rows.Count; unit = 'objects'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult -ScriptId '2.4-disk-partitions' -Category 'Management' -SubCategory 'Disks, Partitions & Volumes' -TargetServer $ComputerName -ProtocolUsed $res.ProtocolUsed -DurationMs $sw.ElapsedMilliseconds -Schema $schema -Metrics $metrics -Data $rows -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult -ScriptId '2.4-disk-partitions' -Category 'Management' -SubCategory 'Disks, Partitions & Volumes' -TargetServer $ComputerName -ProtocolUsed $Protocol -DurationMs $sw.ElapsedMilliseconds -Status 'Error' -Warnings $warnings -Errors $errors | ConvertTo-WinInspectorJson
}
