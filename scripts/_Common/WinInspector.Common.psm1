#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helper module for WinInspector diagnostic scripts.
.DESCRIPTION
    Provides strict hostname validation, local/remote protocol negotiation
    (WinRM-HTTPS, WinRM-HTTP, CIM-DCOM, RPC), Event XML parsing helpers,
    and standardized JSON result envelope builders.
#>

Set-StrictMode -Version Latest
$script:WinInspectorLastExecutedAs = $null

function Resolve-WinInspectorTargetHost {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $trimmed = $ComputerName.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $trimmed }
    if ($trimmed -in @('.', 'localhost', '127.0.0.1', '::1')) { return $trimmed }

    $ipObj = $null
    if ([System.Net.IPAddress]::TryParse($trimmed, [ref]$ipObj)) {
        return $trimmed
    }

    # Already an FQDN
    if ($trimmed.Contains('.')) {
        return $trimmed
    }

    # Resolve short NetBIOS hostname to canonical DNS FQDN for Kerberos SPN matching
    try {
        $entry = [System.Net.Dns]::GetHostEntry($trimmed)
        if ($entry -and -not [string]::IsNullOrWhiteSpace($entry.HostName) -and $entry.HostName.Contains('.')) {
            return $entry.HostName.Trim()
        }
    }
    catch {
        # Keep original hostname if DNS reverse/FQDN resolution fails
    }

    return $trimmed
}

function Test-WinInspectorHostName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $false
    }

    $trimmed = $ComputerName.Trim()
    if ($trimmed -eq '.') { return $true }

    # Allow valid IPv4/IPv6
    $ipObj = $null
    if ([System.Net.IPAddress]::TryParse($trimmed, [ref]$ipObj)) {
        return $true
    }

    # Strict NetBIOS hostname or FQDN (RFC 1123 + Windows NetBIOS)
    return ($trimmed -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
}

function Test-WinInspectorIsLocal {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $t = $ComputerName.Trim().ToLowerInvariant()
    if ($t -in @('.', 'localhost', '127.0.0.1', '::1', $env:COMPUTERNAME.ToLowerInvariant())) {
        return $true
    }

    try {
        $localFqdn = [System.Net.Dns]::GetHostEntry('').HostName.ToLowerInvariant()
        if ($t -eq $localFqdn) { return $true }
    }
    catch {
        # Ignore DNS lookup failure for local FQDN check
    }

    return $false
}

function Test-WinInspectorTcpPort {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter()]
        [int]$TimeoutMs = 1500
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async  = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $wait   = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($wait -and $client.Connected) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $client) {
            try { $client.Close() } catch {}
            try { $client.Dispose() } catch {}
        }
    }
}

function New-WinInspectorCimSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')]
        [string]$Protocol = 'Auto'
    )

    if (-not (Test-WinInspectorHostName -ComputerName $ComputerName)) {
        throw "Invalid ComputerName '$ComputerName'."
    }

    $script:WinInspectorLastExecutedAs = if ($null -ne $Credential) {
        $Credential.UserName
    } else {
        try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    }

    $isLocal = (Test-WinInspectorIsLocal -ComputerName $ComputerName) -and ($null -eq $Credential)
    if ($isLocal -and $Protocol -eq 'Auto') {
        return [PSCustomObject]@{
            Session      = $null
            ProtocolUsed = 'Local'
            IsLocal      = $true
            ExecutedAs   = $script:WinInspectorLastExecutedAs
        }
    }

    $targetHost = if (Test-WinInspectorIsLocal -ComputerName $ComputerName) {
        $ComputerName.Trim()
    } else {
        Resolve-WinInspectorTargetHost -ComputerName $ComputerName
    }

    $attempts = switch ($Protocol) {
        'WinRM-HTTPS' { @('WinRM-HTTPS') }
        'WinRM-HTTP'  { @('WinRM-HTTP') }
        'CIM-DCOM'    { @('CIM-DCOM') }
        'RPC'         { @('CIM-DCOM') }
        default       { @('WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM') }
    }

    $attemptErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($mode in $attempts) {
        if ($Protocol -eq 'Auto') {
            $portToCheck = switch ($mode) {
                'WinRM-HTTPS' { 5986 }
                'WinRM-HTTP'  { 5985 }
                default       { 135 }
            }
            if (-not (Test-WinInspectorTcpPort -ComputerName $targetHost -Port $portToCheck -TimeoutMs 1200)) {
                continue
            }
        }

        try {
            $cimParams = @{
                ComputerName = $targetHost
                ErrorAction  = 'Stop'
            }
            if ($null -ne $Credential) {
                $cimParams['Credential'] = $Credential
            }

            if ($mode -eq 'WinRM-HTTPS') {
                $opt = New-CimSessionOption -Protocol Wsman -UseSsl
                $cimParams['SessionOption'] = $opt
                $cimParams['Port'] = 5986
            }
            elseif ($mode -eq 'WinRM-HTTP') {
                $opt = New-CimSessionOption -Protocol Wsman
                $cimParams['SessionOption'] = $opt
                $cimParams['Port'] = 5985
            }
            else {
                $opt = New-CimSessionOption -Protocol Dcom
                $cimParams['SessionOption'] = $opt
            }

            $session = New-CimSession @cimParams
            return [PSCustomObject]@{
                Session      = $session
                ProtocolUsed = $mode
                IsLocal      = $false
                TargetHost   = $targetHost
                ExecutedAs   = $script:WinInspectorLastExecutedAs
            }
        }
        catch {
            $attemptErrors.Add("${mode}: $($_.Exception.Message)")
        }
    }

    $errSummary = if ($attemptErrors.Count -gt 0) {
        $attemptErrors -join ' | '
    } else {
        "No management ports (5986/5985/135) are reachable on '$targetHost'."
    }
    throw "Failed to establish CIM session to '$targetHost' as '$($script:WinInspectorLastExecutedAs)' using protocol '$Protocol': $errSummary"
}

function Invoke-WinInspectorRemote {
    <#
    .SYNOPSIS
        Executes a self-contained, WinPS 5.1-compatible ScriptBlock locally or remotely
        via WinRM (HTTPS/HTTP), with optional FallbackScriptBlock for RPC/DCOM mode.
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

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [scriptblock]$FallbackScriptBlock
    )

    if (-not (Test-WinInspectorHostName -ComputerName $ComputerName)) {
        throw "Invalid ComputerName '$ComputerName'."
    }

    $script:WinInspectorLastExecutedAs = if ($null -ne $Credential) {
        $Credential.UserName
    } else {
        try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    }

    $warnings = [System.Collections.Generic.List[string]]::new()

    # Fast local execution when targeting local machine without explicit alternate creds
    if ((Test-WinInspectorIsLocal -ComputerName $ComputerName) -and ($null -eq $Credential) -and ($Protocol -eq 'Auto')) {
        $data = & $ScriptBlock @ArgumentList
        return [PSCustomObject]@{
            ProtocolUsed = 'Local'
            Data         = $data
            ExecutedAs   = $script:WinInspectorLastExecutedAs
            Warnings     = $warnings.ToArray()
        }
    }

    $targetHost = if (Test-WinInspectorIsLocal -ComputerName $ComputerName) {
        $ComputerName.Trim()
    } else {
        Resolve-WinInspectorTargetHost -ComputerName $ComputerName
    }

    # Explicit RPC/DCOM fallback requested
    if ($Protocol -in @('CIM-DCOM', 'RPC')) {
        if ($null -ne $FallbackScriptBlock) {
            $data = & $FallbackScriptBlock $targetHost $Credential $Protocol @ArgumentList
            return [PSCustomObject]@{
                ProtocolUsed = $Protocol
                Data         = $data
                ExecutedAs   = $script:WinInspectorLastExecutedAs
                Warnings     = $warnings.ToArray()
            }
        }
        throw "This diagnostic requires WinRM remoting and does not support pure $Protocol fallback."
    }

    $winRmModes = switch ($Protocol) {
        'WinRM-HTTPS' { @('WinRM-HTTPS') }
        'WinRM-HTTP'  { @('WinRM-HTTP') }
        default       { @('WinRM-HTTPS', 'WinRM-HTTP') }
    }

    $lastError = $null
    foreach ($mode in $winRmModes) {
        # Quick port probe in Auto mode so we fail fast instead of waiting 30s on closed 5986
        if ($Protocol -eq 'Auto') {
            $portToCheck = if ($mode -eq 'WinRM-HTTPS') { 5986 } else { 5985 }
            if (-not (Test-WinInspectorTcpPort -ComputerName $targetHost -Port $portToCheck -TimeoutMs 1200)) {
                continue
            }
        }

        $session = $null
        try {
            $sessParams = @{
                ComputerName  = $targetHost
                ErrorAction   = 'Stop'
                SessionOption = (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 90000)
            }
            if ($null -ne $Credential) {
                $sessParams['Credential'] = $Credential
            }
            if ($mode -eq 'WinRM-HTTPS') {
                $sessParams['UseSSL'] = $true
            }

            $session = New-PSSession @sessParams
            try {
                $remoteWho = Invoke-Command -Session $session -ScriptBlock {
                    try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" }
                } -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace([string]$remoteWho)) {
                    $script:WinInspectorLastExecutedAs = ([string]$remoteWho).Trim()
                }
            } catch {}

            $data = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
            return [PSCustomObject]@{
                ProtocolUsed = $mode
                Data         = $data
                ExecutedAs   = $script:WinInspectorLastExecutedAs
                Warnings     = $warnings.ToArray()
            }
        }
        catch {
            $lastError = $_
        }
        finally {
            if ($null -ne $session) {
                try { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } catch {}
            }
        }
    }

    # Auto fallback to RPC/CIM-DCOM if available
    if (($Protocol -eq 'Auto') -and ($null -ne $FallbackScriptBlock)) {
        $warnings.Add("WinRM unreachable on '$targetHost' as '$($script:WinInspectorLastExecutedAs)'; automatically fell back to RPC/CIM-DCOM.")
        $data = & $FallbackScriptBlock $targetHost $Credential 'RPC' @ArgumentList
        return [PSCustomObject]@{
            ProtocolUsed = 'RPC/CIM-DCOM (Fallback)'
            Data         = $data
            ExecutedAs   = $script:WinInspectorLastExecutedAs
            Warnings     = $warnings.ToArray()
        }
    }

    $errMsg = if ($null -ne $lastError) { $lastError.Exception.Message } else { "WinRM ports (5986/5985) are not reachable on '$targetHost'." }
    throw "Remote execution failed on '$targetHost' as '$($script:WinInspectorLastExecutedAs)': $errMsg"
}

function ConvertFrom-WinEventXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$EventRecord
    )

    $map = @{}
    try {
        $xml = [xml]$EventRecord.ToXml()
        if ($null -ne $xml.Event.EventData -and $null -ne $xml.Event.EventData.Data) {
            $idx = 0
            foreach ($node in $xml.Event.EventData.Data) {
                if ($node -is [System.Xml.XmlElement]) {
                    $key = if ($node.HasAttribute('Name')) { $node.GetAttribute('Name') } else { "Param$idx" }
                    $map[$key] = $node.InnerText
                }
                else {
                    $map["Param$idx"] = [string]$node
                }
                $idx++
            }
        }
        elseif ($null -ne $xml.Event.UserData) {
            foreach ($child in $xml.Event.UserData.ChildNodes) {
                foreach ($leaf in $child.ChildNodes) {
                    if ($leaf.Name) { $map[$leaf.Name] = $leaf.InnerText }
                }
            }
        }
    }
    catch {
        # Best-effort XML extraction
    }
    return $map
}

function Format-WinInspectorSeverity {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Level
    )

    switch ([string]$Level) {
        '1'           { return 'Critical' }
        'Critical'    { return 'Critical' }
        '2'           { return 'Error' }
        'Error'       { return 'Error' }
        '3'           { return 'Warning' }
        'Warning'     { return 'Warning' }
        '4'           { return 'Info' }
        'Information' { return 'Info' }
        '0'           { return 'Info' }
        default       { return 'Info' }
    }
}

function New-WinInspectorResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptId,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$SubCategory,

        [Parameter(Mandatory)]
        [string]$TargetServer,

        [Parameter()]
        [string]$ProtocolUsed = 'Auto',

        [Parameter()]
        [long]$DurationMs = 0,

        [Parameter()]
        [ValidateSet('Success', 'Partial', 'Error')]
        [string]$Status = 'Success',

        [Parameter()]
        [object[]]$Schema = @(),

        [Parameter()]
        [object[]]$Metrics = @(),

        [Parameter()]
        [object[]]$Data = @(),

        [Parameter()]
        [string[]]$Warnings = @(),

        [Parameter()]
        [string[]]$Errors = @(),

        [Parameter()]
        [string]$ExecutedAs = ''
    )

    $resolvedExecutedAs = if (-not [string]::IsNullOrWhiteSpace($ExecutedAs)) {
        $ExecutedAs.Trim()
    }
    elseif (-not [string]::IsNullOrWhiteSpace($script:WinInspectorLastExecutedAs)) {
        $script:WinInspectorLastExecutedAs
    }
    else {
        try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    }
    $script:WinInspectorLastExecutedAs = $null

    $rowArray     = @($Data | Where-Object { $null -ne $_ })
    $schemaArray  = @($Schema | Where-Object { $null -ne $_ })
    $metricsArray = @($Metrics | Where-Object { $null -ne $_ })
    $warnArray    = @($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $errArray     = @($Errors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    return [ordered]@{
        meta    = [ordered]@{
            scriptId      = $ScriptId
            category      = $Category
            subCategory   = $SubCategory
            targetServer  = $TargetServer
            protocolUsed  = $ProtocolUsed
            executedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            durationMs    = $DurationMs
            executedAs    = $resolvedExecutedAs
            status        = $Status
            totalRows     = $rowArray.Count
            warnings      = $warnArray
            errors        = $errArray
        }
        metrics = $metricsArray
        schema  = $schemaArray
        data    = $rowArray
    }
}

function Invoke-WinInspectorSmbAction {
    <#
    .SYNOPSIS
        Executes a ScriptBlock against a target server's C$ share (or local C:\ when local
        without alternate credentials), mounting a temporary PSDrive if Credential is provided.
        The ScriptBlock receives ($driveRoot) e.g. 'C:\' or '\\server\c$' or 'WinInspSmb:\'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )

    if (-not (Test-WinInspectorHostName -ComputerName $ComputerName)) {
        throw "Invalid ComputerName '$ComputerName'."
    }

    $script:WinInspectorLastExecutedAs = if ($null -ne $Credential) {
        $Credential.UserName
    } else {
        try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    }

    $isLocal = (Test-WinInspectorIsLocal -ComputerName $ComputerName) -and ($null -eq $Credential)
    if ($isLocal) {
        return (& $ScriptBlock 'C:\')
    }

    $targetHost = if (Test-WinInspectorIsLocal -ComputerName $ComputerName) {
        $ComputerName.Trim()
    } else {
        Resolve-WinInspectorTargetHost -ComputerName $ComputerName
    }

    $uncRoot = "\\$targetHost\c$"
    if ($null -eq $Credential) {
        return (& $ScriptBlock $uncRoot)
    }

    $driveName = 'WinInspSmb_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $drv = $null
    try {
        $drv = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $uncRoot -Credential $Credential -ErrorAction Stop
        return (& $ScriptBlock "${driveName}:\")
    }
    finally {
        if ($null -ne $drv) {
            try { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

function ConvertTo-WinInspectorJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )
    process {
        return ($InputObject | ConvertTo-Json -Depth 6 -Compress)
    }
}

Export-ModuleMember -Function @(
    'Test-WinInspectorHostName',
    'Test-WinInspectorIsLocal',
    'Resolve-WinInspectorTargetHost',
    'Test-WinInspectorTcpPort',
    'New-WinInspectorCimSession',
    'Invoke-WinInspectorRemote',
    'Invoke-WinInspectorSmbAction',
    'ConvertFrom-WinEventXml',
    'Format-WinInspectorSeverity',
    'New-WinInspectorResult',
    'ConvertTo-WinInspectorJson'
)
