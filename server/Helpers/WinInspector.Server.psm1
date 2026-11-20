#Requires -Version 5.1
<#
.SYNOPSIS
    Server-side helper module for the WinInspector Pode backend.
.DESCRIPTION
    Handles manifest loading & allow-list validation, typed parameter binding,
    strict UPN credential verification via Win32 LogonUser, per-session SecureString
    PSCredential vault management, and JSONL audit logging.
#>

Set-StrictMode -Version Latest

if (-not ('WinInspector.NativeAuthV2' -as [type])) {
    $authCs = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

namespace WinInspector
{
    public static class NativeAuthV2
    {
        private const int LOGON32_LOGON_NETWORK = 3;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            IntPtr lpszUsername,
            IntPtr lpszDomain,
            IntPtr lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static int ValidateUpnCredential(string upn, SecureString password, out string errorMessage, out string resolvedAccount)
        {
            errorMessage = string.Empty;
            resolvedAccount = string.Empty;
            if (string.IsNullOrWhiteSpace(upn) || password == null || password.Length == 0)
            {
                errorMessage = "Username and password are required.";
                return 87;
            }

            IntPtr userPtr = IntPtr.Zero;
            IntPtr passPtr = IntPtr.Zero;
            IntPtr token   = IntPtr.Zero;

            try
            {
                userPtr = Marshal.StringToHGlobalUni(upn);
                passPtr = Marshal.SecureStringToGlobalAllocUnicode(password);

                bool ok = LogonUser(userPtr, IntPtr.Zero, passPtr, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out token);
                if (ok)
                {
                    try
                    {
                        using (var id = new WindowsIdentity(token))
                        {
                            if (!string.IsNullOrWhiteSpace(id.Name))
                            {
                                resolvedAccount = id.Name;
                            }
                        }
                    }
                    catch { }
                    return 0;
                }

                int err = Marshal.GetLastWin32Error();
                errorMessage = new Win32Exception(err).Message;
                return err;
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
                if (userPtr != IntPtr.Zero) Marshal.FreeHGlobal(userPtr);
                if (passPtr != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(passPtr);
            }
        }
    }
}
'@
    Add-Type -TypeDefinition $authCs -Language CSharp
}

function Test-WinInspectorUpnFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$UserName
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        return $false
    }

    $trimmed = $UserName.Trim()
    # Strict UPN format: user@domain.tld (disallows DOMAIN\user or bare usernames)
    return ($trimmed -match '^[^@\s\\\/]+@[^@\s\\\/]+\.[^@\s\\\/]+$')
}

function Test-WinInspectorUpnCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $upn = $Credential.UserName.Trim()
    if (-not (Test-WinInspectorUpnFormat -UserName $upn)) {
        return [PSCustomObject]@{
            Valid        = $false
            ErrorCode    = 87
            ErrorMessage = 'Username must be in UserPrincipalName format (e.g. user@domain.net).'
        }
    }

    $errMsg = ''
    $resolvedAcct = ''
    $rc = [WinInspector.NativeAuthV2]::ValidateUpnCredential($upn, $Credential.Password, [ref]$errMsg, [ref]$resolvedAcct)

    return [PSCustomObject]@{
        Valid           = ($rc -eq 0)
        ErrorCode       = $rc
        ErrorMessage    = $errMsg
        ResolvedAccount = $resolvedAcct
    }
}

function New-WinInspectorCredVault {
    [CmdletBinding()]
    param()
    return [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new([System.StringComparer]::Ordinal)
}

function Set-WinInspectorSessionCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string, object]]$Vault,

        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential = $null,

        [Parameter()]
        [ValidateSet('SessionLogin', 'LocalPassthrough')]
        [string]$AuthMode = 'SessionLogin',

        [Parameter()]
        [string]$DisplayUpn = '',

        [Parameter()]
        [string]$ResolvedAccount = '',

        [Parameter()]
        [int]$TtlMinutes = 480
    )

    if ($AuthMode -eq 'SessionLogin' -and $null -eq $Credential) {
        throw 'Credential is required when AuthMode is SessionLogin.'
    }

    $now = (Get-Date).ToUniversalTime()
    $fallbackName = if ($null -ne $Credential) { $Credential.UserName } else { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
    $upnLabel = if (-not [string]::IsNullOrWhiteSpace($DisplayUpn)) { $DisplayUpn.Trim() } else { $fallbackName }
    $entry = [PSCustomObject]@{
        AuthMode        = $AuthMode
        UserName        = $upnLabel
        ResolvedAccount = if (-not [string]::IsNullOrWhiteSpace($ResolvedAccount)) { $ResolvedAccount.Trim() } else { $fallbackName }
        Credential      = $Credential
        CreatedUtc      = $now
        ExpiresUtc      = $now.AddMinutes($TtlMinutes)
    }

    $Vault[$SessionId] = $entry

    # Sweep expired entries to keep memory bounded
    foreach ($k in @($Vault.Keys)) {
        $existing = $null
        if ($Vault.TryGetValue($k, [ref]$existing) -and $null -ne $existing -and $existing.ExpiresUtc -lt $now) {
            $removed = $null
            if ($Vault.TryRemove($k, [ref]$removed) -and $null -ne $removed -and $removed.Credential -and $removed.Credential.Password) {
                try { $removed.Credential.Password.Dispose() } catch {}
            }
        }
    }

    return $entry
}

function Get-WinInspectorSessionCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string, object]]$Vault,

        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter()]
        [int]$ExtendMinutes = 480
    )

    if ([string]::IsNullOrWhiteSpace($SessionId)) { return $null }

    $entry = $null
    if (-not $Vault.TryGetValue($SessionId, [ref]$entry) -or $null -eq $entry) {
        return $null
    }

    $now = (Get-Date).ToUniversalTime()
    if ($entry.ExpiresUtc -lt $now) {
        $removed = $null
        $null = $Vault.TryRemove($SessionId, [ref]$removed)
        if ($removed -and $removed.Credential -and $removed.Credential.Password) {
            try { $removed.Credential.Password.Dispose() } catch {}
        }
        return $null
    }

    $entry.ExpiresUtc = $now.AddMinutes($ExtendMinutes)
    return $entry
}

function Remove-WinInspectorSessionCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string, object]]$Vault,

        [Parameter(Mandatory)]
        [string]$SessionId
    )

    if ([string]::IsNullOrWhiteSpace($SessionId)) { return }
    $removed = $null
    if ($Vault.TryRemove($SessionId, [ref]$removed)) {
        if ($removed -and $removed.Credential -and $removed.Credential.Password) {
            try { $removed.Credential.Password.Dispose() } catch {}
        }
    }
}

function Get-WinInspectorManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest file not found at '$ManifestPath'."
    }

    $raw = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    return ($raw | ConvertFrom-Json)
}

function Get-WinInspectorPublicCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Manifest
    )

    $categories = foreach ($cat in @($Manifest.categories)) {
        $subs = foreach ($sub in @($cat.subCategories)) {
            [ordered]@{
                id          = $sub.id
                name        = $sub.name
                description = $sub.description
                protocols   = @($sub.protocols)
                keywords    = @($sub.keywords)
                implemented = [bool]$sub.implemented
                parameters  = @($sub.parameters)
            }
        }
        [ordered]@{
            id            = $cat.id
            number        = $cat.number
            name          = $cat.name
            subCategories = @($subs)
        }
    }

    return [ordered]@{
        version    = $Manifest.version
        categories = @($categories)
    }
}

function Resolve-WinInspectorScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,

        [Parameter(Mandatory)]
        [string]$ScriptsRoot,

        [Parameter(Mandatory)]
        [string]$ScriptId
    )

    $resolvedRoot = [System.IO.Path]::GetFullPath($ScriptsRoot)

    foreach ($cat in @($Manifest.categories)) {
        foreach ($sub in @($cat.subCategories)) {
            if ($sub.id -eq $ScriptId) {
                if (-not [bool]$sub.implemented -or [string]::IsNullOrWhiteSpace($sub.scriptPath)) {
                    throw "Diagnostic '$ScriptId' is not yet implemented."
                }
                $candidate = [System.IO.Path]::GetFullPath((Join-Path $resolvedRoot $sub.scriptPath))
                if (-not $candidate.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Invalid script path outside scripts root for '$ScriptId'."
                }
                if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                    throw "Script file missing on disk for '$ScriptId'."
                }
                return [PSCustomObject]@{
                    Category   = $cat
                    Definition = $sub
                    FullPath   = $candidate
                }
            }
        }
    }

    throw "Unknown or unapproved scriptId '$ScriptId'."
}

function ConvertTo-ValidatedScriptParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ScriptDefinition,

        [Parameter()]
        [object]$InputParams
    )

    $bound = @{}
    if ($null -eq $InputParams) {
        return $bound
    }

    $inputMap = @{}
    if ($InputParams -is [hashtable] -or $InputParams -is [System.Collections.IDictionary]) {
        foreach ($k in $InputParams.Keys) { $inputMap[$k] = $InputParams[$k] }
    }
    else {
        foreach ($prop in $InputParams.PSObject.Properties) {
            $inputMap[$prop.Name] = $prop.Value
        }
    }

    foreach ($def in @($ScriptDefinition.parameters)) {
        $pName = $def.name
        if (-not $inputMap.ContainsKey($pName)) { continue }
        $val = $inputMap[$pName]
        if ($null -eq $val) { continue }

        switch ($def.type) {
            'number' {
                if ([string]::IsNullOrWhiteSpace([string]$val)) { continue }
                $num = [int]$val
                if ($null -ne $def.PSObject.Properties['min'] -and $num -lt [int]$def.min) {
                    throw "Parameter '$pName' must be >= $($def.min)."
                }
                if ($null -ne $def.PSObject.Properties['max'] -and $num -gt [int]$def.max) {
                    throw "Parameter '$pName' must be <= $($def.max)."
                }
                $bound[$pName] = $num
            }
            'boolean' {
                $bound[$pName] = [bool]$val
            }
            'select' {
                $strVal = [string]$val
                if ([string]::IsNullOrWhiteSpace($strVal)) { continue }
                $allowed = @($def.options | ForEach-Object { [string]$_ })
                if ($allowed.Count -gt 0 -and ($strVal -notin $allowed)) {
                    throw "Parameter '$pName' has unsupported value '$strVal'."
                }
                $bound[$pName] = $strVal
            }
            'multiselect' {
                $arr = @($val | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($arr.Count -eq 0) { continue }
                $allowed = @($def.options | ForEach-Object { [string]$_ })
                if ($allowed.Count -gt 0) {
                    foreach ($item in $arr) {
                        if ($item -notin $allowed) {
                            throw "Parameter '$pName' contains unsupported value '$item'."
                        }
                    }
                }
                $bound[$pName] = $arr
            }
            default {
                $strVal = ([string]$val).Trim()
                if ([string]::IsNullOrWhiteSpace($strVal)) { continue }
                if ($strVal.Length -gt 256) {
                    throw "Parameter '$pName' exceeds maximum length (256)."
                }
                $bound[$pName] = $strVal
            }
        }
    }

    return $bound
}

function New-InMemoryCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($UserName) -or [string]::IsNullOrEmpty($Password)) {
        throw "Both Username and Password are required."
    }

    $sec = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $sec.MakeReadOnly()
    return (New-Object System.Management.Automation.PSCredential($UserName.Trim(), $sec))
}

function Write-WinInspectorAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [hashtable]$Entry
    )

    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -Path $dir -ItemType Directory -Force
        }
        $record = [ordered]@{
            timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
        foreach ($k in $Entry.Keys) {
            if ($k -match 'pass|secret|cred|token') { continue }
            $record[$k] = $Entry[$k]
        }
        $line = $record | ConvertTo-Json -Depth 5 -Compress
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    }
    catch {
        [Console]::Error.WriteLine("WinInspector AuditLog Error: $($_.Exception.Message)")
    }
}

function New-WinInspectorPbkdf2Hash {
    param(
        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter()]
        [byte[]]$Salt = $null,

        [Parameter()]
        [int]$Iterations = 100000
    )

    if ($null -eq $Salt) {
        $Salt = [byte[]]::new(16)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($Salt) } finally { $rng.Dispose() }
    }

    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,
        $Salt,
        $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $hash = $pbkdf2.GetBytes(32)
    }
    finally {
        $pbkdf2.Dispose()
    }

    return [PSCustomObject]@{
        SaltBase64 = [Convert]::ToBase64String($Salt)
        HashBase64 = [Convert]::ToBase64String($hash)
        Iterations = $Iterations
    }
}

function Initialize-WinInspectorMasterAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    if (Test-Path -LiteralPath $ConfigPath) { return }

    $dir = Split-Path -Parent $ConfigPath
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }

    $hashed = New-WinInspectorPbkdf2Hash -Password 'a1b2c3'
    $payload = [ordered]@{
        version    = 1
        isDefault  = $true
        iterations = $hashed.Iterations
        salt       = $hashed.SaltBase64
        hash       = $hashed.HashBase64
        updatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
}

function Get-WinInspectorMasterAuthStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    Initialize-WinInspectorMasterAuth -ConfigPath $ConfigPath
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    return [PSCustomObject]@{
        configured = $true
        isDefault  = [bool]$cfg.isDefault
        updatedUtc = [string]$cfg.updatedUtc
    }
}

function Test-WinInspectorMasterPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Password
    )

    Initialize-WinInspectorMasterAuth -ConfigPath $ConfigPath
    if ([string]::IsNullOrEmpty($Password)) {
        return [PSCustomObject]@{ Valid = $false; IsDefault = $false }
    }

    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $saltBytes = [Convert]::FromBase64String([string]$cfg.salt)
    $expectedHash = [Convert]::FromBase64String([string]$cfg.hash)
    $iterations = if ($cfg.iterations) { [int]$cfg.iterations } else { 100000 }

    $computed = New-WinInspectorPbkdf2Hash -Password $Password -Salt $saltBytes -Iterations $iterations
    $actualHash = [Convert]::FromBase64String($computed.HashBase64)

    $diff = $expectedHash.Length -bxor $actualHash.Length
    $minLen = [Math]::Min($expectedHash.Length, $actualHash.Length)
    for ($i = 0; $i -lt $minLen; $i++) {
        $diff = $diff -bor ($expectedHash[$i] -bxor $actualHash[$i])
    }

    return [PSCustomObject]@{
        Valid     = ($diff -eq 0)
        IsDefault = [bool]$cfg.isDefault
    }
}

function Set-WinInspectorMasterPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$NewPassword
    )

    if ([string]::IsNullOrWhiteSpace($NewPassword) -or $NewPassword.Length -lt 4) {
        throw 'Master password must be at least 4 characters.'
    }

    $dir = Split-Path -Parent $ConfigPath
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }

    $hashed = New-WinInspectorPbkdf2Hash -Password $NewPassword
    $payload = [ordered]@{
        version    = 1
        isDefault  = $false
        iterations = $hashed.Iterations
        salt       = $hashed.SaltBase64
        hash       = $hashed.HashBase64
        updatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

    return [PSCustomObject]@{
        ok        = $true
        isDefault = $false
    }
}

Export-ModuleMember -Function @(
    'Test-WinInspectorUpnFormat',
    'Test-WinInspectorUpnCredential',
    'New-WinInspectorCredVault',
    'Set-WinInspectorSessionCredential',
    'Get-WinInspectorSessionCredential',
    'Remove-WinInspectorSessionCredential',
    'Initialize-WinInspectorMasterAuth',
    'Get-WinInspectorMasterAuthStatus',
    'Test-WinInspectorMasterPassword',
    'Set-WinInspectorMasterPassword',
    'Get-WinInspectorManifest',
    'Get-WinInspectorPublicCatalog',
    'Resolve-WinInspectorScript',
    'ConvertTo-ValidatedScriptParameters',
    'New-InMemoryCredential',
    'Write-WinInspectorAuditLog'
)
