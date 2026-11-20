#Requires -Version 5.1
<#
.SYNOPSIS
    Starts the WinInspector 100% Pure-PowerShell (Pode) Web & REST API Server.
.DESCRIPTION
    Serves the HTML5 frontend and secure allow-listed diagnostic REST API.
    Forces UserPrincipalName (user@domain.net) session authentication before any
    application asset, catalog, or diagnostic endpoint can be accessed. The user's
    credentials are validated via Win32 LogonUser and stored strictly in an
    in-memory, per-session SecureString vault on the server so Pode can run under
    NT AUTHORITY\SYSTEM or a local service account while injecting the signed-in
    user's PSCredential into every remote diagnostic execution.
.EXAMPLE
    pwsh -NoProfile -File .\server\Start-WinInspector.ps1 -DevMode
.EXAMPLE
    pwsh -NoProfile -File .\server\Start-WinInspector.ps1 -ListenAddress '*' -Port 8085
.EXAMPLE
    pwsh -NoProfile -File .\server\Start-WinInspector.ps1 -ListenAddress '*' -Port 8443 -UseHttps -CertificateThumbprint "<THUMBPRINT>"
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ListenAddress = '',

    [Parameter()]
    [int]$Port = 8085,

    [Parameter()]
    [int]$Threads = 4,

    [Parameter()]
    [switch]$UseHttps,

    [Parameter()]
    [string]$CertificateThumbprint = '',

    [Parameter()]
    [switch]$SelfSigned,

    [Parameter()]
    [switch]$UseIISAuth,

    [Parameter()]
    [switch]$DevMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Support IIS HttpPlatformHandler dynamic port injection
if ($env:HTTP_PLATFORM_PORT -and ($PSBoundParameters.ContainsKey('Port') -eq $false)) {
    $Port = [int]$env:HTTP_PLATFORM_PORT
}

if (-not (Get-Module -ListAvailable -Name Pode)) {
    throw "Required module 'Pode' is not installed. Run: Install-Module Pode -Scope CurrentUser"
}

Import-Module Pode -Force

$projectRoot  = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$webRoot      = Join-Path $projectRoot 'web'
$scriptsRoot  = Join-Path $projectRoot 'scripts'
$manifestPath = Join-Path $scriptsRoot 'manifest.json'
$auditLogPath   = Join-Path $projectRoot 'logs\audit.jsonl'
$dbPath         = Join-Path $projectRoot 'data\wininspector.db'
$masterAuthPath = Join-Path $projectRoot 'data\master-auth.json'
$serverHelper   = Join-Path $PSScriptRoot 'Helpers\WinInspector.Server.psm1'
$dbHelper     = Join-Path $PSScriptRoot 'Helpers\WinInspector.Db.psm1'
$commonHelper = Join-Path $scriptsRoot '_Common\WinInspector.Common.psm1'
$connectTest  = Join-Path $scriptsRoot '_Common\Test-ServerConnection.ps1'
$perfSampler    = Join-Path $scriptsRoot '20-Performance\Get-LivePerformanceSample.ps1'
$procDetails    = Join-Path $scriptsRoot '20-Performance\Get-ProcessDeepDetails.ps1'
$procKiller     = Join-Path $scriptsRoot '20-Performance\Stop-TargetProcess.ps1'
$rdpResetter    = Join-Path $scriptsRoot '11-Remote-Connectivity\Reset-TerminalSession.ps1'
$terminalRunner = Join-Path $scriptsRoot '23-Terminal\Invoke-LocalTerminalCommand.ps1'

Import-Module $serverHelper -Force
Import-Module $dbHelper -Force
Initialize-WinInspectorDb -DbPath $dbPath
Initialize-WinInspectorMasterAuth -ConfigPath $masterAuthPath
$credVault = New-WinInspectorCredVault

$enableHttps = [bool]$UseHttps -or (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) -or [bool]$SelfSigned

# Resolve default ListenAddress: '*' (all interfaces, dual-stack IPv4/IPv6) when elevated/SYSTEM,
# falling back to '127.0.0.1' only when running unelevated.
$isElevated = $false
try {
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = [System.Security.Principal.WindowsPrincipal]::new($wi)
    $isElevated = $wi.IsSystem -or $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {}

if ([string]::IsNullOrWhiteSpace($ListenAddress)) {
    if ($isElevated) {
        $ListenAddress = '*'
    }
    else {
        $ListenAddress = '127.0.0.1'
        Write-Warning "WinInspector is not running elevated (Administrator/SYSTEM); binding to 127.0.0.1 only. Start elevated to listen on all interfaces (*)."
    }
}

$useDualMode = ($ListenAddress -in @('*', 'all'))
$schemeLabel = if ($enableHttps) { 'https' } else { 'http' }
Write-Host "Starting WinInspector on ${schemeLabel}://${ListenAddress}:${Port} (DualMode=$useDualMode, Elevated=$isElevated)..."

Start-PodeServer -Threads $Threads -RootPath $projectRoot {
    if ($enableHttps) {
        $epParams = @{
            Address  = $ListenAddress
            Port     = $Port
            Protocol = 'Https'
        }
        if ($useDualMode) { $epParams['DualMode'] = $true }
        if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            $epParams['CertificateThumbprint'] = $CertificateThumbprint.Trim()
        }
        else {
            $epParams['SelfSigned'] = $true
        }
        Add-PodeEndpoint @epParams
    }
    else {
        $epParams = @{
            Address  = $ListenAddress
            Port     = $Port
            Protocol = 'Http'
        }
        if ($useDualMode) { $epParams['DualMode'] = $true }
        Add-PodeEndpoint @epParams
    }

    # Expose shared paths, settings, and per-session credential vault into Pode state
    Set-PodeState -Name 'SessionCredVault' -Value $credVault
    Set-PodeState -Name 'WinInspectorConfig' -Value @{
        ProjectRoot  = $projectRoot
        WebRoot      = $webRoot
        ScriptsRoot  = $scriptsRoot
        ManifestPath = $manifestPath
        AuditLogPath   = $auditLogPath
        DbPath         = $dbPath
        MasterAuthPath = $masterAuthPath
        ServerHelper   = $serverHelper
        DbHelper     = $dbHelper
        CommonHelper = $commonHelper
        ConnectTest  = $connectTest
        PerfSampler    = $perfSampler
        ProcDetails    = $procDetails
        ProcKiller     = $procKiller
        RdpResetter    = $rdpResetter
        TerminalRunner = $terminalRunner
        SessionTtl     = 480
        DevMode      = [bool]$DevMode
    }

    # HttpOnly server-side session cookies (8-hour sliding window; Secure flag enabled when using native HTTPS)
    if ($enableHttps) {
        Enable-PodeSessionMiddleware -Duration 480 -Extend -HttpOnly -Secure
    }
    else {
        Enable-PodeSessionMiddleware -Duration 480 -Extend -HttpOnly
    }

    # Global Security Headers & Forced Session Authentication Gate
    Add-PodeMiddleware -Name 'WinInspectorAuthGate' -ScriptBlock {
        Set-PodeHeader -Name 'X-Content-Type-Options' -Value 'nosniff'
        Set-PodeHeader -Name 'X-Frame-Options' -Value 'SAMEORIGIN'
        Set-PodeHeader -Name 'Referrer-Policy' -Value 'no-referrer'
        Set-PodeHeader -Name 'Cache-Control' -Value 'no-store'

        $reqPath = [string]$WebEvent.Path
        $publicPaths = @('/login', '/css/app.css', '/api/auth/login', '/api/auth/master-login', '/api/auth/status')
        if ($reqPath -in $publicPaths) {
            return $true
        }

        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl

        if ($null -eq $sessionEntry) {
            if ($reqPath -like '/api/*' -or $reqPath -like '/js/*') {
                Write-PodeJsonResponse -StatusCode 401 -Value @{
                    error    = 'Authentication required'
                    loginUrl = '/login'
                }
            }
            else {
                Move-PodeResponseUrl -Url '/login'
            }
            return $false
        }

        return $true
    }

    # Serve static HTML5 frontend assets (CSS/JS — gated by WinInspectorAuthGate above)
    Add-PodeStaticRoute -Path '/css' -Source (Join-Path $webRoot 'css')
    Add-PodeStaticRoute -Path '/js'  -Source (Join-Path $webRoot 'js')

    # GET /login — Public sign-in page
    Add-PodeRoute -Method Get -Path '/login' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $existing = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId
        if ($null -ne $existing) {
            Move-PodeResponseUrl -Url '/'
            return
        }

        $loginPath = Join-Path $cfg.WebRoot 'login.html'
        $html = Get-Content -LiteralPath $loginPath -Raw -Encoding UTF8
        Write-PodeHtmlResponse -Value $html
    }

    # GET /api/auth/status — Lightweight unauthenticated check used by login.html
    Add-PodeRoute -Method Get -Path '/api/auth/status' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $entry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId
        $procUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
        $masterStatus = Get-WinInspectorMasterAuthStatus -ConfigPath $cfg.MasterAuthPath

        if ($null -ne $entry) {
            Write-PodeJsonResponse -Value ([ordered]@{
                authenticated           = $true
                authMode                = $entry.AuthMode
                username                = $entry.UserName
                expiresUtc              = $entry.ExpiresUtc.ToString('o')
                processIdentity         = $procUser
                masterPasswordIsDefault = $masterStatus.isDefault
            })
        }
        else {
            Write-PodeJsonResponse -Value ([ordered]@{
                authenticated           = $false
                authMode                = $null
                username                = $null
                processIdentity         = $procUser
                masterPasswordIsDefault = $masterStatus.isDefault
            })
        }
    }

    # POST /api/auth/master-login — Unlocks Local Passthrough (run as current user / local system account)
    Add-PodeRoute -Method Post -Path '/api/auth/master-login' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $body = $WebEvent.Data
        $password = if ($null -ne $body -and $null -ne $body.password) { [string]$body.password } else { '' }
        $procUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }

        if ([string]::IsNullOrEmpty($password)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Master password is required.' }
            return
        }

        $check = Test-WinInspectorMasterPassword -ConfigPath $cfg.MasterAuthPath -Password $password
        $password = $null
        if (-not $check.Valid) {
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $procUser
                authMode     = 'LocalPassthrough'
                targetServer = $env:COMPUTERNAME
                scriptId     = 'auth-master-login'
                status       = 'Denied'
                error        = 'Invalid master password.'
            }
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Invalid master password.' }
            return
        }

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        if ([string]::IsNullOrWhiteSpace($sessionId)) {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = 'Failed to initialize HTTP session.' }
            return
        }

        $stored = Set-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -AuthMode 'LocalPassthrough' -DisplayUpn $procUser -ResolvedAccount $procUser -TtlMinutes $cfg.SessionTtl
        $WebEvent.Session.Data.AuthUser = $procUser
        $WebEvent.Session.Data.AuthMode = 'LocalPassthrough'
        Save-PodeSession -Force

        Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
            caller       = $procUser
            authMode     = 'LocalPassthrough'
            targetServer = $env:COMPUTERNAME
            scriptId     = 'auth-master-login'
            status       = 'Success'
        }

        Write-PodeJsonResponse -Value ([ordered]@{
            authenticated = $true
            authMode      = 'LocalPassthrough'
            username      = $stored.UserName
            isDefault     = $check.IsDefault
            expiresUtc    = $stored.ExpiresUtc.ToString('o')
        })
    }

    # POST /api/auth/master-reset — Updates the master password (requires authenticated LocalPassthrough session)
    Add-PodeRoute -Method Post -Path '/api/auth/master-reset' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry -or $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'Local Passthrough authentication is required to reset the master password.' }
            return
        }

        $body = $WebEvent.Data
        $newPassword = if ($null -ne $body -and $null -ne $body.newPassword) { [string]$body.newPassword } else { '' }
        if ([string]::IsNullOrWhiteSpace($newPassword) -or $newPassword.Length -lt 4) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'New master password must be at least 4 characters.' }
            return
        }

        try {
            $res = Set-WinInspectorMasterPassword -ConfigPath $cfg.MasterAuthPath -NewPassword $newPassword
            $newPassword = $null
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $sessionEntry.UserName
                authMode     = 'LocalPassthrough'
                targetServer = $env:COMPUTERNAME
                scriptId     = 'auth-master-reset'
                status       = 'Success'
            }
            Write-PodeJsonResponse -Value $res
        }
        catch {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = $_.Exception.Message }
        }
        finally {
            $newPassword = $null
        }
    }

    # POST /api/auth/login — Validates UPN credentials via Win32 LogonUser and binds PSCredential to this session only
    Add-PodeRoute -Method Post -Path '/api/auth/login' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $body = $WebEvent.Data
        $upn = if ($null -ne $body -and $null -ne $body.username) { ([string]$body.username).Trim() } else { '' }
        $password = if ($null -ne $body -and $null -ne $body.password) { [string]$body.password } else { '' }

        if (-not (Test-WinInspectorUpnFormat -UserName $upn)) {
            $password = $null
            Write-PodeJsonResponse -StatusCode 400 -Value @{
                error = 'Username must be in UserPrincipalName format (e.g. user@domain.net). DOMAIN\user is not permitted.'
            }
            return
        }

        if ([string]::IsNullOrEmpty($password)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Password is required.' }
            return
        }

        $cred = $null
        $keepCred = $false
        try {
            $cred = New-InMemoryCredential -UserName $upn -Password $password
            $password = $null

            $authCheck = Test-WinInspectorUpnCredential -Credential $cred
            if (-not $authCheck.Valid) {
                Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                    caller       = $upn
                    authMode     = 'SessionLogin'
                    targetServer = $env:COMPUTERNAME
                    scriptId     = 'auth-login'
                    status       = 'Denied'
                    errorCode    = $authCheck.ErrorCode
                    error        = $authCheck.ErrorMessage
                }
                Write-PodeJsonResponse -StatusCode 401 -Value @{
                    error = "Invalid UPN credentials: $($authCheck.ErrorMessage)"
                }
                return
            }

            $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
            if ([string]::IsNullOrWhiteSpace($sessionId)) {
                Write-PodeJsonResponse -StatusCode 500 -Value @{ error = 'Failed to initialize HTTP session.' }
                return
            }

            # When LogonUser returns a canonical DOMAIN\SamAccountName (e.g. IVCORP\MaraAar-Admin),
            # bind the PSCredential with that identity (reusing the same read-only SecureString) so
            # Kerberos, NTLM, WinRM, CIM/DCOM, RPC Get-WinEvent, and SMB all receive Domain + UserName cleanly.
            $resolvedAcct = [string]$authCheck.ResolvedAccount
            $sessionCred = if (-not [string]::IsNullOrWhiteSpace($resolvedAcct) -and $resolvedAcct.Contains('\')) {
                New-Object System.Management.Automation.PSCredential($resolvedAcct, $cred.Password)
            }
            else {
                $cred
            }

            $stored = Set-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -Credential $sessionCred -DisplayUpn $upn -ResolvedAccount $resolvedAcct -TtlMinutes $cfg.SessionTtl
            $keepCred = $true
            $WebEvent.Session.Data.AuthUser = $upn
            Save-PodeSession -Force

            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller          = $upn
                resolvedAccount = $stored.ResolvedAccount
                authMode        = 'SessionLogin'
                targetServer    = $env:COMPUTERNAME
                scriptId        = 'auth-login'
                status          = 'Success'
            }

            Write-PodeJsonResponse -Value ([ordered]@{
                authenticated   = $true
                username        = $stored.UserName
                resolvedAccount = $stored.ResolvedAccount
                expiresUtc      = $stored.ExpiresUtc.ToString('o')
            })
        }
        catch {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
        finally {
            $password = $null
            if (-not $keepCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/auth/logout — Disposes session SecureString and terminates HTTP session
    Add-PodeRoute -Method Post -Path '/api/auth/logout' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $existing = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId
        $caller = if ($null -ne $existing) { $existing.UserName } else { 'unknown' }

        Remove-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId
        try { Remove-PodeSession } catch {}

        Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
            caller       = $caller
            authMode     = 'SessionLogin'
            targetServer = $env:COMPUTERNAME
            scriptId     = 'auth-logout'
            status       = 'Success'
        }

        Write-PodeJsonResponse -Value @{ ok = $true; loginUrl = '/login' }
    }

    # Root HTML5 App
    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $indexPath = Join-Path $cfg.WebRoot 'index.html'
        $html = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
        Write-PodeHtmlResponse -Value $html
    }

    # GET /api/health
    Add-PodeRoute -Method Get -Path '/api/health' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId
        $procUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }

        Write-PodeJsonResponse -Value ([ordered]@{
            status           = 'ok'
            app              = 'WinInspector'
            version          = '1.0.0'
            psVersion        = $PSVersionTable.PSVersion.ToString()
            podeVersion      = (Get-Module Pode).Version.ToString()
            serverHost       = $env:COMPUTERNAME
            devMode          = $cfg.DevMode
            authScheme       = if ($null -ne $sessionEntry -and $sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'UPN-Session' }
            sessionAuthMode  = if ($null -ne $sessionEntry) { $sessionEntry.AuthMode } else { $null }
            iisAuthEnabled   = $false
            hasWinAuthToken  = $false
            authenticated    = ($null -ne $sessionEntry)
            authenticatedAs  = if ($null -ne $sessionEntry) { $sessionEntry.UserName } else { $null }
            processIdentity  = $procUser
            timestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
        })
    }

    # GET /api/catalog
    Add-PodeRoute -Method Get -Path '/api/catalog' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        Import-Module $cfg.ServerHelper -Force
        try {
            $manifest = Get-WinInspectorManifest -ManifestPath $cfg.ManifestPath
            $catalog  = Get-WinInspectorPublicCatalog -Manifest $manifest
            Write-PodeJsonResponse -Value $catalog
        }
        catch {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
    }

    # POST /api/connect/test
    Add-PodeRoute -Method Post -Path '/api/connect/test' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ reachable = $false; error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName = [string]$body.computerName
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode  = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode     = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }

        if ($authMode -eq 'CurrentUser') {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ reachable = $false; error = "CurrentUser mode requires unlocking Local Passthrough with the master password." }
            return
        }
        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ reachable = $false; error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ reachable = $false; error = "Local Passthrough requires authenticating with the master password." }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ reachable = $false; error = "Invalid server hostname or FQDN." }
            return
        }
        if ($protocol -notin @('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ reachable = $false; error = "Unsupported protocol '$protocol'." }
            return
        }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        try {
            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ reachable = $false; error = "Custom Credentials require HTTPS outside DevMode." }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ reachable = $false; error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName = $computerName.Trim()
                Protocol     = $protocol
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }

            $rawJson = & $cfg.ConnectTest @execParams
            $parsed = ($rawJson | Out-String) | ConvertFrom-Json
            $effectiveUser = if ($null -ne $cred) { $cred.UserName } else { $sessionEntry.UserName }
            if ($null -ne $parsed -and ($null -eq $parsed.executedAs -or [string]::IsNullOrWhiteSpace([string]$parsed.executedAs))) {
                $parsed | Add-Member -NotePropertyName executedAs -NotePropertyValue $effectiveUser -Force
            }
            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ reachable = $false; targetServer = $computerName; error = $_.Exception.Message }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/diagnostics/run
    Add-PodeRoute -Method Post -Path '/api/diagnostics/run' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName = [string]$body.computerName
        $scriptId     = [string]$body.scriptId
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode  = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode     = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }
        $caller       = $sessionEntry.UserName

        if ($authMode -eq 'CurrentUser') {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "CurrentUser mode requires unlocking Local Passthrough with the master password." }
            return
        }
        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = "Local Passthrough requires authenticating with the master password." }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Invalid target server hostname or FQDN." }
            return
        }
        if ([string]::IsNullOrWhiteSpace($scriptId)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Missing required 'scriptId'." }
            return
        }
        if ($protocol -notin @('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported protocol '$protocol'." }
            return
        }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $manifest = Get-WinInspectorManifest -ManifestPath $cfg.ManifestPath
            $resolved = Resolve-WinInspectorScript -Manifest $manifest -ScriptsRoot $cfg.ScriptsRoot -ScriptId $scriptId
            $validatedParams = ConvertTo-ValidatedScriptParameters -ScriptDefinition $resolved.Definition -InputParams $body.parameters

            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Custom Credentials require HTTPS outside DevMode." }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName = $computerName.Trim()
                Protocol     = $protocol
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }
            foreach ($k in $validatedParams.Keys) {
                $execParams[$k] = $validatedParams[$k]
            }

            $rawJson = & $resolved.FullPath @execParams
            $jsonString = ($rawJson | Out-String).Trim()
            $parsed = $jsonString | ConvertFrom-Json
            $sw.Stop()

            # Ensure meta.executedAs reflects the authenticated credential / verified remote identity
            # and never leaks the host process/service account identity unless LocalPassthrough is active.
            $procUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
            if ($null -ne $parsed -and $null -ne $parsed.meta -and -not $usePassthrough -and $null -ne $cred) {
                if ([string]::IsNullOrWhiteSpace([string]$parsed.meta.executedAs) -or ($parsed.meta.executedAs -ieq $procUser -and $cred.UserName -ine $procUser)) {
                    $parsed.meta.executedAs = $cred.UserName
                }
            }

            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller         = $caller
                executedAs     = if ($null -ne $parsed.meta) { [string]$parsed.meta.executedAs } elseif ($null -ne $cred) { $cred.UserName } else { $procUser }
                authMode       = $authMode
                targetServer   = $computerName.Trim()
                scriptId       = $scriptId
                protocol       = $parsed.meta.protocolUsed
                parameters     = $validatedParams
                status         = $parsed.meta.status
                totalRows      = $parsed.meta.totalRows
                durationMs     = $sw.ElapsedMilliseconds
            }

            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            $sw.Stop()
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $caller
                authMode     = $authMode
                targetServer = $computerName.Trim()
                scriptId     = $scriptId
                protocol     = $protocol
                status       = 'Error'
                error        = $_.Exception.Message
                durationMs   = $sw.ElapsedMilliseconds
            }
            Write-PodeJsonResponse -StatusCode 500 -Value @{
                error = $_.Exception.Message
            }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/perf/start — Create a SQLite-backed live monitoring session
    Add-PodeRoute -Method Post -Path '/api/perf/start' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force
        Import-Module $cfg.DbHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName = [string]$body.computerName
        $intervalSec  = if ($body.intervalSec) { [int]$body.intervalSec } else { 5 }
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }

        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid target server hostname or FQDN.' }
            return
        }
        if ($intervalSec -notin @(1, 3, 5, 10, 15)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'intervalSec must be 1, 3, 5, 10, or 15.' }
            return
        }

        $session = Start-PerfSessionRecord -DbPath $cfg.DbPath -ServerName $computerName.Trim() -IntervalSec $intervalSec -ExecutedBy $sessionEntry.UserName -ProtocolUsed $protocol
        Write-PodeJsonResponse -Value $session
    }

    # POST /api/perf/sample — Capture 1 sample, persist directly to SQLite, return filtered chart/table view
    Add-PodeRoute -Method Post -Path '/api/perf/sample' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force
        Import-Module $cfg.DbHelper -Force

        $httpSessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $httpSessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $sessionId    = [string]$body.sessionId
        $computerName = [string]$body.computerName
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode  = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode     = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }
        $topProcs     = if ($body.topProcesses) { [int]$body.topProcesses } else { 15 }
        $filters      = $body.filters

        if ($authMode -eq 'CurrentUser') {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'CurrentUser mode requires unlocking Local Passthrough with the master password.' }
            return
        }
        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'Local Passthrough requires authenticating with the master password.' }
            return
        }
        if ([string]::IsNullOrWhiteSpace($sessionId)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Missing sessionId.' }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid target server hostname or FQDN.' }
            return
        }
        if ($topProcs -lt 5 -or $topProcs -gt 50) { $topProcs = 15 }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        try {
            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Custom Credentials require HTTPS outside DevMode.' }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName = $computerName.Trim()
                Protocol     = $protocol
                TopProcesses = $topProcs
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }

            $rawJson = & $cfg.PerfSampler @execParams
            $payload = ($rawJson | Out-String).Trim() | ConvertFrom-Json
            $null = Save-PerfSampleRecord -DbPath $cfg.DbPath -SessionId $sessionId -Payload $payload

            $histParams = @{
                DbPath        = $cfg.DbPath
                SessionId     = $sessionId
                TimelineLimit = 240
            }
            if ($filters) {
                if ($filters.clientIp)    { $histParams['ClientIp']    = [string]$filters.clientIp }
                if ($filters.protocol)    { $histParams['Protocol']    = [string]$filters.protocol }
                if ($filters.serviceName) { $histParams['ServiceName'] = [string]$filters.serviceName }
                if ($filters.processName) { $histParams['ProcessName'] = [string]$filters.processName }
                if ($filters.localPort)   { $histParams['LocalPort']   = [string]$filters.localPort }
                if ($filters.remotePort)  { $histParams['RemotePort']  = [string]$filters.remotePort }
                if ($filters.search)      { $histParams['Search']      = [string]$filters.search }
            }

            $history = Get-PerfSessionHistory @histParams
            $history['lastSampleDurationMs'] = $payload.durationMs
            $fallbackAs = if ($null -ne $cred) { $cred.UserName } else { $sessionEntry.UserName }
            $history['executedAs'] = if ($payload.PSObject.Properties['executedAs'] -and -not [string]::IsNullOrWhiteSpace([string]$payload.executedAs)) { [string]$payload.executedAs } else { $fallbackAs }
            $history['warnings'] = @($payload.warnings)
            Write-PodeJsonResponse -Value $history
        }
        catch {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/perf/stop — Mark monitoring session stopped in SQLite
    Add-PodeRoute -Method Post -Path '/api/perf/stop' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        Import-Module $cfg.DbHelper -Force
        $sessionId = [string]$WebEvent.Data.sessionId
        if ([string]::IsNullOrWhiteSpace($sessionId)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Missing sessionId.' }
            return
        }
        $res = Stop-PerfSessionRecord -DbPath $cfg.DbPath -SessionId $sessionId
        Write-PodeJsonResponse -Value $res
    }

    # GET /api/perf/sessions — List stored monitoring sessions from SQLite
    Add-PodeRoute -Method Get -Path '/api/perf/sessions' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        Import-Module $cfg.DbHelper -Force
        $sessions = Get-PerfSessionsList -DbPath $cfg.DbPath -Limit 40
        Write-PodeJsonResponse -Value @{ sessions = @($sessions) }
    }

    # GET /api/perf/history — Query stored session timeline & filtered network details from SQLite
    Add-PodeRoute -Method Get -Path '/api/perf/history' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        Import-Module $cfg.DbHelper -Force
        $q = $WebEvent.Query
        $sessionId = [string]$q['sessionId']
        if ([string]::IsNullOrWhiteSpace($sessionId)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Missing sessionId query parameter.' }
            return
        }
        $hist = Get-PerfSessionHistory `
            -DbPath $cfg.DbPath `
            -SessionId $sessionId `
            -ClientIp ([string]$q['clientIp']) `
            -Protocol ([string]$q['protocol']) `
            -ServiceName ([string]$q['serviceName']) `
            -ProcessName ([string]$q['processName']) `
            -LocalPort ([string]$q['localPort']) `
            -RemotePort ([string]$q['remotePort']) `
            -Search ([string]$q['search']) `
            -TimelineLimit 300
        Write-PodeJsonResponse -Value $hist
    }

    # POST /api/perf/process-details — Deep live inspection for a single process (Memory, VRAM, Disk/Net I/O, Sockets, Modules)
    Add-PodeRoute -Method Post -Path '/api/perf/process-details' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName = [string]$body.computerName
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode  = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode     = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }
        $processId    = if ($body.processId) { [int]$body.processId } else { 0 }
        $processName  = if ($body.processName) { [string]$body.processName } else { '' }

        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'Local Passthrough requires master password authentication.' }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid target server hostname or FQDN.' }
            return
        }
        if ($processId -le 0 -and [string]::IsNullOrWhiteSpace($processName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'ProcessId or ProcessName is required.' }
            return
        }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        try {
            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Custom Credentials require HTTPS outside DevMode.' }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName = $computerName.Trim()
                Protocol     = $protocol
                ProcessId    = $processId
                ProcessName  = $processName
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }

            $rawJson = & $cfg.ProcDetails @execParams
            $parsed = ($rawJson | Out-String).Trim() | ConvertFrom-Json
            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/perf/process-kill — Terminate a target process by PID
    Add-PodeRoute -Method Post -Path '/api/perf/process-kill' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName = [string]$body.computerName
        $protocol     = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode  = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode     = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }
        $processId    = if ($body.processId) { [int]$body.processId } else { 0 }
        $caller       = $sessionEntry.UserName

        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'Local Passthrough requires master password authentication.' }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid target server hostname or FQDN.' }
            return
        }
        if ($processId -le 4) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Cannot terminate protected system PID (<= 4).' }
            return
        }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        try {
            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Custom Credentials require HTTPS outside DevMode.' }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName = $computerName.Trim()
                Protocol     = $protocol
                ProcessId    = $processId
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }

            $rawJson = & $cfg.ProcKiller @execParams
            $parsed = ($rawJson | Out-String).Trim() | ConvertFrom-Json

            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $caller
                executedAs   = [string]$parsed.executedAs
                authMode     = $authMode
                targetServer = $computerName.Trim()
                scriptId     = 'perf-process-kill'
                processId    = $processId
                processName  = [string]$parsed.processName
                status       = 'Success'
            }

            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $caller
                authMode     = $authMode
                targetServer = $computerName.Trim()
                scriptId     = 'perf-process-kill'
                processId    = $processId
                status       = 'Error'
                error        = $_.Exception.Message
            }
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/rdp/reset — Disconnect/Reset a Terminal Session via rwinsta.exe or WMI
    Add-PodeRoute -Method Post -Path '/api/rdp/reset' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force
        Import-Module $cfg.CommonHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $body = $WebEvent.Data
        $computerName  = [string]$body.computerName
        $sessionTarget = [string]$body.sessionTarget
        $logonId       = if ($body.logonId) { [string]$body.logonId } else { '' }
        $method        = if ($body.method) { [string]$body.method } else { 'Auto' }
        $protocol      = if ($body.protocol) { [string]$body.protocol } else { 'Auto' }
        $defaultMode   = if ($sessionEntry.AuthMode -eq 'LocalPassthrough') { 'LocalPassthrough' } else { 'SessionLogin' }
        $authMode      = if ($body.authMode) { [string]$body.authMode } else { $defaultMode }
        $caller        = $sessionEntry.UserName

        if ($authMode -eq 'CurrentUser') {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'CurrentUser mode requires unlocking Local Passthrough with the master password.' }
            return
        }
        if ($authMode -notin @('SessionLogin', 'LocalPassthrough', 'CustomCredentials')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported authMode '$authMode'." }
            return
        }
        if ($authMode -eq 'LocalPassthrough' -and $sessionEntry.AuthMode -ne 'LocalPassthrough') {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'Local Passthrough requires authenticating with the master password.' }
            return
        }
        if (-not (Test-WinInspectorHostName -ComputerName $computerName)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid target server hostname or FQDN.' }
            return
        }
        if ($sessionTarget -notmatch '^[a-zA-Z0-9#\-_.]{1,32}$') {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid session ID or session name.' }
            return
        }
        if ($method -notin @('Auto', 'rwinsta', 'WMI')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Invalid reset method.' }
            return
        }

        $cred = $null
        $disposeCred = $false
        $usePassthrough = ($authMode -eq 'LocalPassthrough') -or ($authMode -eq 'SessionLogin' -and $sessionEntry.AuthMode -eq 'LocalPassthrough')
        try {
            if ($authMode -eq 'CustomCredentials') {
                $isHttps = ($WebEvent.Request.Headers['X-Forwarded-Proto'] -eq 'https') -or ($WebEvent.Request.Url.Scheme -eq 'https')
                if (-not $cfg.DevMode -and -not $isHttps) {
                    Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Custom Credentials require HTTPS outside DevMode.' }
                    return
                }
                $cred = New-InMemoryCredential -UserName ([string]$body.credential.username) -Password ([string]$body.credential.password)
                $disposeCred = $true
            }
            elseif (-not $usePassthrough) {
                $cred = $sessionEntry.Credential
                if ($null -eq $cred) {
                    Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'No user credentials available in session.'; loginUrl = '/login' }
                    return
                }
            }

            $execParams = @{
                ComputerName  = $computerName.Trim()
                SessionTarget = $sessionTarget.Trim()
                Method        = $method
                Protocol      = $protocol
            }
            if ($null -ne $cred) { $execParams['Credential'] = $cred }
            if ($logonId) { $execParams['LogonId'] = $logonId.Trim() }

            $rawJson = & $cfg.RdpResetter @execParams
            $parsed = ($rawJson | Out-String).Trim() | ConvertFrom-Json
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller        = $caller
                authMode      = $authMode
                targetServer  = $computerName.Trim()
                scriptId      = 'rdp-rwinsta'
                sessionTarget = $sessionTarget.Trim()
                status        = 'Success'
            }
            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller        = $caller
                authMode      = $authMode
                targetServer  = $computerName.Trim()
                scriptId      = 'rdp-rwinsta'
                sessionTarget = $sessionTarget.Trim()
                status        = 'Error'
                error         = $_.Exception.Message
            }
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
        finally {
            if ($disposeCred -and $null -ne $cred) {
                try { $cred.Password.Dispose() } catch {}
            }
            $cred = $null
        }
    }

    # POST /api/terminal/run — Execute a local troubleshooting command on localhost as host process (no user credentials injected)
    Add-PodeRoute -Method Post -Path '/api/terminal/run' -ScriptBlock {
        $cfg = Get-PodeState -Name 'WinInspectorConfig'
        $vault = Get-PodeState -Name 'SessionCredVault'
        Import-Module $cfg.ServerHelper -Force

        $sessionId = if ($null -ne $WebEvent.Session) { [string]$WebEvent.Session.Id } else { '' }
        $sessionEntry = Get-WinInspectorSessionCredential -Vault $vault -SessionId $sessionId -ExtendMinutes $cfg.SessionTtl
        if ($null -eq $sessionEntry) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Session expired. Please sign in again.'; loginUrl = '/login' }
            return
        }

        $caller = $sessionEntry.UserName
        $body = $WebEvent.Data
        $command = if ($null -ne $body -and $null -ne $body.command) { ([string]$body.command).Trim() } else { '' }
        $shell   = if ($null -ne $body -and $body.shell) { [string]$body.shell } else { 'PowerShell' }
        $cwd     = if ($null -ne $body -and $body.cwd) { [string]$body.cwd } else { '' }
        $timeout = if ($null -ne $body -and $body.timeoutSeconds) { [int]$body.timeoutSeconds } else { 30 }

        if ([string]::IsNullOrWhiteSpace($command)) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Command cannot be empty.' }
            return
        }
        if ($command.Length -gt 4000) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = 'Command exceeds maximum length (4000 characters).' }
            return
        }
        if ($shell -notin @('PowerShell', 'CMD')) {
            Write-PodeJsonResponse -StatusCode 400 -Value @{ error = "Unsupported shell '$shell'. Use PowerShell or CMD." }
            return
        }
        if ($timeout -lt 5) { $timeout = 5 }
        if ($timeout -gt 120) { $timeout = 120 }

        try {
            $execParams = @{
                Command          = $command
                Shell            = $shell
                WorkingDirectory = $cwd
                TimeoutSeconds   = $timeout
            }
            $rawJson = & $cfg.TerminalRunner @execParams
            $parsed = ($rawJson | Out-String).Trim() | ConvertFrom-Json

            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $caller
                executedAs   = [string]$parsed.executedAs
                authMode     = 'LocalProcess'
                targetServer = 'localhost'
                scriptId     = '23.1-local-terminal'
                shell        = $shell
                command      = $command
                exitCode     = $parsed.exitCode
                timedOut     = [bool]$parsed.timedOut
                durationMs   = $parsed.durationMs
                status       = if ($parsed.ok) { 'Success' } else { 'Warning' }
            }

            Write-PodeJsonResponse -Value $parsed
        }
        catch {
            Write-WinInspectorAuditLog -LogPath $cfg.AuditLogPath -Entry @{
                caller       = $caller
                authMode     = 'LocalProcess'
                targetServer = 'localhost'
                scriptId     = '23.1-local-terminal'
                shell        = $shell
                command      = $command
                status       = 'Error'
                error        = $_.Exception.Message
            }
            Write-PodeJsonResponse -StatusCode 500 -Value @{ error = $_.Exception.Message }
        }
    }
}
