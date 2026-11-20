#Requires -Version 5.1
<#
.SYNOPSIS
    Executes a local troubleshooting command on localhost as the WinInspector host process
    identity (SYSTEM / local service account) without using or injecting user session credentials.
.NOTES
    Category:  23-Terminal / 23.1-Local-Terminal
    Protocols: Local (localhost only)
    ReadOnly:  False (Interactive local troubleshooting console)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateLength(1, 4000)]
    [string]$Command,

    [Parameter()]
    [ValidateSet('PowerShell', 'CMD')]
    [string]$Shell = 'PowerShell',

    [Parameter()]
    [string]$WorkingDirectory = '',

    [Parameter()]
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$procUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }

$defaultDir = if ($env:SystemDrive) { "$($env:SystemDrive)\" } else { 'C:\' }
$cwd = $defaultDir
if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $candidate = $WorkingDirectory.Trim()
    if (Test-Path -LiteralPath $candidate -PathType Container -ErrorAction SilentlyContinue) {
        try { $cwd = (Resolve-Path -LiteralPath $candidate).Path } catch { $cwd = $candidate }
    }
}

$cwdMarker = '__WININSPECTOR_CWD_9F4A2C__:'
$maxBytes = 262144 # 256 KB per stream

$fileName = ''
$arguments = ''

if ($Shell -eq 'PowerShell') {
    $pwshExe = (Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue)
    if ($pwshExe) {
        $fileName = $pwshExe.Source
    }
    else {
        $fileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    $escapedCwd = $cwd.Replace("'", "''")
    $wrappedScript = @"
`$ProgressPreference = 'SilentlyContinue'
`$env:NO_COLOR = '1'
`$env:TERM = 'dumb'
if (`$PSStyle) { `$PSStyle.OutputRendering = 'PlainText' }
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { Set-Location -LiteralPath '$escapedCwd' -ErrorAction Stop } catch {}
`$global:LASTEXITCODE = 0
`$__wiExit = 0
try {
$Command
    if (`$null -ne `$LASTEXITCODE -and `$LASTEXITCODE -ne 0) {
        `$__wiExit = [int]`$LASTEXITCODE
    }
    elseif (-not `$?) {
        `$__wiExit = 1
    }
}
catch {
    [Console]::Error.WriteLine(`$_.Exception.Message)
    `$__wiExit = 1
}
`$__wiCwd = try { (Get-Location).ProviderPath } catch { '$escapedCwd' }
Write-Output ("$cwdMarker" + `$__wiCwd)
exit `$__wiExit
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($wrappedScript)
    $encoded = [Convert]::ToBase64String($bytes)
    $arguments = "-NoLogo -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand $encoded"
}
else {
    $fileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    # Enable delayed expansion to preserve exact command exit code while echoing updated %CD%
    $arguments = "/d /v:on /c `"$Command & set __wi_ec=!errorlevel! & echo ${cwdMarker}!CD! & exit /b !__wi_ec!`""
}

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $fileName
$psi.Arguments = $arguments
$psi.WorkingDirectory = $cwd
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.RedirectStandardInput = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi

$stdout = ''
$stderr = ''
$exitCode = 0
$timedOut = $false
$truncated = $false
$newCwd = $cwd

try {
    $null = $proc.Start()
    # Immediately close stdin so interactive commands don't hang waiting for user input
    try { $proc.StandardInput.Close() } catch {}

    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) {
        $timedOut = $true
        $exitCode = -1
        try {
            $proc.Kill($true)
        }
        catch {
            try { & taskkill.exe /T /F /PID $proc.Id 2>$null | Out-Null } catch {}
            try { $proc.Kill() } catch {}
        }
    }
    else {
        $exitCode = $proc.ExitCode
    }

    try { $null = $outTask.Wait(3000) } catch {}
    try { $null = $errTask.Wait(3000) } catch {}

    if ($outTask.IsCompletedSuccessfully) { $stdout = [string]$outTask.Result }
    if ($errTask.IsCompletedSuccessfully) { $stderr = [string]$errTask.Result }
}
finally {
    try { $proc.Dispose() } catch {}
}

# Extract updated working directory marker from stdout tail
if (-not [string]::IsNullOrEmpty($stdout) -and $stdout.Contains($cwdMarker)) {
    $lines = $stdout -split "`r?`n"
    $cleanLines = [System.Collections.Generic.List[string]]::new()
    foreach ($ln in $lines) {
        if ($ln.StartsWith($cwdMarker, [System.StringComparison]::Ordinal)) {
            $cand = $ln.Substring($cwdMarker.Length).Trim()
            if (-not [string]::IsNullOrWhiteSpace($cand) -and (Test-Path -LiteralPath $cand -PathType Container -ErrorAction SilentlyContinue)) {
                $newCwd = $cand
            }
        }
        else {
            $cleanLines.Add($ln)
        }
    }
    $stdout = ($cleanLines.ToArray() -join "`n").TrimEnd("`r", "`n")
}
else {
    $stdout = $stdout.TrimEnd("`r", "`n")
}

$stderr = $stderr.TrimEnd("`r", "`n")

function Remove-AnsiAndClixml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    # Strip ANSI/VT100 escape sequences (colors, cursor codes, OSC)
    $clean = [regex]::Replace($Text, "`e\[[0-9;?]*[ -/]*[@-~]", '')
    $clean = [regex]::Replace($clean, "`e\][^\a]*(\a|`e\\)", '')
    # Convert CLIXML warning/error/verbose blocks into clean readable lines if present
    if ($clean -match '#<\s*CLIXML') {
        $clean = [regex]::Replace($clean, '(?s)#<\s*CLIXML\s*<Objs[^>]*>(.*?)</Objs>', {
            param($m)
            $inner = $m.Groups[1].Value
            $msgs = [regex]::Matches($inner, '<S S="([^"]+)">(.*?)</S>')
            if ($msgs.Count -gt 0) {
                $parts = foreach ($mm in $msgs) {
                    $stream = $mm.Groups[1].Value.ToUpperInvariant()
                    $body = [System.Net.WebUtility]::HtmlDecode($mm.Groups[2].Value).Replace('_x000A_', "`n").Replace('_x000D_', '').Trim()
                    if ($body) { "${stream}: $body" }
                }
                return ($parts -join "`n")
            }
            return ''
        })
    }
    return $clean.TrimEnd("`r", "`n")
}

$stdout = Remove-AnsiAndClixml -Text $stdout
$stderr = Remove-AnsiAndClixml -Text $stderr

if ($stdout.Length -gt $maxBytes) {
    $stdout = $stdout.Substring(0, $maxBytes) + "`n... [Output truncated at 256 KB]"
    $truncated = $true
}
if ($stderr.Length -gt $maxBytes) {
    $stderr = $stderr.Substring(0, $maxBytes) + "`n... [Error output truncated at 256 KB]"
    $truncated = $true
}

if ($timedOut) {
    $timeoutMsg = "Command timed out after ${TimeoutSeconds}s and was terminated."
    $stderr = if ($stderr) { "$stderr`n$timeoutMsg" } else { $timeoutMsg }
}

$sw.Stop()

[ordered]@{
    ok           = (-not $timedOut -and $exitCode -eq 0)
    shell        = $Shell
    command      = $Command
    cwd          = $newCwd
    hostName     = $env:COMPUTERNAME
    executedAs   = $procUser
    exitCode     = $exitCode
    timedOut     = $timedOut
    truncated    = $truncated
    durationMs   = $sw.ElapsedMilliseconds
    stdout       = $stdout
    stderr       = $stderr
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 4 -Compress
