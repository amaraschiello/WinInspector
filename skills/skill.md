---
name: wininspector-dev
description: >-
  Expert Windows Systems Administration and HTML5-to-PowerShell web interface
  development skill for building WinInspector. Activate when designing, coding,
  debugging, or deploying WinInspector's IIS-hosted HTML5 UI, REST API bridge,
  remote PowerShell diagnostic scripts (WinRM/CIM/RPC), or IIS authentication.
---

# WinInspector Development & Windows Systems Administration Skill

Use this skill whenever developing, extending, or reviewing any part of the **WinInspector** project—including PowerShell diagnostic scripts, the `WinInspector.Common` module, the IIS-hosted backend API bridge, `scripts/manifest.json`, and the dynamic HTML5 frontend.

---

## 1. Windows Systems Administration Expertise & Remote Execution Rules

### 1.1 Protocol Selection & Graceful Fallback
Target Windows Servers may have WinRM enabled (HTTP/HTTPS) or disabled (RPC/DCOM only). Every remote operation must be designed with protocol awareness:

| Mechanism | Protocol / Ports | When to Use |
| :--- | :--- | :--- |
| `Invoke-Command -ComputerName` / `New-PSSession` | WinRM WS-Man (`5986` HTTPS / `5985` HTTP) | Primary method for running remote cmdlets, native CLI tools (`w32tm`, `dsregcmd`, `nltest`, `dcdiag`, `klist`), registry queries, and complex log parsing on the target server. |
| `New-CimSession` (WSMan → DCOM fallback) | WinRM (`5985/5986`) or DCOM/RPC (`135` + ephemeral) | Hardware, OS, Services, Disks, Network Adapters, BitLocker, Hyper-V, Defender, Storage Spaces (`root\cimv2`, `root\Microsoft\Windows\Storage`, `root\Microsoft\Windows\Defender`, `root\virtualization\v2`). |
| `Get-WinEvent -ComputerName` | RPC (`135` + ephemeral) | Direct fallback for Windows Event Logs when WinRM is unavailable. Always prefer executing `Get-WinEvent` **inside** `Invoke-Command` when WinRM is available because WinRM filters and serializes faster over high-latency links. |
| Native Remote CLI (`wevtutil /r:`, `sc.exe \\`, `w32tm /computer:`) | RPC / SMB | Lightweight fallback for specific subsystems when WinRM is blocked. |

**Rule**: Always prefer **FQDN** over short NetBIOS names or IP addresses so Kerberos SPN negotiation succeeds cleanly without falling back to NTLM or requiring `TrustedHosts`.

### 1.2 Server-Side Event Log Filtering (Mandatory for Performance)
Never pull unfiltered event logs across the network and pipe to `Where-Object`. Always filter at the source using `-FilterHashtable` or `-FilterXPath` and cap output with `-MaxEvents`:

```powershell
# GOOD: Server-side indexed filtering + XML property extraction
$filter = @{
    LogName   = 'Security'
    Id        = @(4625, 4740, 4771, 4776)
    StartTime = (Get-Date).AddHours(-$HoursBack)
}
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxResults -ErrorAction SilentlyContinue
```

**Parsing Structured Event Fields (User, Client, IP, Server)**:
Never rely solely on fragile regex against localized `.Message` strings when XML `<EventData>` fields exist. Parse `[xml]$event.ToXml()` and extract named `<Data Name="...">` attributes:

```powershell
$xml = [xml]$ev.ToXml()
$dataMap = @{}
foreach ($node in $xml.Event.EventData.Data) {
    if ($node.Name) { $dataMap[$node.Name] = $node.'#text' }
}
# Example: $dataMap['TargetUserName'], $dataMap['IpAddress'], $dataMap['WorkstationName']
```

### 1.3 Key Windows Troubleshooting Logs & Event IDs Quick Reference

| Category | Primary Logs / Channels | Critical Event IDs / Tools |
| :--- | :--- | :--- |
| **1. OS / Boot / Shutdown / Stability** | `System`, `Microsoft-Windows-Kernel-Boot/Operational`, `Microsoft-Windows-Diagnostics-Performance/Operational` | `41` (Kernel-Power), `1074` (Graceful restart/shutdown), `6008` (Unexpected shutdown), `1001` (BugCheck/WER), `100` (Boot duration), `Win32_ReliabilityRecords` |
| **2. Hardware** | `System`, `Microsoft-Windows-PrintService/Operational`, `Microsoft-Windows-Kernel-PnP/Configuration` | `WHEA-Logger` (`17, 18, 19, 20, 46`), `Resource-Exhaustion-Detector` (`2004`), `Display`/`DxgKrnl` (`4101` TDR), Print Spooler (`307, 372, 808`) |
| **3. Storage** | `System`, `Microsoft-Windows-Ntfs/Operational`, `Microsoft-Windows-StorageSpaces-Driver/Operational`, `Microsoft-Windows-BitLocker/BitLocker Management` | `Disk` (`7, 11, 51, 153`), `StorPort` (`129`), `NTFS` (`55, 98, 130`), `Get-PhysicalDisk` + `Get-StorageReliabilityCounter`, `Get-BitLockerVolume` |
| **4. Networking** | `System`, `Microsoft-Windows-TCPIP/*`, `Microsoft-Windows-NDIS/*`, `Microsoft-Windows-Winsock-AFD/Operational`, `Microsoft-Windows-WFP/Operational`, `Microsoft-Windows-Kernel-Network/Analytic`, `Microsoft-Windows-SMBServer/*`, `Microsoft-Windows-DNS-Client/Operational`, `Microsoft-Windows-WinINet/*`, `Microsoft-Windows-Dhcp-Client/Admin`, `Security` | `5152/5157` (WFP dropped packets), `1014` (DNS timeout), `RasClient` (`20225-20227`), `Get-NetAdapterStatistics` (Rx/Tx packet errors & discards), `Get-NetTCPConnection`, `Get-NetUDPEndpoint` |
| **5. AD / Auth / GPO** | `Security`, `System`, `Microsoft-Windows-NTLM/Operational`, `Microsoft-Windows-GroupPolicy/Operational` | `4624/4625` (Logon), `4740` (Lockout), `4771/4776` (Kerb/NTLM), `8001-8004` (NTLM Op), `7016/7017/5312` (GPO timing/failures), `nltest /sc_verify` |
| **6. Security** | `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-CodeIntegrity/Operational`, `Microsoft-Windows-AppLocker/EXE and DLL`, `Security` | Defender (`1006, 1116, 1117, 2001`), WDAC (`3076, 3077`), AppLocker (`8003, 8004`), Audit (`4672, 4688, 4697`), `Win32_DeviceGuard` |
| **7. User Profiles** | `Application`, `Microsoft-Windows-User Profile Service/Operational`, `Microsoft-Windows-FSLogix-Apps/Operational` | Profile Service (`1500, 1502, 1508, 1511, 1515, 1530`), FSLogix (`25, 26, 31, 41`) |
| **8. Windows Services** | `System` (Service Control Manager) | `7000, 7001, 7009, 7023, 7024, 7031, 7034, 7036` + `Get-CimInstance Win32_Service` (Auto-start services currently stopped) |
| **9. Windows Update / WSUS** | `System`, `Microsoft-Windows-WindowsUpdateClient/Operational` | `19` (Install success), `20` (Install failure), `25` (Sync failure), `Get-HotFix`, `WindowsUpdateLog` |
| **10. Certificates & PKI** | `Microsoft-Windows-CAPI2/Operational`, `Cert:\LocalMachine\My` | Cert expiration audit (`NotAfter < (Get-Date).AddDays(30)`), CAPI2 (`11, 30, 41, 53, 81`) |
| **11. Remote Connectivity** | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`, `Microsoft-Windows-WinRM/Operational` | RDS (`21, 23, 24, 25, 1149`), WinRM (`142, 161, 162`), `Test-WSMan` |
| **12. App Platform** | `Application`, `System`, `Microsoft-Windows-PowerShell/Operational` | `.NET Runtime` (`1026`), `Application Error` (`1000`), `DistributedCOM` (`10016, 10028`), PowerShell (`4103, 4104`) |
| **13. Virtualization** | `Microsoft-Windows-Hyper-V-VMMS-Admin`, `Microsoft-Windows-Hyper-V-Hypervisor-Admin`, `System` | `Get-VM`, `Get-VMSnapshot`, `Get-VMReplication`, `LxssManager` events |
| **14. Cloud & Identity** | `Microsoft-Windows-User Device Registration/Admin`, `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin` | `dsregcmd /status`, Entra Reg (`304, 305, 306`), Intune (`76, 813, 814`) |
| **15. Web Services (IIS)** | `System` (WAS / W3SVC), `Application`, IIS W3C logs | WAS (`5002, 5009, 5011, 5074, 5186`), `Get-IISSite`, `Get-IISAppPool`, SSL binding checks |
| **16. File Services** | `Microsoft-Windows-SMBClient/Connectivity`, `Microsoft-Windows-SMBServer/Connectivity`, `DFS Replication` | `Get-SmbSession`, `Get-SmbOpenFile`, `Get-DfsrBacklog`, DFSR (`2213, 4012, 5002, 5014`) |
| **17. Scheduled Tasks** | `Microsoft-Windows-TaskScheduler/Operational` | `101, 103, 201, 203`, `Get-ScheduledTask` + `Get-ScheduledTaskInfo` (`LastTaskResult != 0`) |
| **18. Time Service** | `System` (Microsoft-Windows-Time-Service) | `12, 24, 35, 36, 46, 50`, `w32tm /query /status`, `w32tm /stripchart` |
| **19. Licensing** | `Application` (`Microsoft-Windows-Security-SPP`) | `8198, 8200, 12288, 12289`, `SoftwareLicensingProduct` CIM class |
| **20. Performance** | Native CIM Formatted Counters (`Win32_PerfFormattedData_*`) & `Get-NetAdapterStatistics` | CPU %, Memory %, Disk Read/Write Latency & Queue, GPU Engine % & Adapter/Process VRAM (`GPUPerformanceCounters`), NIC Rx/Tx KB/s & Receive/Outbound Packet Errors, Top Processes, Open TCP/UDP Connections, `Get-SmbOpenFile`, and Named Pipes (`\\.\pipe\*`) persisted to SQLite (`winsqlite3.dll`) |
| **21. Event Log Infra** | `System`, `Application`, `Microsoft-Windows-Eventlog/Operational` | `104` (Log cleared), `1102` (Audit log cleared), `105, 1104` (Log full), `Get-WinEvent -ListLog *` |
| **22. Recovery & Maint** | `CBS.log`, `DISM.log`, `Win32_ReliabilityRecords` | `Get-WindowsImage` / `Repair-WindowsImage -CheckHealth` (read-only), Reliability Stability Index (`Win32_ReliabilityStabilityMetrics`) |

### 1.4 PowerShell 7 vs. Windows PowerShell 5.1 Compatibility
- Write scripts so they work cleanly in **PowerShell 7.4+** (the recommended host runtime) while avoiding breaking legacy target servers running **Windows PowerShell 5.1**.
- Remember that remote `Invoke-Command` against Windows Server targets runs in **Windows PowerShell 5.1** on the target unless PowerShell 7 remoting endpoints are explicitly configured. Therefore, **any script block executed remotely via `Invoke-Command` must use Windows PowerShell 5.1-compatible syntax** (e.g., avoid `??`, `?.`, ternary `?:`, or `-AsHashtable` inside remote script blocks!).
- Always pass `-Depth 6` to `ConvertTo-Json` and wrap single-element collections in `@(...)` so JSON arrays never collapse into bare objects.
- When converting a `[System.Collections.Generic.List[T]]` to an array, always call `$list.ToArray()` instead of `@($list)` (PowerShell 7.7's DLR `PSToObjectArrayBinder` throws `Argument types do not match` on `@($genericList)`).

### 1.5 Handling Missing Roles & Non-Terminating Errors
If an admin runs an IIS or Hyper-V diagnostic against a server without that role installed, do **not** throw an unhandled stack trace. Return a valid `New-WinInspectorResult` JSON object with `status = "Partial"` (or `"Success"` with 0 rows) and an informative message in `meta.warnings`.

---

## 2. HTML5 → IIS → PowerShell Interface Development Guide

### 2.1 Architecture Contract
1. **Strict Separation of Concerns**:
   - **Frontend (`web/`)**: Pure HTML5, CSS3, and Vanilla JavaScript ES Modules (`type="module"`). No heavy bundler required so files deploy directly into an IIS site folder or serve from Pode.
   - **API Bridge (`server/`)**: 100% pure-PowerShell **Pode** web server (`server/Start-WinInspector.ps1`) hosted behind IIS via **HttpPlatformHandler** or **IIS Reverse Proxy (ARR + URL Rewrite)**. Handles IIS Windows Auth (`Add-PodeAuthIIS` / token impersonation), manifest allow-listing, parameter validation, script execution, and JSONL audit logging.
   - **Scripts (`scripts/`)**: Category-organized `.ps1` scripts sharing `scripts/_Common/WinInspector.Common.psm1`. Every script outputs strictly valid JSON to `stdout` conforming to the standard envelope.

### 2.2 REST API Endpoints

| Method & Route | Purpose | Request / Response |
| :--- | :--- | :--- |
| `GET /api/catalog` | Returns the category tree & dynamic parameter definitions from `scripts/manifest.json` (excluding internal filesystem paths). | `200 OK` JSON catalog |
| `POST /api/connect/test` | Validates DNS, ports (`5986/5985/135/445`), WinRM/CIM connectivity, OS version, and uptime. | Req: `{ computerName, protocol, authMode, credential? }` → Res: `{ reachable, fqdn, osCaption, protocols: {...}, recommendedProtocol }` |
| `POST /api/diagnostics/run` | Executes a single allow-listed diagnostic script against a target server. | Req: `{ computerName, scriptId, protocol, authMode, credential?, parameters: {...} }` → Res: Standardized `{ meta, metrics, schema, data }` JSON |

### 2.3 Safe PowerShell Execution Pattern (Pode Backend)
When executing diagnostic scripts from the Pode backend:
1. **Resolve `scriptId` strictly via `manifest.json`** — reject any unknown ID or path traversal (`..`).
2. **Validate `computerName`** against `^[a-zA-Z0-9][a-zA-Z0-9\.\-]{0,253}$` (or validated IPv4/IPv6).
3. **Validate every parameter** against the parameter's declared `type`, `min`/`max`, or `options` in `manifest.json`.
4. **Never build command strings** or use `Invoke-Expression`. Pass validated parameters exclusively via PowerShell splatting (`& $scriptFullPath @validatedParams`).
5. **Enforce execution timeouts** and clean error capture so unhandled exceptions return a structured `{ meta, metrics, schema, data }` JSON payload instead of raw stack traces.
6. **Forced Session Auth & Credential Handling**:
   - `SessionLogin` (Default & Mandatory Gate): Unauthenticated requests cannot load `/`, `/js/*`, or `/api/*`. Users sign in via `/login` using **UserPrincipalName (`user@domain.net`)** format, validated via Win32 `advapi32!LogonUser`. Credentials are held strictly in an in-memory per-session `SecureString` vault accessible only by that session ID and injected as `-Credential` into every command even when Pode runs under `SYSTEM` or a local account.
   - `CurrentUser` mode is disabled and rejected with HTTP 400.
   - `CustomCredentials`: Construct a `[System.Management.Automation.PSCredential]` strictly in memory (require HTTPS in non-dev mode), pass via `-Credential`, dispose immediately after use, and never log or persist to disk.

### 2.4 Standard PowerShell Diagnostic Script Template

Every script in `scripts/<Category>/<SubCategory>/` must follow this structure:

```powershell
<#
.SYNOPSIS
    Short description of what this diagnostic script checks.
.DESCRIPTION
    Detailed explanation, target event logs/CIM classes, and required permissions.
.NOTES
    Category:    05-ActiveDirectory-Auth / 5.1-Logon
    Protocols:   WinRM, RPC
    ReadOnly:    True
    Reference:   (Optional URL if adapted from References.csv)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9\.\-]{0,253}$')]
    [string]$ComputerName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('Auto', 'WinRM-HTTPS', 'WinRM-HTTP', 'CIM-DCOM', 'RPC')]
    [string]$Protocol = 'Auto',

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxResults = 500,

    [Parameter()]
    [string]$UserName,

    [Parameter()]
    [string]$ClientHost
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\_Common\WinInspector.Common.psm1') -Force

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$warnings = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[string]]::new()
$rows     = [System.Collections.Generic.List[psobject]]::new()

try {
    # 1. Execute remote query (WinPS 5.1-safe scriptblock inside Invoke-WinInspectorRemote)
    $remoteResult = Invoke-WinInspectorRemote -ComputerName $ComputerName -Credential $Credential -Protocol $Protocol -ScriptBlock {
        param($Hours, $Max, $UserFilter, $ClientFilter)
        # Perform server-side filtered Get-WinEvent / Get-CimInstance here
        # Return lightweight PSCustomObjects (avoid returning raw EventRecord objects with huge XML)
    } -ArgumentList @($HoursBack, $MaxResults, $UserName, $ClientHost)

    # 2. Populate $rows and compute summary metrics
    foreach ($item in @($remoteResult.Data)) {
        $rows.Add($item)
    }

    # 3. Define dynamic UI schema (columns + facet filters)
    $schema = @(
        @{ key = 'TimeCreated'; label = 'Timestamp';     type = 'datetime'; filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'Severity';    label = 'Severity';      type = 'severity'; filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'EventId';     label = 'Event ID';      type = 'number';   filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'UserName';    label = 'User';          type = 'user';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'ClientHost';  label = 'Client/Server'; type = 'host';     filterable = $true;  facet = $true;  defaultVisible = $true }
        @{ key = 'Summary';     label = 'Summary';       type = 'string';   filterable = $true;  facet = $false; defaultVisible = $true }
        @{ key = 'RawMessage';  label = 'Full Details';  type = 'string';   filterable = $false; facet = $false; defaultVisible = $false }
    )

    $metrics = @(
        @{ key = 'total_findings'; label = 'Total Findings'; value = $rows.Count; unit = 'rows'; severity = 'info' }
    )

    $sw.Stop()
    New-WinInspectorResult `
        -ScriptId '5.1-logon' `
        -Category 'Active Directory & Authentication' `
        -SubCategory 'Logon' `
        -TargetServer $ComputerName `
        -ProtocolUsed $remoteResult.ProtocolUsed `
        -DurationMs $sw.ElapsedMilliseconds `
        -Schema $schema `
        -Metrics $metrics `
        -Data $rows `
        -Warnings $warnings `
        -Errors $errors | ConvertTo-Json -Depth 6 -Compress
}
catch {
    $sw.Stop()
    $errors.Add($_.Exception.Message)
    New-WinInspectorResult `
        -ScriptId '5.1-logon' `
        -Category 'Active Directory & Authentication' `
        -SubCategory 'Logon' `
        -TargetServer $ComputerName `
        -ProtocolUsed $Protocol `
        -DurationMs $sw.ElapsedMilliseconds `
        -Status 'Error' `
        -Schema @() `
        -Metrics @() `
        -Data @() `
        -Warnings $warnings `
        -Errors $errors | ConvertTo-Json -Depth 6 -Compress
}
```

> **Critical Output Rule**: Never write diagnostic chatter with `Write-Host` or uncaptured pipeline output inside scripts. `stdout` MUST contain **only** the final JSON envelope. Always capture or suppress noisy cmdlet outputs (`$null = ...`).

### 2.5 Dynamic HTML5 Table, Filtering & CSV Export Standards

1. **XSS-Safe Rendering**:
   - Always render remote cell values via `element.textContent = value` (never `innerHTML`). Event log descriptions frequently contain `<`, `>`, quotes, or attacker-controlled payloads.
2. **Schema-Driven Dynamic Table**:
   - Rebuild `<thead>` and column visibility controls from `response.schema` on every category run.
   - Support type-aware sorting (`datetime` via ISO-8601 Date parsing, `number` numerically, `ip` by octet, `severity` by Critical > Error > Warning > Info, `string` localeCompare).
3. **Interactive Focus Filtering**:
   - Automatically build facet dropdowns/chips for every schema column where `facet === true` (e.g., `User`, `Client/Server`, `Source IP`, `Event ID`, `Severity`, `Service`).
   - Support clicking any facetable cell value in the table to immediately apply a filter pill, plus a time-range slider/picker for narrowing returned timestamps client-side.
   - Maintain `state.allRows` and `state.filteredRows` cleanly so toggling filters is instantaneous without re-querying the server.
4. **Safe RFC 4180 CSV Export**:
   - Prepend UTF-8 BOM (`\uFEFF`) so Microsoft Excel opens Unicode cleanly.
   - Neutralize CSV formula injection: if a string cell starts with `=`, `+`, `-`, `@`, `\t`, or `\r`, prefix it with a single quote (`'`) before RFC 4180 quoting (`"` doubled to `""`).
   - Offer both **Export Filtered View** and **Export All Rows**.

---

## 3. IIS Hosting & Troubleshooting Checklist (Pode + IIS)

When configuring or troubleshooting WinInspector on IIS:
1. **Authentication**: Enable **Windows Authentication** (Providers: `Negotiate` first, `NTLM` second); disable **Anonymous Authentication**.
2. **IIS Integration Mode**:
   - **HttpPlatformHandler** (`deploy/web.config.httpplatform`): Set `processPath="pwsh.exe"`, `forwardWindowsAuthToken="true"`, `requestTimeout="00:05:00"`, and pass `-Port %HTTP_PLATFORM_PORT% -UseIISAuth` to `server/Start-WinInspector.ps1`.
   - **IIS Reverse Proxy (`ARR` + `URL Rewrite`)** (`deploy/web.config.arr`): Run Pode on `127.0.0.1:8085` as a Windows Service and proxy via IIS ARR with `preserveHostHeader` and extended proxy timeout (`300s`).
3. **App Pool / Service Identity**: Prefer a domain gMSA (`DOMAIN\gMSA-WinInspector$`), set `.NET CLR version` to `No Managed Code`, and set `Load User Profile = True` (required for PowerShell module/profile paths and Cert/DPAPI operations).
4. **Kerberos Double-Hop Verification**:
   - Confirm SPNs on the IIS server / gMSA (`setspn -L <account>` has `HTTP/<fqdn>`).
   - Confirm RBCD (`Get-ADComputer <target> -Properties PrincipalsAllowedToDelegateToAccount`) or KCD when using **Current User (Kerberos Delegation)** mode.
5. **Pode Module**: Install `Pode` in `AllUsers` scope (`Install-Module Pode -Scope AllUsers`) so the IIS App Pool / Windows Service identity can import it without interactive prompts.

---

## 4. Development & Verification Workflow

Before considering any new script, API change, or UI feature complete:
1. **Manifest Sync**: Verify every new `.ps1` script has a matching entry in `scripts/manifest.json` with accurate `parameters` and `protocols`.
2. **PowerShell Static Analysis**: Run `Invoke-ScriptAnalyzer` (if available) and verify zero syntax errors and WinPS 5.1 compatibility for remote script blocks.
3. **JSON Contract Test**: Run the script directly against `localhost` or a lab server and pipe output to `ConvertFrom-Json` to confirm valid JSON with non-empty `meta`, `schema`, `metrics`, and `data` keys.
4. **Fallback & Error Test**: Test against an unreachable host and a host without the optional role/log to confirm clean error/warning JSON rather than raw stderr crashes.
5. **UI & Export Check**: Verify dynamic column rendering, facet filtering (User, Client, Time, Severity), XSS escaping on special characters (`<script>`), and clean CSV export in Excel.
6. **Attribution Check**: If external community code or patterns were referenced/adapted, log the Category, Sub-Category, Developer, and URL in `References.csv`.
