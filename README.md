# WinInspector

Centralized, IIS-hosted **HTML5 + 100% Pure PowerShell (Pode)** diagnostic and troubleshooting portal for Windows Server operating system and service issues.

## Features (All 24 Categories / 71 Diagnostic Sub-Categories)
- **Target Any Server**: Enter a Hostname or FQDN and test connectivity (`DNS`, `WinRM HTTPS 5986`, `WinRM HTTP 5985`, `RPC/DCOM 135`, `SMB 445`) with automatic short-hostname-to-FQDN resolution and protocol fallback.
- **Category 2: Management**: PowerShell modules/libraries, installed apps (WinGet + native MSI/EXE), Autoruns, Disk/Partition/Volume details, Local Users & Groups, Local & Group Policy (`gpresult`), iSCSI connections, Failover Cluster status, NTFS share permissions & open files/handles, Data Deduplication + raw storage calculator, Volume Shadow Copies (VSS), DHCP scopes & options, Firewall profiles & rules, and SQL Server diagnostics.
- **Live Performance Monitor + Merged Local Terminal**:
  - 1–15s SQLite-backed (`winsqlite3.dll`) CPU/RAM/GPU/Disk/Network monitoring with HTML5 Canvas charts.
  - Click-to-toggle filtering by Process, Client IP, Local Port, and Remote Port, sortable columns, **Kill Process**, and **Analyze in Detail** modal (Disk I/O rates, RAM/Private Bytes/VRAM, open sockets, loaded DLLs).
  - Embedded **Local Troubleshooting Terminal** (`localhost` PowerShell/CMD as host process) with 50+ searchable commands that automatically bind active filter parameters (`{clientIp}`, `{process}`, `{localPort}`, `{remotePort}`).
- **Forced Session Authentication (`SYSTEM`-Safe Hosting)**:
  - **Authenticated Session (UPN)** — mandatory `/login` gate (PAM-friendly `Username` / `Password` fields). Validates `user@domain.net` via Win32 `LogonUser`, resolves `DOMAIN\SamAccountName`, and stores a read-only `SecureString` `[PSCredential]` strictly per HTTP session.
  - **Local Passthrough (Master Password)** — optional `/login` unlock button (default master password `a1b2c3` with first-time reset prompt, stored as salted PBKDF2-SHA256 in `data/master-auth.json`) to run commands directly as the host process / `SYSTEM` account without domain credentials.
  - **Alternate Credentials (Run-As)** — optional per-request in-memory override credentials over HTTPS (never stored on disk or in browser `localStorage`).
- **Network Listening & Native HTTPS**: Automatically binds `*` (all interfaces, dual-stack IPv4/IPv6) when run elevated/`SYSTEM`, and supports `-UseHttps -CertificateThumbprint <thumbprint>` or `-SelfSigned`.
- **Dynamic HTML5 Interface**:
  - Category tree mirroring `TroubleshootingCategories.txt` with instant keyword & Event ID search (`4625`, `BSOD`, `Spooler`, `TLS`, `DNS`, etc.).
  - Auto-generated category parameters & lookback presets.
  - Dynamic table columns, type-aware sorting, multi-facet focus filtering (click any User, Client, IP, Server, Service, or Event ID cell to filter), time-range narrowing, slide-over detail drawer, and **RFC 4180 CSV Export** (filtered or full).
- **Zero Arbitrary Command Execution**: Strict allow-list in `scripts/manifest.json`, typed parameter validation, read-only diagnostics, XSS-safe DOM rendering, CSV formula-injection neutralization, and JSONL audit logging (`logs/audit.jsonl`).

## Quick Start (Local Testing / DevMode)

1. Install **PowerShell 7+** and the **Pode** module:
   ```powershell
   Install-Module -Name Pode -Scope CurrentUser
   ```
2. Start WinInspector in DevMode:
   ```powershell
   pwsh -NoProfile -File .\server\Start-WinInspector.ps1 -DevMode
   ```
3. Open your browser to `http://127.0.0.1:8085`.

## Deploying to IIS (Central Management Server)

1. Install **PowerShell 7 LTS** and **Pode** for all users:
   ```powershell
   Install-Module -Name Pode -Scope AllUsers
   ```
2. Install either:
   - **IIS HttpPlatformHandler** (recommended for Windows Auth token forwarding + Kerberos Delegation), **OR**
   - **IIS Application Request Routing (ARR) + URL Rewrite** (Reverse Proxy mode with Pode running as a Windows Service).
3. Copy the repository into `C:\inetpub\WinInspector` and run:
   ```powershell
   .\deploy\Install-WinInspectorIIS.ps1 -PhysicalPath C:\inetpub\WinInspector -HostingMode HttpPlatformHandler
   ```
4. On target servers (if WinRM is not yet enabled), run:
   ```powershell
   .\deploy\Enable-WinInspectorTarget.ps1
   ```
   Users sign in at `/login` with their `user@domain.net` UPN; Pode runs as `NT AUTHORITY\SYSTEM` (or a local service account) and injects each session's in-memory `SecureString` `[PSCredential]` directly into every remote WinRM/CIM/RPC call.

## Documentation
- [project-summary.md](project-summary.md) — Full architecture, security model, data contracts, and phased roadmap.
- [References.csv](References.csv) — Verified external GitHub repositories and developers referenced.
- [skills/skill.md](skills/skill.md) — Windows Systems Administration & HTML5-to-PowerShell development guide.
