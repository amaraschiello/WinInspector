/**
 * WinInspector Faux Local Troubleshooting Terminal Controller
 * Executes built-in Windows/PowerShell commands strictly on localhost under the
 * host process identity (SYSTEM / local account) without using remote session credentials.
 * Supports seamless context parameter injection from Performance Monitor filters
 * (Client IP, Process, Local Port, Remote Port, Target Server).
 */
import { runTerminalCommand } from './api.js';

const COMMAND_LIBRARY = [
  // Network & DNS (Context-aware with {clientIp}, {port}, {target})
  { label: 'nslookup (PTR/Host)', cat: 'Network & DNS', shell: 'CMD', cmd: 'nslookup {clientIp}', needs: ['clientIp'], tags: 'dns ptr reverse hostname ip' },
  { label: 'nslookup -type=PTR', cat: 'Network & DNS', shell: 'CMD', cmd: 'nslookup -type=PTR {clientIp}', needs: ['clientIp'], tags: 'dns reverse lookup' },
  { label: 'Resolve-DnsName', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Resolve-DnsName -Name {clientIp} -ErrorAction SilentlyContinue | Format-Table -AutoSize', needs: ['clientIp'], tags: 'dns ptr powershell hostname' },
  { label: 'DNS GetHostEntry', cat: 'Network & DNS', shell: 'PowerShell', cmd: "[System.Net.Dns]::GetHostEntry('{clientIp}') | Format-List HostName,Aliases,AddressList", needs: ['clientIp'], tags: 'dns reverse hostname net' },
  { label: 'nbtstat -A', cat: 'Network & DNS', shell: 'CMD', cmd: 'nbtstat -A {clientIp}', needs: ['clientIp'], tags: 'netbios hostname workstation ip' },
  { label: 'ping -n 4', cat: 'Network & DNS', shell: 'CMD', cmd: 'ping -n 4 {clientIp}', needs: ['clientIp'], tags: 'icmp latency reachability' },
  { label: 'tracert -d', cat: 'Network & DNS', shell: 'CMD', cmd: 'tracert -d -h 15 {clientIp}', needs: ['clientIp'], tags: 'traceroute hop path' },
  { label: 'Test-NetConnection', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Test-NetConnection -ComputerName {clientIp} -Port {port} -InformationLevel Detailed', needs: ['clientIp', 'port'], tags: 'tcp port test connectivity' },
  { label: 'ipconfig /all', cat: 'Network & DNS', shell: 'CMD', cmd: 'ipconfig /all', tags: 'nic dhcp dns gateway mac' },
  { label: 'ipconfig /displaydns', cat: 'Network & DNS', shell: 'CMD', cmd: 'ipconfig /displaydns', tags: 'dns cache resolver' },
  { label: 'Get-DnsClientCache', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Get-DnsClientCache | Select-Object -First 40 Entry,Name,Type,Status,Data | Format-Table -AutoSize', tags: 'dns cache' },
  { label: 'Get-NetIPConfiguration', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Get-NetIPConfiguration -Detailed', tags: 'ip subnet gateway dns' },
  { label: 'Get-NetAdapter', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Get-NetAdapter | Format-Table Name,InterfaceDescription,Status,LinkSpeed,MacAddress -AutoSize', tags: 'nic link speed mac' },
  { label: 'Get-NetAdapterStatistics', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Get-NetAdapterStatistics | Format-Table Name,ReceivedBytes,SentBytes,ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscards,OutboundDiscards -AutoSize', tags: 'nic packet errors discards' },
  { label: 'route print', cat: 'Network & DNS', shell: 'CMD', cmd: 'route print', tags: 'routing table gateway' },
  { label: 'Get-NetRoute', cat: 'Network & DNS', shell: 'PowerShell', cmd: 'Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Format-Table DestinationPrefix,NextHop,InterfaceAlias,RouteMetric -AutoSize', tags: 'routing ipv4' },
  { label: 'arp -a', cat: 'Network & DNS', shell: 'CMD', cmd: 'arp -a', tags: 'arp mac neighbor' },

  // Ports & TCP/UDP Connections
  { label: 'netstat -ano | findstr :port', cat: 'Ports & TCP', shell: 'CMD', cmd: 'netstat -ano | findstr :{port}', needs: ['port'], tags: 'socket port pid' },
  { label: 'netstat -ano | findstr IP', cat: 'Ports & TCP', shell: 'CMD', cmd: 'netstat -ano | findstr {clientIp}', needs: ['clientIp'], tags: 'socket ip pid' },
  { label: 'Get-NetTCPConnection (LocalPort)', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetTCPConnection -LocalPort {localPort} -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize', needs: ['localPort'], tags: 'tcp local port owner' },
  { label: 'Get-NetTCPConnection (RemotePort)', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetTCPConnection -RemotePort {remotePort} -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize', needs: ['remotePort'], tags: 'tcp remote port owner' },
  { label: 'Get-NetTCPConnection (RemoteIP)', cat: 'Ports & TCP', shell: 'PowerShell', cmd: "Get-NetTCPConnection -RemoteAddress '{clientIp}' -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize", needs: ['clientIp'], tags: 'tcp client ip owner' },
  { label: 'netstat -ano', cat: 'Ports & TCP', shell: 'CMD', cmd: 'netstat -ano', tags: 'all sockets listening established' },
  { label: 'Top TCP Processes', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetTCPConnection -State Established | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 15 Count,@{N="PID";E={$_.Name}},@{N="Process";E={(Get-Process -Id $_.Name -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize', tags: 'tcp established count process' },
  { label: 'Listening TCP Ports', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize', tags: 'listen ports' },
  { label: 'Get-NetUDPEndpoint', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetUDPEndpoint | Sort-Object LocalPort | Select-Object -First 40 LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize', tags: 'udp ports' },
  { label: 'Firewall Rules (Enabled)', cat: 'Ports & TCP', shell: 'PowerShell', cmd: 'Get-NetFirewallRule -Enabled True | Select-Object -First 30 DisplayName,Direction,Action,Profile | Format-Table -AutoSize', tags: 'firewall rules' },

  // Processes & Services
  { label: 'Get-Process (Filtered)', cat: 'Processes & Services', shell: 'PowerShell', cmd: "Get-Process -Name '*{process}*' -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}},Handles,Path | Format-Table -AutoSize", needs: ['process'], tags: 'process pid cpu memory path' },
  { label: 'Win32_Process CommandLine', cat: 'Processes & Services', shell: 'PowerShell', cmd: 'Get-CimInstance Win32_Process -Filter "Name LIKE \'%{process}%\'" | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-Table -Wrap -AutoSize', needs: ['process'], tags: 'process wmi commandline parent' },
  { label: 'tasklist /fi Process', cat: 'Processes & Services', shell: 'CMD', cmd: 'tasklist /svc /fi "IMAGENAME eq {process}.exe"', needs: ['process'], tags: 'tasklist service process' },
  { label: 'Top 20 CPU Processes', cat: 'Processes & Services', shell: 'PowerShell', cmd: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id,ProcessName,@{N="CPU(s)";E={[math]::Round($_.CPU,1)}},@{N="RAM(MB)";E={[math]::Round($_.WorkingSet64/1MB,1)}},Handles | Format-Table -AutoSize', tags: 'top cpu ram' },
  { label: 'tasklist /svc', cat: 'Processes & Services', shell: 'CMD', cmd: 'tasklist /svc', tags: 'svchost services' },
  { label: 'Running Services', cat: 'Processes & Services', shell: 'PowerShell', cmd: 'Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName | Select-Object Name,DisplayName,StartType | Format-Table -AutoSize', tags: 'services running' },
  { label: 'Stopped Auto Services', cat: 'Processes & Services', shell: 'PowerShell', cmd: "Get-CimInstance Win32_Service -Filter \"StartMode='Auto' AND State!='Running'\" | Select-Object Name,DisplayName,State,ExitCode | Format-Table -AutoSize", tags: 'services failed stopped auto' },
  { label: 'Loaded Drivers (Signed)', cat: 'Processes & Services', shell: 'PowerShell', cmd: 'Get-CimInstance Win32_SystemDriver -Filter "State=\'Running\'" | Select-Object -First 30 Name,DisplayName,StartMode,PathName | Format-Table -AutoSize', tags: 'drivers kernel' },

  // SMB, Storage & System
  { label: 'Get-SmbSession', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-SmbSession | Format-Table SessionId,ClientComputerName,ClientUserName,NumOpens,Dialect -AutoSize', tags: 'smb clients sessions' },
  { label: 'Get-SmbOpenFile', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-SmbOpenFile | Select-Object -First 40 FileId,SessionId,ClientUserName,ClientComputerName,Path | Format-Table -AutoSize', tags: 'smb open files locks' },
  { label: 'Get-SmbConnection', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-SmbConnection | Format-Table ServerName,ShareName,UserName,Dialect,NumOpens -AutoSize', tags: 'smb outbound connections' },
  { label: 'Get-SmbShare', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-SmbShare | Format-Table Name,Path,Description,CurrentUsers -AutoSize', tags: 'smb shares' },
  { label: 'Get-Volume', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-Volume | Where-Object DriveLetter | Format-Table DriveLetter,FileSystemLabel,FileSystem,@{N="SizeGB";E={[math]::Round($_.Size/1GB,1)}},@{N="FreeGB";E={[math]::Round($_.SizeRemaining/1GB,1)}},HealthStatus -AutoSize', tags: 'disk space volume' },
  { label: 'Get-PhysicalDisk', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-PhysicalDisk | Format-Table FriendlyName,MediaType,HealthStatus,OperationalStatus,@{N="SizeGB";E={[math]::Round($_.Size/1GB,1)}} -AutoSize', tags: 'storage smart disk' },
  { label: 'systeminfo', cat: 'SMB & System', shell: 'CMD', cmd: 'systeminfo', tags: 'os uptime hotfix memory' },
  { label: 'whoami /all', cat: 'SMB & System', shell: 'CMD', cmd: 'whoami /all', tags: 'identity groups privileges' },
  { label: 'klist', cat: 'SMB & System', shell: 'CMD', cmd: 'klist', tags: 'kerberos tickets tgt' },
  { label: 'w32tm /query /status', cat: 'SMB & System', shell: 'CMD', cmd: 'w32tm /query /status', tags: 'ntp time sync' },
  { label: 'Recent System Errors', cat: 'SMB & System', shell: 'PowerShell', cmd: 'Get-WinEvent -FilterHashtable @{LogName="System";Level=1,2,3} -MaxEvents 20 | Format-Table TimeCreated,Id,LevelDisplayName,ProviderName,@{N="Message";E={($_.Message -split "`n")[0]}} -AutoSize', tags: 'event log errors' },

  // AD, Certs & IIS
  { label: 'nltest /dsgetdc', cat: 'AD, Certs & IIS', shell: 'CMD', cmd: 'nltest /dsgetdc:%USERDNSDOMAIN%', tags: 'domain controller ad' },
  { label: 'gpresult /r', cat: 'AD, Certs & IIS', shell: 'CMD', cmd: 'gpresult /r', tags: 'gpo group policy' },
  { label: 'Machine Certificates', cat: 'AD, Certs & IIS', shell: 'PowerShell', cmd: 'Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject,NotAfter,HasPrivateKey,Thumbprint | Sort-Object NotAfter | Format-Table -AutoSize', tags: 'tls ssl cert expire' },
  { label: 'WinRM Listeners', cat: 'AD, Certs & IIS', shell: 'CMD', cmd: 'winrm enumerate winrm/config/listener', tags: 'winrm 5985 5986' },
  { label: 'WinRM QuickConfig', cat: 'AD, Certs & IIS', shell: 'PowerShell', cmd: 'Test-WSMan -ComputerName {target}', tags: 'winrm wsman' },
  { label: 'IIS Worker Processes', cat: 'AD, Certs & IIS', shell: 'CMD', cmd: '%windir%\\system32\\inetsrv\\appcmd.exe list wp', tags: 'iis w3wp apppool' },
];

const CATEGORIES = ['All', 'Network & DNS', 'Ports & TCP', 'Processes & Services', 'SMB & System', 'AD, Certs & IIS'];

export class TerminalController {
  constructor({ dom, getTargetServer }) {
    this.dom = dom;
    this.getTargetServer = getTargetServer;
    this.cwd = 'C:\\';
    this.hostName = 'localhost';
    this.processIdentity = 'local';
    this.activeCategory = 'All';
    this.contextParams = {
      clientIp: '',
      processName: '',
      localPort: '',
      remotePort: '',
    };
    this.history = [];
    this.historyIdx = -1;
    this.running = false;
    this.abortController = null;
    this.initialized = false;
    this.transcript = [];

    this._bindEvents();
    this._renderCategoryTabs();
    this._renderContextBar();
    this._renderQuickCommands();
    this._updatePrompt();
  }

  setHostContext({ serverHost, processIdentity }) {
    if (serverHost) this.hostName = serverHost;
    if (processIdentity) this.processIdentity = processIdentity;
    if (this.dom.hostBadge) {
      this.dom.hostBadge.textContent = `Host: ${this.hostName} (localhost) • Process: ${this.processIdentity} • No Remote Credentials Used`;
    }
    this._updatePrompt();
  }

  setContextParams(filters = {}) {
    this.contextParams = {
      clientIp: (filters.clientIp || '').trim(),
      processName: (filters.processName || '').trim(),
      localPort: (filters.localPort || '').trim(),
      remotePort: (filters.remotePort || '').trim(),
    };
    this._renderContextBar();
    this._renderQuickCommands();
  }

  show({ focus = true } = {}) {
    this.dom.panel.classList.remove('hidden');
    if (!this.initialized) {
      this.initialized = true;
      this._appendSystemLine(
        `WinInspector Local Troubleshooting Terminal [${this.hostName}]`
      );
      this._appendSystemLine(
        `Running strictly on localhost as host process (${this.processIdentity}). Session credentials are NOT injected.`
      );
      this._appendSystemLine(
        `Tip: Click any Process, Client IP, Local Port, or Remote Port above to bind it to quick commands, then click a command (or enable Auto-run).`
      );
    }
    this._renderContextBar();
    this._renderQuickCommands();
    if (focus) {
      setTimeout(() => this.dom.input?.focus(), 0);
    }
  }

  hide() {
    this.dom.panel.classList.add('hidden');
  }

  _getShell() {
    return this.dom.shellSelect?.value || 'PowerShell';
  }

  _getTimeout() {
    return Number(this.dom.timeoutSelect?.value || 30);
  }

  _updatePrompt() {
    if (!this.dom.promptLabel) return;
    const prefix = this._getShell() === 'PowerShell' ? `PS ${this.cwd}>` : `${this.cwd}>`;
    this.dom.promptLabel.textContent = prefix;
  }

  _resolveCommandTemplate(template) {
    const rawTarget = (this.getTargetServer?.() || '').trim() || 'localhost';
    const clientIp = this.contextParams.clientIp || rawTarget;
    const processName = this.contextParams.processName || 'svchost';
    const localPort = this.contextParams.localPort || this.contextParams.remotePort || '8085';
    const remotePort = this.contextParams.remotePort || this.contextParams.localPort || '443';
    const anyPort = this.contextParams.remotePort || this.contextParams.localPort || '5985';

    return template
      .replace(/\{clientIp\}/g, clientIp)
      .replace(/\{process\}/g, processName)
      .replace(/\{localPort\}/g, localPort)
      .replace(/\{remotePort\}/g, remotePort)
      .replace(/\{port\}/g, anyPort)
      .replace(/\{target\}/g, rawTarget);
  }

  _hasMatchingContext(item) {
    if (!item.needs || item.needs.length === 0) return false;
    return item.needs.some((n) => {
      if (n === 'clientIp') return Boolean(this.contextParams.clientIp);
      if (n === 'process') return Boolean(this.contextParams.processName);
      if (n === 'localPort') return Boolean(this.contextParams.localPort);
      if (n === 'remotePort') return Boolean(this.contextParams.remotePort);
      if (n === 'port') return Boolean(this.contextParams.localPort || this.contextParams.remotePort);
      return false;
    });
  }

  _renderContextBar() {
    if (!this.dom.contextBar) return;
    this.dom.contextBar.replaceChildren();

    const entries = [
      ['Client IP', this.contextParams.clientIp],
      ['Process', this.contextParams.processName],
      ['Local Port', this.contextParams.localPort],
      ['Remote Port', this.contextParams.remotePort],
    ].filter(([, val]) => Boolean(val));

    if (entries.length === 0) {
      const hint = document.createElement('span');
      hint.className = 'term-ctx-pill muted-pill';
      hint.textContent = 'No table parameter selected — click any Process, Client IP, Local Port, or Remote Port in 20.1';
      this.dom.contextBar.appendChild(hint);
      return;
    }

    for (const [label, val] of entries) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'term-ctx-pill';
      btn.textContent = `${label}: ${val}`;
      btn.title = `Click to insert '${val}' into terminal input`;
      btn.addEventListener('click', () => {
        const cur = this.dom.input.value;
        this.dom.input.value = cur ? `${cur} ${val}` : val;
        this.dom.input.focus();
      });
      this.dom.contextBar.appendChild(btn);
    }
  }

  _renderCategoryTabs() {
    if (!this.dom.catTabs) return;
    this.dom.catTabs.replaceChildren();
    for (const cat of CATEGORIES) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = cat === this.activeCategory ? 'term-cat-btn active' : 'term-cat-btn';
      btn.textContent = cat;
      btn.addEventListener('click', () => {
        this.activeCategory = cat;
        this._renderCategoryTabs();
        this._renderQuickCommands();
      });
      this.dom.catTabs.appendChild(btn);
    }
  }

  _renderQuickCommands() {
    if (!this.dom.quickBar) return;
    this.dom.quickBar.replaceChildren();

    const search = (this.dom.cmdSearch?.value || '').trim().toLowerCase();
    const filtered = COMMAND_LIBRARY.filter((item) => {
      if (this.activeCategory !== 'All' && item.cat !== this.activeCategory) return false;
      if (!search) return true;
      const hay = `${item.label} ${item.cmd} ${item.cat} ${item.tags || ''}`.toLowerCase();
      return hay.includes(search);
    });

    // Prioritize commands that match active selected parameters (Client IP, Process, Port)
    const sorted = [...filtered].sort((a, b) => {
      const aMatch = this._hasMatchingContext(a) ? 1 : 0;
      const bMatch = this._hasMatchingContext(b) ? 1 : 0;
      return bMatch - aMatch;
    });

    if (sorted.length === 0) {
      const empty = document.createElement('span');
      empty.className = 'muted small';
      empty.textContent = 'No commands match your search.';
      this.dom.quickBar.appendChild(empty);
      return;
    }

    for (const item of sorted) {
      const resolvedCmd = this._resolveCommandTemplate(item.cmd);
      const hasCtx = this._hasMatchingContext(item);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = hasCtx ? 'term-chip has-ctx' : 'term-chip';
      btn.textContent = item.label;
      btn.title = `[${item.shell}] ${resolvedCmd}\n(Click to insert • Double-click or enable Auto-run to execute immediately)`;

      btn.addEventListener('click', async (e) => {
        if (item.shell && this.dom.shellSelect) {
          this.dom.shellSelect.value = item.shell;
          this._updatePrompt();
        }
        this.dom.input.value = resolvedCmd;
        this.dom.input.focus();
        if (this.dom.autoRunCheck?.checked || e.shiftKey) {
          await this.executeCurrentInput();
        }
      });

      btn.addEventListener('dblclick', async () => {
        if (item.shell && this.dom.shellSelect) {
          this.dom.shellSelect.value = item.shell;
          this._updatePrompt();
        }
        this.dom.input.value = resolvedCmd;
        await this.executeCurrentInput();
      });

      this.dom.quickBar.appendChild(btn);
    }
  }

  _bindEvents() {
    this.dom.shellSelect?.addEventListener('change', () => this._updatePrompt());
    this.dom.cmdSearch?.addEventListener('input', () => this._renderQuickCommands());

    this.dom.form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.executeCurrentInput();
    });

    this.dom.stopBtn?.addEventListener('click', () => {
      if (this.abortController) {
        this.abortController.abort();
      }
    });

    this.dom.clearBtn?.addEventListener('click', () => this.clear());

    this.dom.copyBtn?.addEventListener('click', async () => {
      const text = this.transcript.join('\n');
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        const orig = this.dom.copyBtn.textContent;
        this.dom.copyBtn.textContent = 'Copied!';
        setTimeout(() => { this.dom.copyBtn.textContent = orig; }, 1200);
      } catch {
        // Ignore clipboard errors in non-HTTPS contexts
      }
    });

    this.dom.downloadBtn?.addEventListener('click', () => {
      const text = this.transcript.join('\n');
      if (!text) return;
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      a.href = url;
      a.download = `WinInspector_Terminal_${this.hostName}_${stamp}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

    this.dom.output?.addEventListener('mouseup', () => {
      const sel = window.getSelection();
      if (!sel || sel.toString().length === 0) {
        this.dom.input?.focus();
      }
    });

    this.dom.input?.addEventListener('keydown', (e) => {
      if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) {
        e.preventDefault();
        this.clear();
        return;
      }
      if (e.key === 'ArrowUp') {
        if (this.history.length === 0) return;
        e.preventDefault();
        if (this.historyIdx < this.history.length - 1) {
          this.historyIdx++;
        }
        this.dom.input.value = this.history[this.history.length - 1 - this.historyIdx] || '';
      } else if (e.key === 'ArrowDown') {
        if (this.history.length === 0) return;
        e.preventDefault();
        if (this.historyIdx > 0) {
          this.historyIdx--;
          this.dom.input.value = this.history[this.history.length - 1 - this.historyIdx] || '';
        } else {
          this.historyIdx = -1;
          this.dom.input.value = '';
        }
      }
    });
  }

  clear() {
    this.dom.output.replaceChildren();
    this.transcript = [];
    this._appendSystemLine(`Terminal cleared (${this.hostName} • ${this.processIdentity}).`);
  }

  _scrollBottom() {
    this.dom.output.scrollTop = this.dom.output.scrollHeight;
  }

  _appendSystemLine(text) {
    const div = document.createElement('div');
    div.className = 'term-line term-system';
    div.textContent = text;
    this.dom.output.appendChild(div);
    this.transcript.push(text);
    this._scrollBottom();
  }

  async executeCurrentInput() {
    if (this.running) return;
    const command = (this.dom.input.value || '').trim();
    if (!command) return;

    if (/^(cls|clear|clear-host)$/i.test(command)) {
      this.dom.input.value = '';
      this.clear();
      return;
    }

    if (this.history[this.history.length - 1] !== command) {
      this.history.push(command);
      if (this.history.length > 100) this.history.shift();
    }
    this.historyIdx = -1;
    this.dom.input.value = '';

    const shell = this._getShell();
    const promptText = shell === 'PowerShell' ? `PS ${this.cwd}>` : `${this.cwd}>`;

    const block = document.createElement('div');
    block.className = 'term-entry';

    const cmdRow = document.createElement('div');
    cmdRow.className = 'term-cmd-line';
    const promptSpan = document.createElement('span');
    promptSpan.className = 'term-prompt';
    promptSpan.textContent = promptText;
    const cmdSpan = document.createElement('span');
    cmdSpan.className = 'term-cmd-text';
    cmdSpan.textContent = ` ${command}`;
    cmdRow.append(promptSpan, cmdSpan);
    block.appendChild(cmdRow);

    const statusLine = document.createElement('div');
    statusLine.className = 'term-meta term-running';
    statusLine.textContent = `Running on localhost (${shell})…`;
    block.appendChild(statusLine);

    this.dom.output.appendChild(block);
    this.transcript.push(`${promptText} ${command}`);
    this._scrollBottom();

    this.running = true;
    this.abortController = new AbortController();
    this.dom.runBtn.disabled = true;
    this.dom.input.disabled = true;
    this.dom.stopBtn.classList.remove('hidden');

    try {
      const res = await runTerminalCommand({
        command,
        shell,
        cwd: this.cwd,
        timeoutSeconds: this._getTimeout(),
        signal: this.abortController.signal,
      });

      if (res.cwd) {
        this.cwd = res.cwd;
        this._updatePrompt();
      }
      if (res.executedAs) {
        this.processIdentity = res.executedAs;
      }

      statusLine.remove();

      if (res.stdout) {
        const preOut = document.createElement('pre');
        preOut.className = 'term-stdout';
        preOut.textContent = res.stdout.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
        block.appendChild(preOut);
        this.transcript.push(preOut.textContent);
      }

      if (res.stderr) {
        const preErr = document.createElement('pre');
        preErr.className = 'term-stderr';
        preErr.textContent = res.stderr.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
        block.appendChild(preErr);
        this.transcript.push(`[STDERR]\n${preErr.textContent}`);
      }

      if (!res.stdout && !res.stderr) {
        const empty = document.createElement('div');
        empty.className = 'term-meta';
        empty.textContent = '(No output)';
        block.appendChild(empty);
      }

      const meta = document.createElement('div');
      meta.className = `term-meta ${res.exitCode === 0 && !res.timedOut ? 'term-meta-ok' : 'term-meta-err'}`;
      const flags = [];
      if (res.timedOut) flags.push('TIMED OUT');
      if (res.truncated) flags.push('TRUNCATED');
      const extra = flags.length ? ` • ${flags.join(', ')}` : '';
      meta.textContent = `Exit ${res.exitCode} • ${res.durationMs}ms • localhost (${res.executedAs})${extra}`;
      block.appendChild(meta);
      this.transcript.push(`-- ${meta.textContent}`);
    } catch (err) {
      statusLine.remove();
      const errPre = document.createElement('pre');
      errPre.className = 'term-stderr';
      errPre.textContent = err.name === 'AbortError'
        ? 'Request cancelled by user.'
        : `Error: ${err.message}`;
      block.appendChild(errPre);
      this.transcript.push(errPre.textContent);
    } finally {
      this.running = false;
      this.abortController = null;
      this.dom.runBtn.disabled = false;
      this.dom.input.disabled = false;
      this.dom.stopBtn.classList.add('hidden');
      this._scrollBottom();
      this.dom.input.focus();
    }
  }
}
