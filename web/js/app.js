/**
 * WinInspector Main Application Controller
 */
import { fetchHealth, fetchCatalog, testServerConnection, runDiagnostic, resetTerminalSession, logoutSession } from './api.js';
import { renderSidebar } from './sidebar.js';
import { renderParametersForm, collectParameterValues } from './paramsForm.js';
import { DynamicDataTable } from './dataTable.js';
import { exportRowsToCsv } from './csvExport.js';
import { PerfMonitorController } from './perfMonitor.js';
import { TerminalController } from './terminal.js';

const state = {
  catalog: null,
  selectedCategory: null,
  selectedSub: null,
  expandedCategories: new Set(),
  sessionCredential: null, // Strictly in-memory; never written to localStorage
  activeController: null,
  lastResponse: null,
};

const els = {
  serverIdentityLabel: document.getElementById('serverIdentityLabel'),
  connectionForm: document.getElementById('connectionForm'),
  serverInput: document.getElementById('serverInput'),
  recentServers: document.getElementById('recentServers'),
  authModeSelect: document.getElementById('authModeSelect'),
  protocolSelect: document.getElementById('protocolSelect'),
  credBtn: document.getElementById('credBtn'),
  testConnBtn: document.getElementById('testConnBtn'),
  themeToggleBtn: document.getElementById('themeToggleBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  connRibbon: document.getElementById('connectionStatusRibbon'),
  categorySearch: document.getElementById('categorySearch'),
  onlyImplementedToggle: document.getElementById('onlyImplementedToggle'),
  categoryTree: document.getElementById('categoryTree'),
  selectedTitle: document.getElementById('selectedTitle'),
  selectedDescription: document.getElementById('selectedDescription'),
  selectedProtocols: document.getElementById('selectedProtocols'),
  paramsForm: document.getElementById('paramsForm'),
  paramsGrid: document.getElementById('paramsGrid'),
  quickTimePresets: document.getElementById('quickTimePresets'),
  runAnalysisBtn: document.getElementById('runAnalysisBtn'),
  cancelRunBtn: document.getElementById('cancelRunBtn'),
  alertsContainer: document.getElementById('alertsContainer'),
  metricsStrip: document.getElementById('metricsStrip'),
  resultsPanel: document.getElementById('resultsPanel'),
  welcomeState: document.getElementById('welcomeState'),
  exportFilteredBtn: document.getElementById('exportFilteredBtn'),
  exportAllBtn: document.getElementById('exportAllBtn'),
  credModalBackdrop: document.getElementById('credModalBackdrop'),
  credModalForm: document.getElementById('credModalForm'),
  credUsername: document.getElementById('credUsername'),
  credPassword: document.getElementById('credPassword'),
  closeCredModalBtn: document.getElementById('closeCredModalBtn'),
  clearCredBtn: document.getElementById('clearCredBtn'),
  rdpSessionsPanel: document.getElementById('rdpSessionsPanel'),
  queryQwinstaBtn: document.getElementById('queryQwinstaBtn'),
  rdpSessionsStatus: document.getElementById('rdpSessionsStatus'),
  rdpSessionsTbody: document.getElementById('rdpSessionsTbody'),
};

const dataTable = new DynamicDataTable({
  globalSearch: document.getElementById('tableGlobalSearch'),
  timeFilterGroup: document.getElementById('timeFilterGroup'),
  timeFromInput: document.getElementById('timeFromInput'),
  timeToInput: document.getElementById('timeToInput'),
  rowCountBadge: document.getElementById('rowCountBadge'),
  columnsBtn: document.getElementById('columnsBtn'),
  columnsMenu: document.getElementById('columnsMenu'),
  facetBar: document.getElementById('facetBar'),
  activePillsBar: document.getElementById('activePillsBar'),
  thead: document.getElementById('resultsThead'),
  tbody: document.getElementById('resultsTbody'),
  emptyState: document.getElementById('emptyTableState'),
  drawerBackdrop: document.getElementById('detailDrawerBackdrop'),
  drawer: document.getElementById('detailDrawer'),
  drawerBody: document.getElementById('drawerBody'),
  closeDrawerBtn: document.getElementById('closeDrawerBtn'),
  copyRawBtn: document.getElementById('copyRawBtn'),
});

const perfMonitor = new PerfMonitorController({
  dom: {
    panel: document.getElementById('perfMonitorPanel'),
    intervalSelect: document.getElementById('perfIntervalSelect'),
    startBtn: document.getElementById('perfStartBtn'),
    stopBtn: document.getElementById('perfStopBtn'),
    statusBadge: document.getElementById('perfStatusBadge'),
    sessionSelect: document.getElementById('perfSessionSelect'),
    refreshSessionsBtn: document.getElementById('perfRefreshSessionsBtn'),
    chartCompute: document.getElementById('chartCompute'),
    chartNetThroughput: document.getElementById('chartNetThroughput'),
    chartNetErrors: document.getElementById('chartNetErrors'),
    chartBreakdown: document.getElementById('chartBreakdown'),
    filterClientIp: document.getElementById('perfFilterClientIp'),
    filterProtocol: document.getElementById('perfFilterProtocol'),
    filterService: document.getElementById('perfFilterService'),
    filterProcess: document.getElementById('perfFilterProcess'),
    filterLocalPort: document.getElementById('perfFilterLocalPort'),
    filterRemotePort: document.getElementById('perfFilterRemotePort'),
    filterSearch: document.getElementById('perfFilterSearch'),
    applyFilterBtn: document.getElementById('perfApplyFilterBtn'),
    clearFilterBtn: document.getElementById('perfClearFilterBtn'),
    tabButtons: Array.from(document.querySelectorAll('[data-perf-tab]')),
    exportTabCsvBtn: document.getElementById('perfExportTabCsvBtn'),
    tabHead: document.getElementById('perfTabHead'),
    tabBody: document.getElementById('perfTabBody'),
    procDetailBackdrop: document.getElementById('procDetailModalBackdrop'),
    procDetailTitle: document.getElementById('procDetailModalTitle'),
    procDetailBody: document.getElementById('procDetailBody'),
    procDetailAutoRefresh: document.getElementById('procDetailAutoRefresh'),
    procDetailRefreshBtn: document.getElementById('procDetailRefreshBtn'),
    procDetailKillBtn: document.getElementById('procDetailKillBtn'),
    closeProcDetailBtn: document.getElementById('closeProcDetailModalBtn'),
  },
  onFiltersChange: (filters) => terminal.setContextParams(filters),
  getConnectionContext: () => {
    const computerName = els.serverInput.value.trim();
    if (!computerName) {
      els.serverInput.focus();
      return null;
    }
    const authMode = els.authModeSelect.value;
    if (authMode === 'CustomCredentials' && !state.sessionCredential) {
      openCredModal();
      return null;
    }
    saveRecentServer(computerName);
    return {
      computerName,
      protocol: els.protocolSelect.value,
      authMode,
      credential: state.sessionCredential,
    };
  },
});

const terminal = new TerminalController({
  dom: {
    panel: document.getElementById('terminalPanel'),
    hostBadge: document.getElementById('termHostBadge'),
    shellSelect: document.getElementById('termShellSelect'),
    timeoutSelect: document.getElementById('termTimeoutSelect'),
    copyBtn: document.getElementById('termCopyBtn'),
    downloadBtn: document.getElementById('termDownloadBtn'),
    clearBtn: document.getElementById('termClearBtn'),
    contextBar: document.getElementById('termContextBar'),
    catTabs: document.getElementById('termCatTabs'),
    cmdSearch: document.getElementById('termCmdSearch'),
    autoRunCheck: document.getElementById('termAutoRunCheck'),
    quickBar: document.getElementById('termQuickBar'),
    output: document.getElementById('termOutput'),
    form: document.getElementById('termForm'),
    promptLabel: document.getElementById('termPromptLabel'),
    input: document.getElementById('termInput'),
    runBtn: document.getElementById('termRunBtn'),
    stopBtn: document.getElementById('termStopBtn'),
  },
  getTargetServer: () => els.serverInput.value.trim(),
});

// ---- Theme & Recent Server History (non-sensitive only) ----
function loadTheme() {
  const saved = localStorage.getItem('wininspector_theme') || 'dark';
  document.documentElement.dataset.theme = saved;
}
els.themeToggleBtn.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('wininspector_theme', next);
});

els.logoutBtn?.addEventListener('click', async () => {
  els.logoutBtn.disabled = true;
  state.sessionCredential = null;
  try {
    await logoutSession();
  } catch {
    // Redirect even if network call fails
  }
  window.location.replace('/login');
});

function saveRecentServer(name) {
  const clean = name.trim();
  if (!clean) return;
  const list = JSON.parse(localStorage.getItem('wininspector_recent_servers') || '[]');
  const next = [clean, ...list.filter((x) => x.toLowerCase() !== clean.toLowerCase())].slice(0, 12);
  localStorage.setItem('wininspector_recent_servers', JSON.stringify(next));
  renderRecentServers(next);
}

function renderRecentServers(list) {
  els.recentServers.replaceChildren();
  for (const srv of list) {
    const opt = document.createElement('option');
    opt.value = srv;
    els.recentServers.appendChild(opt);
  }
}

// ---- Credentials Modal ----
function updateCredButtonVisibility() {
  const isCustom = els.authModeSelect.value === 'CustomCredentials';
  els.credBtn.classList.toggle('hidden', !isCustom);
  if (isCustom) {
    els.credBtn.textContent = state.sessionCredential
      ? `Creds: ${state.sessionCredential.username}`
      : 'Enter Credentials…';
  }
}

els.authModeSelect.addEventListener('change', () => {
  updateCredButtonVisibility();
  if (els.authModeSelect.value === 'CustomCredentials' && !state.sessionCredential) {
    openCredModal();
  }
});

function openCredModal() {
  els.credUsername.value = state.sessionCredential?.username || '';
  els.credPassword.value = '';
  els.credModalBackdrop.classList.remove('hidden');
  els.credUsername.focus();
}

function closeCredModal() {
  els.credModalBackdrop.classList.add('hidden');
}

els.credBtn.addEventListener('click', openCredModal);
els.closeCredModalBtn.addEventListener('click', closeCredModal);
els.clearCredBtn.addEventListener('click', () => {
  state.sessionCredential = null;
  els.credUsername.value = '';
  els.credPassword.value = '';
  updateCredButtonVisibility();
  closeCredModal();
});

els.credModalForm.addEventListener('submit', (e) => {
  e.preventDefault();
  state.sessionCredential = {
    username: els.credUsername.value.trim(),
    password: els.credPassword.value,
  };
  els.credPassword.value = '';
  updateCredButtonVisibility();
  closeCredModal();
});

// ---- Alerts & Metrics Helpers ----
function renderAlerts(items) {
  els.alertsContainer.replaceChildren();
  if (!items || items.length === 0) {
    els.alertsContainer.classList.add('hidden');
    return;
  }
  els.alertsContainer.classList.remove('hidden');
  for (const item of items) {
    const div = document.createElement('div');
    div.className = `alert alert-${item.level || 'info'}`;
    div.textContent = item.text;
    els.alertsContainer.appendChild(div);
  }
}

function renderMetrics(metrics) {
  els.metricsStrip.replaceChildren();
  if (!metrics || metrics.length === 0) {
    els.metricsStrip.classList.add('hidden');
    return;
  }
  els.metricsStrip.classList.remove('hidden');
  for (const m of metrics) {
    const card = document.createElement('div');
    card.className = `metric-card ${m.severity || 'info'}`;

    const lbl = document.createElement('div');
    lbl.className = 'metric-label';
    lbl.textContent = m.label || m.key;

    const valWrap = document.createElement('div');
    valWrap.className = 'metric-value';
    valWrap.textContent = String(m.value ?? '');

    if (m.unit) {
      const unit = document.createElement('span');
      unit.className = 'metric-unit';
      unit.textContent = m.unit;
      valWrap.appendChild(unit);
    }

    card.append(lbl, valWrap);
    els.metricsStrip.appendChild(card);
  }
}

// ---- Connection Test ----
function renderConnectionRibbon(res) {
  els.connRibbon.replaceChildren();
  els.connRibbon.classList.remove('hidden', 'ok', 'warn', 'err');

  const statusClass = res.authSuccess ? 'ok' : res.reachable ? 'warn' : 'err';
  els.connRibbon.classList.add(statusClass);

  const left = document.createElement('div');
  if (res.authSuccess) {
    const osText = res.osInfo?.caption ? `${res.osInfo.caption} | Uptime: ${res.osInfo.uptimeHours}h` : 'Connected';
    left.textContent = `Connected to ${res.resolvedFqdn || res.targetServer} (${res.protocolUsed}) — ${osText} — as ${res.executedAs} (${res.durationMs}ms)`;
  } else {
    left.textContent = `Target ${res.targetServer}: ${res.error || 'Unreachable or authentication failed.'}`;
  }

  const pills = document.createElement('div');
  pills.className = 'proto-pill-group';
  const pMap = res.protocols || {};
  const badgeDefs = [
    ['DNS', res.dnsResolved],
    ['WinRM HTTPS (5986)', pMap.winrmHttps],
    ['WinRM HTTP (5985)', pMap.winrmHttp],
    ['RPC/DCOM (135)', pMap.rpcDcom],
    ['SMB (445)', pMap.smb],
  ];
  for (const [label, ok] of badgeDefs) {
    const span = document.createElement('span');
    span.className = `pill ${ok ? 'pill-ok' : 'pill-off'}`;
    span.textContent = `${ok ? '✓' : '✕'} ${label}`;
    pills.appendChild(span);
  }

  els.connRibbon.append(left, pills);
}

els.connectionForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const computerName = els.serverInput.value.trim();
  const authMode = els.authModeSelect.value;
  if (!computerName) return;

  if (authMode === 'CustomCredentials' && !state.sessionCredential) {
    openCredModal();
    return;
  }

  saveRecentServer(computerName);
  els.testConnBtn.disabled = true;
  els.testConnBtn.textContent = 'Testing…';

  try {
    const res = await testServerConnection({
      computerName,
      protocol: els.protocolSelect.value,
      authMode,
      credential: state.sessionCredential,
    });
    renderConnectionRibbon(res);
  } catch (err) {
    renderConnectionRibbon({ reachable: false, authSuccess: false, targetServer: computerName, error: err.message });
  } finally {
    els.testConnBtn.disabled = false;
    els.testConnBtn.textContent = 'Test Connection';
  }
});

// ---- Category Selection ----
function selectSubCategory(cat, sub) {
  state.selectedCategory = cat;
  state.selectedSub = sub;
  state.expandedCategories.add(cat.id);

  els.selectedTitle.textContent = `${cat.number}. ${cat.name} — ${sub.name}`;
  els.selectedDescription.textContent = sub.description || '';

  els.selectedProtocols.replaceChildren();
  for (const p of sub.protocols || []) {
    const pill = document.createElement('span');
    pill.className = 'pill pill-info';
    pill.textContent = p;
    els.selectedProtocols.appendChild(pill);
  }
  if (!sub.implemented) {
    const pill = document.createElement('span');
    pill.className = 'pill pill-warn';
    pill.textContent = 'Planned (Phase 2)';
    els.selectedProtocols.appendChild(pill);
  }

  if (sub.id === '23.1-local-terminal') {
    els.paramsForm.classList.add('hidden');
    els.welcomeState.classList.add('hidden');
    els.resultsPanel.classList.add('hidden');
    els.metricsStrip.classList.add('hidden');
    els.alertsContainer.classList.add('hidden');
    perfMonitor.hide();
    els.rdpSessionsPanel.classList.add('hidden');
    terminal.show();
  } else {
    terminal.hide();
    renderParametersForm({
      formEl: els.paramsForm,
      gridEl: els.paramsGrid,
      presetsEl: els.quickTimePresets,
      subCategory: sub,
    });

    if (sub.id === '20.1-performance-snapshot') {
      els.welcomeState.classList.add('hidden');
      perfMonitor.show();
      terminal.setContextParams(perfMonitor.getFilters());
      terminal.show({ focus: false });
    } else {
      perfMonitor.hide();
    }

    if (sub.id === '11.1-rdp' || sub.id === '11.3-rdp-sessions') {
      els.welcomeState.classList.add('hidden');
      els.rdpSessionsPanel.classList.remove('hidden');
    } else {
      els.rdpSessionsPanel.classList.add('hidden');
    }
  }

  redrawSidebar();
}

function redrawSidebar() {
  renderSidebar({
    container: els.categoryTree,
    catalog: state.catalog,
    selectedId: state.selectedSub?.id,
    expandedCategories: state.expandedCategories,
    searchText: els.categorySearch.value,
    onlyImplemented: els.onlyImplementedToggle.checked,
    onSelect: selectSubCategory,
  });
}

els.categorySearch.addEventListener('input', redrawSidebar);
els.onlyImplementedToggle.addEventListener('change', redrawSidebar);

// ---- Run Diagnostic Analysis ----
els.paramsForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.selectedSub || !state.selectedSub.implemented) return;

  const computerName = els.serverInput.value.trim();
  if (!computerName) {
    els.serverInput.focus();
    return;
  }

  const authMode = els.authModeSelect.value;
  if (authMode === 'CustomCredentials' && !state.sessionCredential) {
    openCredModal();
    return;
  }

  saveRecentServer(computerName);
  const parameters = collectParameterValues(els.paramsGrid);

  if (state.activeController) state.activeController.abort();
  state.activeController = new AbortController();

  els.runAnalysisBtn.disabled = true;
  els.runAnalysisBtn.textContent = 'Running…';
  els.cancelRunBtn.classList.remove('hidden');
  renderAlerts([{ level: 'info', text: `Running "${state.selectedSub.name}" against ${computerName}…` }]);

  try {
    const response = await runDiagnostic({
      computerName,
      scriptId: state.selectedSub.id,
      protocol: els.protocolSelect.value,
      authMode,
      credential: state.sessionCredential,
      parameters,
      signal: state.activeController.signal,
    });

    state.lastResponse = response;
    els.welcomeState.classList.add('hidden');

    const alerts = [];
    const meta = response.meta || {};
    alerts.push({
      level: meta.status === 'Error' ? 'err' : 'info',
      text: `Completed on ${meta.targetServer} via ${meta.protocolUsed} in ${meta.durationMs}ms | Executed as ${meta.executedAs} | ${meta.totalRows} row(s)`,
    });
    for (const w of meta.warnings || []) alerts.push({ level: 'warn', text: `Warning: ${w}` });
    for (const er of meta.errors || []) alerts.push({ level: 'err', text: `Error: ${er}` });
    renderAlerts(alerts);

    renderMetrics(response.metrics || []);

    if ((response.schema || []).length > 0) {
      els.resultsPanel.classList.remove('hidden');
      dataTable.setData({ schema: response.schema, rows: response.data || [] });
    } else {
      els.resultsPanel.classList.add('hidden');
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      renderAlerts([{ level: 'warn', text: 'Diagnostic execution cancelled by user.' }]);
    } else {
      renderAlerts([{ level: 'err', text: `Execution failed: ${err.message}` }]);
    }
  } finally {
    els.runAnalysisBtn.disabled = false;
    els.runAnalysisBtn.textContent = 'Run Analysis';
    els.cancelRunBtn.classList.add('hidden');
    state.activeController = null;
  }
});

els.cancelRunBtn.addEventListener('click', () => {
  if (state.activeController) state.activeController.abort();
});

// ---- RDP qwinsta / rwinsta Interactive Panel ----
async function refreshQwinstaSessions() {
  const computerName = els.serverInput.value.trim();
  if (!computerName) {
    els.serverInput.focus();
    return;
  }
  const authMode = els.authModeSelect.value;
  if (authMode === 'CustomCredentials' && !state.sessionCredential) {
    openCredModal();
    return;
  }

  saveRecentServer(computerName);
  els.queryQwinstaBtn.disabled = true;
  els.queryQwinstaBtn.textContent = 'Querying…';
  els.rdpSessionsStatus.textContent = `Running qwinsta on ${computerName}…`;

  try {
    const res = await runDiagnostic({
      computerName,
      scriptId: '11.3-rdp-sessions',
      protocol: els.protocolSelect.value,
      authMode,
      credential: state.sessionCredential,
      parameters: {},
    });

    const rows = res.data || [];
    const warns = (res.meta?.warnings || []).join(' | ');
    const errs = (res.meta?.errors || []).join(' | ');
    if (errs) {
      els.rdpSessionsStatus.textContent = `Error: ${errs}`;
    } else if (warns) {
      els.rdpSessionsStatus.textContent = `${rows.length} session(s) via ${res.meta?.protocolUsed} — Note: ${warns}`;
    } else {
      els.rdpSessionsStatus.textContent = `${rows.length} session(s) found on ${computerName} via ${res.meta?.protocolUsed} (${res.meta?.durationMs}ms).`;
    }

    els.rdpSessionsTbody.replaceChildren();
    for (const s of rows) {
      const tr = document.createElement('tr');
      const cells = [
        String(s.SessionId ?? ''),
        `${s.IsCurrent ? '> ' : ''}${s.SessionName || ''}`,
        s.UserName || '(none)',
        s.State || '',
        s.Type || '',
        s.Device || '',
      ];
      for (const val of cells) {
        const td = document.createElement('td');
        td.textContent = val;
        tr.appendChild(td);
      }

      const actionTd = document.createElement('td');
      if (s.CanReset) {
        const targetId = String(s.SessionId);
        const logonId = s.LogonId ? String(s.LogonId) : '';
        const who = s.UserName || s.SessionName || targetId;
        const selfWarn = s.IsCurrent ? '\n\nWARNING: This appears to be your current local desktop session!' : '';

        const btnWrap = document.createElement('div');
        btnWrap.style.display = 'flex';
        btnWrap.style.gap = '6px';

        const makeActionBtn = (label, methodChoice, btnClass) => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = `btn ${btnClass} btn-sm`;
          btn.textContent = label;
          btn.addEventListener('click', async () => {
            if (!window.confirm(`Kill / disconnect session ID ${targetId} (${who}) on ${computerName} using ${methodChoice}?${selfWarn}`)) {
              return;
            }
            btn.disabled = true;
            btn.textContent = 'Killing…';
            try {
              const resetRes = await resetTerminalSession({
                computerName,
                sessionTarget: targetId,
                logonId,
                method: methodChoice,
                protocol: els.protocolSelect.value,
                authMode,
                credential: state.sessionCredential,
              });
              els.rdpSessionsStatus.textContent = `${resetRes.command}: ${resetRes.output}`;
              await refreshQwinstaSessions();
            } catch (resetErr) {
              els.rdpSessionsStatus.textContent = `${methodChoice} error: ${resetErr.message}`;
              btn.disabled = false;
              btn.textContent = label;
            }
          });
          return btn;
        };

        if (s.ResetMethod !== 'WMI') {
          btnWrap.appendChild(makeActionBtn('Disconnect (rwinsta)', 'rwinsta', 'btn-danger'));
        }
        btnWrap.appendChild(makeActionBtn('Kill Session (WMI)', 'WMI', s.ResetMethod === 'WMI' ? 'btn-danger' : 'btn-secondary'));
        actionTd.appendChild(btnWrap);
      } else {
        const span = document.createElement('span');
        span.className = 'muted small';
        span.textContent = 'System / N/A';
        actionTd.appendChild(span);
      }
      tr.appendChild(actionTd);
      els.rdpSessionsTbody.appendChild(tr);
    }
  } catch (err) {
    els.rdpSessionsStatus.textContent = `Session query failed: ${err.message}`;
  } finally {
    els.queryQwinstaBtn.disabled = false;
    els.queryQwinstaBtn.textContent = 'Query Active Sessions';
  }
}

els.queryQwinstaBtn.addEventListener('click', refreshQwinstaSessions);

// ---- CSV Export ----
els.exportFilteredBtn.addEventListener('click', () => {
  if (!state.lastResponse) return;
  exportRowsToCsv({
    schema: dataTable.getVisibleSchema(),
    rows: dataTable.filteredRows,
    serverName: state.lastResponse.meta?.targetServer,
    scriptId: state.lastResponse.meta?.scriptId,
    suffix: 'filtered',
  });
});

els.exportAllBtn.addEventListener('click', () => {
  if (!state.lastResponse) return;
  exportRowsToCsv({
    schema: state.lastResponse.schema || [],
    rows: state.lastResponse.data || [],
    serverName: state.lastResponse.meta?.targetServer,
    scriptId: state.lastResponse.meta?.scriptId,
    suffix: 'all',
  });
});

// ---- Bootstrap ----
async function init() {
  loadTheme();
  renderRecentServers(JSON.parse(localStorage.getItem('wininspector_recent_servers') || '["localhost"]'));
  updateCredButtonVisibility();

  try {
    const [health, catalog] = await Promise.all([fetchHealth(), fetchCatalog()]);
    const isPassthrough = health.sessionAuthMode === 'LocalPassthrough';
    if (isPassthrough) {
      const opt = document.createElement('option');
      opt.value = 'LocalPassthrough';
      opt.textContent = `Local Passthrough (${health.processIdentity})`;
      els.authModeSelect.insertBefore(opt, els.authModeSelect.firstChild);
      els.authModeSelect.value = 'LocalPassthrough';
      updateCredButtonVisibility();
    }
    const modeLabel = isPassthrough ? 'Local Passthrough' : 'UPN Session';
    els.serverIdentityLabel.textContent = `Host: ${health.serverHost} | Auth: ${health.authenticatedAs} (${modeLabel}) | Proc: ${health.processIdentity} | PS ${health.psVersion} / Pode ${health.podeVersion}${health.devMode ? ' (DevMode)' : ''}`;
    terminal.setHostContext({ serverHost: health.serverHost, processIdentity: health.processIdentity });
    state.catalog = catalog;
    redrawSidebar();
  } catch (err) {
    els.serverIdentityLabel.textContent = 'Backend unreachable';
    renderAlerts([{ level: 'err', text: `Failed to initialize WinInspector backend: ${err.message}` }]);
  }
}

init();
