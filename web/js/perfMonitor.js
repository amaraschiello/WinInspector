/**
 * Interactive SQLite-Backed Live Performance, GPU & Network Monitor
 * - Configurable 1s / 3s / 5s / 10s / 15s update interval
 * - Start / Stop monitoring persisted in SQLite (data/wininspector.db)
 * - Zero-CDN HTML5 Canvas time-series & breakdown charts
 * - Multi-facet filtering by Client IP, Protocol, Service, Process, and SMB/Pipe Resource
 */
import {
  startPerfSession,
  collectPerfSample,
  stopPerfSession,
  fetchPerfSessions,
  fetchPerfHistory,
  fetchProcessDetails,
  killTargetProcess,
} from './api.js';
import { exportRowsToCsv } from './csvExport.js';

function getThemeColors() {
  const isLight = document.documentElement.dataset.theme === 'light';
  return {
    text: isLight ? '#0f172a' : '#e2e8f0',
    muted: isLight ? '#64748b' : '#94a3b8',
    grid: isLight ? '#e2e8f0' : '#293548',
    bg: isLight ? '#ffffff' : '#0f172a',
  };
}

function formatShortTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function drawLineChart(canvas, seriesList, labels, { yMaxFixed = null, unit = '' } = {}) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(300, Math.floor(rect.width || canvas.width || 420));
  const height = Math.floor(rect.height || 180);
  canvas.width = width * dpr;
  canvas.height = height * dpr;

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const colors = getThemeColors();

  ctx.clearRect(0, 0, width, height);

  const pad = { top: 24, right: 14, bottom: 26, left: 46 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  // Legend at top
  let lx = pad.left;
  ctx.font = '600 11px "Segoe UI", sans-serif';
  for (const s of seriesList) {
    ctx.fillStyle = s.color;
    ctx.fillRect(lx, 7, 10, 8);
    ctx.fillStyle = colors.text;
    const latest = s.values.length ? s.values[s.values.length - 1] : 0;
    const lbl = `${s.label}: ${latest}${unit}`;
    ctx.fillText(lbl, lx + 14, 15);
    lx += ctx.measureText(lbl).width + 26;
  }

  // Y scale
  let maxVal = yMaxFixed || 0;
  if (!yMaxFixed) {
    for (const s of seriesList) {
      for (const v of s.values) {
        if (v > maxVal) maxVal = v;
      }
    }
    maxVal = maxVal <= 0 ? 10 : Math.ceil(maxVal * 1.18);
  }

  // Grid & Y labels
  ctx.strokeStyle = colors.grid;
  ctx.lineWidth = 1;
  ctx.font = '10px Consolas, monospace';
  ctx.fillStyle = colors.muted;
  const ticks = 4;
  for (let i = 0; i <= ticks; i++) {
    const y = pad.top + (plotH * i) / ticks;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    const val = ((maxVal * (ticks - i)) / ticks);
    const txt = val >= 100 ? Math.round(val) : val.toFixed(1).replace(/\.0$/, '');
    ctx.fillText(`${txt}${unit}`, 4, y + 3);
  }

  const count = labels.length;
  if (count === 0) {
    ctx.fillStyle = colors.muted;
    ctx.font = '12px "Segoe UI", sans-serif';
    ctx.fillText('Waiting for samples… Click Start Monitoring.', pad.left + 12, pad.top + plotH / 2);
    return;
  }

  // X axis labels (first, middle, last)
  ctx.fillStyle = colors.muted;
  ctx.font = '10px Consolas, monospace';
  const xIndices = count === 1 ? [0] : count === 2 ? [0, 1] : [0, Math.floor((count - 1) / 2), count - 1];
  for (const idx of xIndices) {
    const x = count === 1 ? pad.left + plotW / 2 : pad.left + (idx / (count - 1)) * plotW;
    const lbl = labels[idx] || '';
    const tw = ctx.measureText(lbl).width;
    ctx.fillText(lbl, Math.min(width - pad.right - tw, Math.max(pad.left, x - tw / 2)), height - 7);
  }

  // Plot lines
  for (const s of seriesList) {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = count === 1 ? pad.left + plotW / 2 : pad.left + (i / (count - 1)) * plotW;
      const clamped = Math.max(0, Math.min(maxVal, Number(v) || 0));
      const y = pad.top + plotH - (clamped / maxVal) * plotH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Draw dots on sparse series or latest point
    ctx.fillStyle = s.color;
    s.values.forEach((v, i) => {
      if (count <= 20 || i === count - 1) {
        const x = count === 1 ? pad.left + plotW / 2 : pad.left + (i / (count - 1)) * plotW;
        const clamped = Math.max(0, Math.min(maxVal, Number(v) || 0));
        const y = pad.top + plotH - (clamped / maxVal) * plotH;
        ctx.beginPath();
        ctx.arc(x, y, 2.8, 0, Math.PI * 2);
        ctx.fill();
      }
    });
  }
}

function drawBreakdownChart(canvas, items) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(300, Math.floor(rect.width || canvas.width || 420));
  const height = Math.floor(rect.height || 180);
  canvas.width = width * dpr;
  canvas.height = height * dpr;

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const colors = getThemeColors();
  ctx.clearRect(0, 0, width, height);

  ctx.font = '600 11px "Segoe UI", sans-serif';
  ctx.fillStyle = colors.text;
  ctx.fillText('Connections / SMB / Pipes by Service & Protocol', 10, 15);

  const topItems = (items || []).slice(0, 7);
  if (topItems.length === 0) {
    ctx.fillStyle = colors.muted;
    ctx.font = '12px "Segoe UI", sans-serif';
    ctx.fillText('No matching network/service connections.', 14, height / 2);
    return;
  }

  const maxCnt = Math.max(...topItems.map((x) => Number(x.cnt) || 0), 1);
  const labelW = 155;
  const barMaxW = Math.max(60, width - labelW - 55);
  const rowH = Math.floor((height - 28) / topItems.length);

  topItems.forEach((item, idx) => {
    const y = 26 + idx * rowH;
    const label = `${item.service_name} (${item.protocol})`;
    ctx.fillStyle = colors.text;
    ctx.font = '11px "Segoe UI", sans-serif';
    const shortLbl = label.length > 23 ? label.slice(0, 21) + '…' : label;
    ctx.fillText(shortLbl, 10, y + 12);

    const w = Math.max(4, Math.round(((Number(item.cnt) || 0) / maxCnt) * barMaxW));
    const barColor =
      item.protocol === 'SMB'
        ? '#f59e0b'
        : item.protocol === 'NamedPipe'
        ? '#a855f7'
        : item.protocol === 'UDP'
        ? '#10b981'
        : '#3b82f6';
    ctx.fillStyle = barColor;
    ctx.fillRect(labelW, y + 2, w, Math.min(14, rowH - 5));

    ctx.fillStyle = colors.muted;
    ctx.font = '11px Consolas, monospace';
    ctx.fillText(String(item.cnt), labelW + w + 6, y + 12);
  });
}

export class PerfMonitorController {
  constructor({ dom, getConnectionContext, onFiltersChange = null }) {
    this.dom = dom;
    this.getConnectionContext = getConnectionContext;
    this.onFiltersChange = onFiltersChange;
    this.running = false;
    this.timerId = null;
    this.abortController = null;
    this.sessionId = null;
    this.sampleCount = 0;
    this.activeTab = 'processes';
    this.lastHistory = null;
    this.sortState = { key: null, dir: 'desc' };
    this.selectedRowKey = null;
    this.inspectedProc = null;
    this.detailTimerId = null;

    this._bindEvents();
  }

  _bindEvents() {
    this.dom.startBtn.addEventListener('click', () => this.start());
    this.dom.stopBtn.addEventListener('click', () => this.stop());
    this.dom.refreshSessionsBtn.addEventListener('click', () => this.loadSessionsList());
    this.dom.sessionSelect.addEventListener('change', () => {
      const sid = this.dom.sessionSelect.value;
      if (sid && !this.running) {
        this.sessionId = sid;
        this.refreshHistory();
      }
    });

    this.dom.applyFilterBtn.addEventListener('click', () => {
      this._notifyFilters();
      this.refreshHistory();
    });
    this.dom.clearFilterBtn.addEventListener('click', () => {
      this.dom.filterClientIp.value = '';
      this.dom.filterProtocol.value = '';
      this.dom.filterService.value = '';
      this.dom.filterProcess.value = '';
      if (this.dom.filterLocalPort) this.dom.filterLocalPort.value = '';
      if (this.dom.filterRemotePort) this.dom.filterRemotePort.value = '';
      this.dom.filterSearch.value = '';
      this._notifyFilters();
      this.refreshHistory();
    });

    for (const inputEl of [
      this.dom.filterClientIp,
      this.dom.filterProcess,
      this.dom.filterLocalPort,
      this.dom.filterRemotePort,
      this.dom.filterSearch,
    ]) {
      inputEl?.addEventListener('input', () => this._notifyFilters());
      inputEl?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this._notifyFilters();
          this.refreshHistory();
        }
      });
    }

    for (const tabBtn of this.dom.tabButtons) {
      tabBtn.addEventListener('click', () => {
        this.activeTab = tabBtn.dataset.perfTab;
        this.sortState = { key: null, dir: 'desc' };
        for (const b of this.dom.tabButtons) b.classList.toggle('active', b === tabBtn);
        this.renderActiveTabTable();
      });
    }

    this.dom.closeProcDetailBtn?.addEventListener('click', () => this.closeProcessDetail());
    this.dom.procDetailBackdrop?.addEventListener('click', (e) => {
      if (e.target === this.dom.procDetailBackdrop) this.closeProcessDetail();
    });
    this.dom.procDetailRefreshBtn?.addEventListener('click', () => this.refreshProcessDetail());
    this.dom.procDetailAutoRefresh?.addEventListener('change', () => {
      this._syncDetailAutoRefresh();
    });
    this.dom.procDetailKillBtn?.addEventListener('click', async () => {
      if (!this.inspectedProc || !this.inspectedProc.pid) return;
      await this.confirmAndKillProcess(this.inspectedProc.pid, this.inspectedProc.processName);
    });

    this.dom.exportTabCsvBtn.addEventListener('click', () => this.exportCurrentTabCsv());

    window.addEventListener('resize', () => {
      if (this.lastHistory && !this.dom.panel.classList.contains('hidden')) {
        this.renderCharts(this.lastHistory);
      }
    });
  }

  async show() {
    this.dom.panel.classList.remove('hidden');
    await this.loadSessionsList();
    if (this.lastHistory) {
      this.renderCharts(this.lastHistory);
    }
  }

  hide() {
    this.dom.panel.classList.add('hidden');
  }

  getFilters() {
    return {
      clientIp: this.dom.filterClientIp.value.trim(),
      protocol: this.dom.filterProtocol.value,
      serviceName: this.dom.filterService.value,
      processName: this.dom.filterProcess.value.trim(),
      localPort: this.dom.filterLocalPort ? this.dom.filterLocalPort.value.trim() : '',
      remotePort: this.dom.filterRemotePort ? this.dom.filterRemotePort.value.trim() : '',
      search: this.dom.filterSearch.value.trim(),
    };
  }

  _getFilterInputForKey(filterKey) {
    switch (filterKey) {
      case 'clientIp': return this.dom.filterClientIp;
      case 'processName': return this.dom.filterProcess;
      case 'localPort': return this.dom.filterLocalPort;
      case 'remotePort': return this.dom.filterRemotePort;
      default: return null;
    }
  }

  _notifyFilters() {
    if (typeof this.onFiltersChange === 'function') {
      this.onFiltersChange(this.getFilters());
    }
  }

  toggleCellFilter(filterKey, value) {
    const inputEl = this._getFilterInputForKey(filterKey);
    if (!inputEl) return;
    const strVal = String(value ?? '').trim();
    if (!strVal) return;

    const current = inputEl.value.trim();
    inputEl.value = current.toLowerCase() === strVal.toLowerCase() ? '' : strVal;
    this._notifyFilters();
    this.refreshHistory();
  }

  async loadSessionsList() {
    try {
      const res = await fetchPerfSessions();
      const sessions = res.sessions || [];
      this.dom.sessionSelect.replaceChildren();
      const def = document.createElement('option');
      def.value = '';
      def.textContent = sessions.length ? 'Select saved DB session…' : 'No saved sessions yet';
      this.dom.sessionSelect.appendChild(def);

      for (const s of sessions) {
        const opt = document.createElement('option');
        opt.value = s.session_id;
        const when = new Date(s.started_utc).toLocaleString();
        opt.textContent = `${s.server_name} | ${when} (${s.sample_count} samples, ${s.interval_sec}s, ${s.status})`;
        if (s.session_id === this.sessionId) opt.selected = true;
        this.dom.sessionSelect.appendChild(opt);
      }
    } catch {
      // Ignore if backend not ready
    }
  }

  async start() {
    if (this.running) return;
    const ctx = this.getConnectionContext();
    if (!ctx) return;

    const intervalSec = Number(this.dom.intervalSelect.value || 5);
    const topProcesses = Number(document.getElementById('param_TopProcesses')?.value || 15);

    this.dom.startBtn.disabled = true;
    this.dom.statusBadge.textContent = 'Starting SQLite session…';

    try {
      const session = await startPerfSession({
        computerName: ctx.computerName,
        intervalSec,
        protocol: ctx.protocol,
      });

      this.sessionId = session.sessionId;
      this.sampleCount = 0;
      this.running = true;
      this.dom.startBtn.classList.add('hidden');
      this.dom.stopBtn.classList.remove('hidden');
      this.dom.intervalSelect.disabled = true;
      this.dom.statusBadge.className = 'pill pill-ok';
      this.dom.statusBadge.textContent = `Monitoring ${ctx.computerName} every ${intervalSec}s…`;

      await this.loadSessionsList();
      this._scheduleNextSample(0, intervalSec, topProcesses);
    } catch (err) {
      this.dom.startBtn.disabled = false;
      this.dom.statusBadge.className = 'pill pill-warn';
      this.dom.statusBadge.textContent = `Failed to start: ${err.message}`;
    }
  }

  _scheduleNextSample(delayMs, intervalSec, topProcesses) {
    if (!this.running) return;
    this.timerId = setTimeout(async () => {
      if (!this.running) return;
      const started = performance.now();
      const ctx = this.getConnectionContext();
      if (!ctx) {
        await this.stop();
        return;
      }

      this.abortController = new AbortController();
      try {
        const hist = await collectPerfSample({
          sessionId: this.sessionId,
          computerName: ctx.computerName,
          protocol: ctx.protocol,
          authMode: ctx.authMode,
          credential: ctx.credential,
          topProcesses,
          filters: this.getFilters(),
          signal: this.abortController.signal,
        });

        this.sampleCount = (hist.timeline || []).length;
        this.lastHistory = hist;
        this.dom.statusBadge.className = 'pill pill-ok';
        const asText = hist.executedAs ? ` • as ${hist.executedAs}` : '';
        this.dom.statusBadge.textContent = `Live: ${ctx.computerName} (${intervalSec}s) • ${this.sampleCount} samples in DB (${hist.lastSampleDurationMs || 0}ms)${asText}`;
        this.renderAll(hist);
      } catch (err) {
        if (err.name !== 'AbortError') {
          this.dom.statusBadge.className = 'pill pill-warn';
          this.dom.statusBadge.textContent = `Sample warning: ${err.message}`;
        }
      } finally {
        this.abortController = null;
      }

      if (this.running) {
        const elapsed = performance.now() - started;
        const waitMs = Math.max(200, intervalSec * 1000 - elapsed);
        this._scheduleNextSample(waitMs, intervalSec, topProcesses);
      }
    }, delayMs);
  }

  async stop() {
    this.running = false;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }

    this.dom.stopBtn.classList.add('hidden');
    this.dom.startBtn.classList.remove('hidden');
    this.dom.startBtn.disabled = false;
    this.dom.intervalSelect.disabled = false;

    if (this.sessionId) {
      try {
        await stopPerfSession({ sessionId: this.sessionId });
        this.dom.statusBadge.className = 'pill pill-info';
        this.dom.statusBadge.textContent = `Stopped • ${this.sampleCount} samples saved in SQLite`;
        await this.loadSessionsList();
      } catch {
        // Ignore stop error
      }
    }
  }

  async refreshHistory() {
    if (!this.sessionId) return;
    try {
      const hist = await fetchPerfHistory({
        sessionId: this.sessionId,
        filters: this.getFilters(),
      });
      this.lastHistory = hist;
      this.sampleCount = (hist.timeline || []).length;
      if (!this.running && hist.session) {
        this.dom.statusBadge.className = 'pill pill-info';
        this.dom.statusBadge.textContent = `DB Session: ${hist.session.server_name} • ${this.sampleCount} samples (${hist.session.status})`;
      }
      this.renderAll(hist);
    } catch (err) {
      this.dom.statusBadge.className = 'pill pill-warn';
      this.dom.statusBadge.textContent = `History query failed: ${err.message}`;
    }
  }

  renderAll(hist) {
    this._populateServiceDropdown(hist.networkDetails || []);
    this.renderCharts(hist);
    this.renderActiveTabTable();
  }

  _populateServiceDropdown(netDetails) {
    const current = this.dom.filterService.value;
    const services = Array.from(new Set(netDetails.map((r) => r.service_name).filter(Boolean))).sort();
    if (services.length === 0) return;

    this.dom.filterService.replaceChildren();
    const allOpt = document.createElement('option');
    allOpt.value = '';
    allOpt.textContent = 'All Services';
    this.dom.filterService.appendChild(allOpt);

    for (const s of services) {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      if (s === current) opt.selected = true;
      this.dom.filterService.appendChild(opt);
    }
  }

  renderCharts(hist) {
    const tl = hist.timeline || [];
    const labels = tl.map((p) => formatShortTime(p.ts_utc));

    drawLineChart(
      this.dom.chartCompute,
      [
        { label: 'CPU', color: '#3b82f6', values: tl.map((p) => p.cpu_pct) },
        { label: 'RAM', color: '#10b981', values: tl.map((p) => p.mem_used_pct) },
        { label: 'GPU', color: '#f59e0b', values: tl.map((p) => p.gpu_util_pct) },
      ],
      labels,
      { yMaxFixed: 100, unit: '%' }
    );

    drawLineChart(
      this.dom.chartNetThroughput,
      [
        { label: 'Net Rx', color: '#38bdf8', values: tl.map((p) => p.net_rx_kbps) },
        { label: 'Net Tx', color: '#a855f7', values: tl.map((p) => p.net_tx_kbps) },
      ],
      labels,
      { unit: ' KB/s' }
    );

    drawLineChart(
      this.dom.chartNetErrors,
      [
        { label: 'Rx Errors', color: '#ef4444', values: tl.map((p) => p.net_rx_errors) },
        { label: 'Tx Errors', color: '#f97316', values: tl.map((p) => p.net_tx_errors) },
        { label: 'Discards', color: '#eab308', values: tl.map((p) => (p.net_rx_discards || 0) + (p.net_tx_discards || 0)) },
      ],
      labels,
      { unit: '' }
    );

    drawBreakdownChart(this.dom.chartBreakdown, hist.serviceBreakdown || []);
  }

  _getTabTableSpec() {
    const hist = this.lastHistory || {};
    if (this.activeTab === 'adapters') {
      return {
        cols: [
          { key: 'adapter_name', label: 'Adapter' },
          { key: 'link_speed', label: 'Link Speed' },
          { key: 'rx_kbps', label: 'Rx KB/s' },
          { key: 'tx_kbps', label: 'Tx KB/s' },
          { key: 'rx_errors', label: 'Receive Packet Errors', highlightIfPositive: true },
          { key: 'tx_errors', label: 'Outbound Packet Errors', highlightIfPositive: true },
          { key: 'rx_discards', label: 'Rx Discards', highlightIfPositive: true },
          { key: 'tx_discards', label: 'Tx Discards', highlightIfPositive: true },
        ],
        rows: hist.adapters || [],
      };
    }
    if (this.activeTab === 'connections') {
      return {
        cols: [
          { key: 'detail_type', label: 'Type' },
          { key: 'protocol', label: 'Protocol' },
          { key: 'service_name', label: 'Service' },
          { key: 'client_ip', label: 'Client / Local', filterKey: 'clientIp' },
          { key: 'local_port', label: 'Local Port', filterKey: 'localPort' },
          { key: 'remote_port', label: 'Remote Port', filterKey: 'remotePort' },
          { key: 'process_name', label: 'Process', filterKey: 'processName' },
          { key: 'state', label: 'State' },
          { key: 'resource_path', label: 'Endpoint' },
        ],
        rows: (hist.networkDetails || []).filter((r) => r.protocol === 'TCP' || r.protocol === 'UDP'),
      };
    }
    if (this.activeTab === 'smbpipes') {
      return {
        cols: [
          { key: 'detail_type', label: 'Type' },
          { key: 'protocol', label: 'Protocol' },
          { key: 'service_name', label: 'Service' },
          { key: 'client_ip', label: 'Client', filterKey: 'clientIp' },
          { key: 'user_name', label: 'User' },
          { key: 'process_name', label: 'Process', filterKey: 'processName' },
          { key: 'state', label: 'State / Locks' },
          { key: 'resource_path', label: 'SMB File / Pipe Path' },
        ],
        rows: (hist.networkDetails || []).filter((r) => r.protocol === 'SMB' || r.protocol === 'NamedPipe'),
      };
    }
    // Default: processes
    return {
      cols: [
        { key: 'proc_name', label: 'Process', filterKey: 'processName' },
        { key: 'pid', label: 'PID' },
        { key: 'cpu_pct', label: 'CPU %' },
        { key: 'cpu_sec', label: 'CPU Time (s)' },
        { key: 'mem_mb', label: 'RAM (MB)' },
        { key: 'gpu_pct', label: 'GPU %' },
        { key: 'gpu_mem_mb', label: 'GPU VRAM (MB)' },
        { key: 'handles', label: 'Handles' },
        { key: 'threads', label: 'Threads' },
      ],
      rows: hist.topProcesses || [],
    };
  }

  _sortRows(rows) {
    if (!this.sortState.key) return rows;
    const { key, dir } = this.sortState;
    const mult = dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = a?.[key];
      const vb = b?.[key];
      const na = typeof va === 'number' ? va : (va !== '' && va !== null && va !== undefined && !Number.isNaN(Number(va)) ? Number(va) : null);
      const nb = typeof vb === 'number' ? vb : (vb !== '' && vb !== null && vb !== undefined && !Number.isNaN(Number(vb)) ? Number(vb) : null);
      if (na !== null && nb !== null) {
        return (na - nb) * mult;
      }
      return String(va ?? '').localeCompare(String(vb ?? ''), undefined, { sensitivity: 'base' }) * mult;
    });
  }

  _toggleSort(colKey) {
    if (this.sortState.key === colKey) {
      this.sortState.dir = this.sortState.dir === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortState.key = colKey;
      this.sortState.dir = 'desc';
    }
    this.renderActiveTabTable();
  }

  _getRowIdentityKey(r) {
    if (this.activeTab === 'processes') return `proc:${r.pid}:${r.proc_name}`;
    if (this.activeTab === 'connections') return `conn:${r.client_ip}:${r.local_port}:${r.remote_port}:${r.process_name}`;
    if (this.activeTab === 'smbpipes') return `smb:${r.resource_path}:${r.client_ip}`;
    return `adp:${r.adapter_name}`;
  }

  async confirmAndKillProcess(pid, procName) {
    const pidNum = Number(pid || 0);
    if (!pidNum || pidNum <= 4) return;
    const ctx = this.getConnectionContext();
    if (!ctx) return;

    const label = procName ? `${procName} (PID ${pidNum})` : `PID ${pidNum}`;
    if (!window.confirm(`Kill process ${label} on ${ctx.computerName}?`)) return;

    try {
      const res = await killTargetProcess({
        computerName: ctx.computerName,
        protocol: ctx.protocol,
        authMode: ctx.authMode,
        credential: ctx.credential,
        processId: pidNum,
      });
      this.dom.statusBadge.className = 'pill pill-ok';
      this.dom.statusBadge.textContent = res.message || `Terminated ${label}`;
      if (this.inspectedProc && Number(this.inspectedProc.pid) === pidNum) {
        this.closeProcessDetail();
      }
      await this.refreshHistory();
    } catch (err) {
      window.alert(`Failed to kill ${label}: ${err.message}`);
    }
  }

  async openProcessDetail({ pid = 0, processName = '' }) {
    this.inspectedProc = { pid: Number(pid || 0), processName: String(processName || '') };
    this.dom.procDetailTitle.textContent = pid > 0
      ? `Process Deep Analysis — ${processName || 'Process'} (PID ${pid})`
      : `Process Deep Analysis — ${processName}`;
    this.dom.procDetailBody.replaceChildren();
    const loading = document.createElement('div');
    loading.className = 'muted';
    loading.textContent = 'Collecting live CPU, RAM, VRAM, Disk I/O, Network Sockets & Modules…';
    this.dom.procDetailBody.appendChild(loading);

    this.dom.procDetailBackdrop.classList.remove('hidden');
    await this.refreshProcessDetail();
    this._syncDetailAutoRefresh();
  }

  closeProcessDetail() {
    if (this.detailTimerId) {
      clearInterval(this.detailTimerId);
      this.detailTimerId = null;
    }
    if (this.dom.procDetailAutoRefresh) this.dom.procDetailAutoRefresh.checked = false;
    this.dom.procDetailBackdrop?.classList.add('hidden');
    this.inspectedProc = null;
  }

  _syncDetailAutoRefresh() {
    if (this.detailTimerId) {
      clearInterval(this.detailTimerId);
      this.detailTimerId = null;
    }
    if (this.dom.procDetailAutoRefresh?.checked && this.inspectedProc) {
      this.detailTimerId = setInterval(() => this.refreshProcessDetail(), 2000);
    }
  }

  async refreshProcessDetail() {
    if (!this.inspectedProc) return;
    const ctx = this.getConnectionContext();
    if (!ctx) return;

    try {
      const res = await fetchProcessDetails({
        computerName: ctx.computerName,
        protocol: ctx.protocol,
        authMode: ctx.authMode,
        credential: ctx.credential,
        processId: this.inspectedProc.pid,
        processName: this.inspectedProc.processName,
      });

      const d = res.details || {};
      this.inspectedProc.pid = Number(d.pid || this.inspectedProc.pid || 0);
      this.inspectedProc.processName = d.processName || this.inspectedProc.processName;
      this.dom.procDetailTitle.textContent = `Process Deep Analysis — ${d.processName || 'Process'} (PID ${d.pid || '?'}) on ${res.targetServer}`;
      if (this.dom.procDetailKillBtn) {
        this.dom.procDetailKillBtn.disabled = !d.pid || Number(d.pid) <= 4;
      }

      this._renderProcessDetailBody(d, res);
    } catch (err) {
      this.dom.procDetailBody.replaceChildren();
      const errDiv = document.createElement('div');
      errDiv.className = 'alert alert-err';
      errDiv.textContent = `Failed to inspect process: ${err.message}`;
      this.dom.procDetailBody.appendChild(errDiv);
    }
  }

  _renderProcessDetailBody(d, res) {
    const body = this.dom.procDetailBody;
    body.replaceChildren();

    const kpis = [
      ['CPU %', `${d.cpuPct ?? 0}%`],
      ['CPU Time', `${d.cpuSec ?? 0} s`],
      ['Working Set RAM', `${d.workingSetMB ?? 0} MB`],
      ['Private Bytes', `${d.privateMB ?? 0} MB`],
      ['Virtual Memory', `${d.virtualMB ?? 0} MB`],
      ['GPU Utilization', `${d.gpuPct ?? 0}%`],
      ['Dedicated VRAM', `${d.gpuDedicatedMB ?? 0} MB`],
      ['Shared VRAM', `${d.gpuSharedMB ?? 0} MB`],
      ['Disk Read/s', `${d.ioReadKBps ?? 0} KB/s (${d.ioReadOpsPerSec ?? 0} ops/s)`],
      ['Disk Write/s', `${d.ioWriteKBps ?? 0} KB/s (${d.ioWriteOpsPerSec ?? 0} ops/s)`],
      ['Total Disk R/W', `${d.totalReadMB ?? 0} / ${d.totalWriteMB ?? 0} MB`],
      ['Page Faults/s', `${d.pageFaultsPerSec ?? 0}`],
      ['Handles / Threads', `${d.handles ?? 0} / ${d.threads ?? 0}`],
      ['Loaded Modules', `${d.totalModules ?? 0}`],
    ];

    const grid = document.createElement('div');
    grid.className = 'proc-kpi-grid';
    for (const [lbl, val] of kpis) {
      const card = document.createElement('div');
      card.className = 'proc-kpi-card';
      const l = document.createElement('div');
      l.className = 'proc-kpi-label';
      l.textContent = lbl;
      const v = document.createElement('div');
      v.className = 'proc-kpi-val';
      v.textContent = val;
      card.append(l, v);
      grid.appendChild(card);
    }
    body.appendChild(grid);

    const meta = document.createElement('div');
    meta.className = 'proc-meta-grid';
    const metaRows = [
      ['Owner', d.owner || '(unknown)'],
      ['Parent PID', String(d.parentPid ?? '')],
      ['Priority', d.priorityClass || 'Normal'],
      ['Start Time (UTC)', d.startTimeUtc || ''],
      ['Paged / NonPaged Pool', `${d.pagedPoolKB ?? 0} KB / ${d.nonPagedPoolKB ?? 0} KB`],
      ['Executable Path', d.executablePath || '(protected / unavailable)'],
      ['Command Line', d.commandLine || '(unavailable)'],
      ['Collection Info', `${res.protocolUsed} • ${res.durationMs}ms • as ${res.executedAs}`],
    ];
    for (const [k, v] of metaRows) {
      const kEl = document.createElement('div');
      kEl.className = 'proc-meta-key';
      kEl.textContent = k;
      const vEl = document.createElement('div');
      vEl.className = 'proc-meta-val';
      vEl.textContent = v;
      meta.append(kEl, vEl);
    }
    body.appendChild(meta);

    // Active Network Sockets
    const sockTitle = document.createElement('h4');
    sockTitle.textContent = `Active Network Connections / Ports (${(d.sockets || []).length})`;
    sockTitle.style.margin = '4px 0 0';
    body.appendChild(sockTitle);

    if ((d.sockets || []).length > 0) {
      const wrap = document.createElement('div');
      wrap.className = 'table-wrapper';
      const tbl = document.createElement('table');
      tbl.className = 'data-table';
      const thead = document.createElement('thead');
      const trh = document.createElement('tr');
      for (const h of ['Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port', 'State']) {
        const th = document.createElement('th');
        th.textContent = h;
        trh.appendChild(th);
      }
      thead.appendChild(trh);
      const tbody = document.createElement('tbody');
      for (const s of d.sockets) {
        const tr = document.createElement('tr');
        for (const val of [s.Protocol, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort, s.State]) {
          const td = document.createElement('td');
          td.textContent = String(val ?? '');
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      }
      tbl.append(thead, tbody);
      wrap.appendChild(tbl);
      body.appendChild(wrap);
    } else {
      const noSock = document.createElement('div');
      noSock.className = 'muted small';
      noSock.textContent = 'No active TCP/UDP sockets owned by this PID.';
      body.appendChild(noSock);
    }

    // Top Loaded Modules
    if ((d.modules || []).length > 0) {
      const modTitle = document.createElement('h4');
      modTitle.textContent = `Loaded Modules (Showing top ${d.modules.length} of ${d.totalModules})`;
      modTitle.style.margin = '4px 0 0';
      body.appendChild(modTitle);

      const wrap = document.createElement('div');
      wrap.className = 'table-wrapper';
      const tbl = document.createElement('table');
      tbl.className = 'data-table';
      const thead = document.createElement('thead');
      const trh = document.createElement('tr');
      for (const h of ['Module', 'Size (KB)', 'Version', 'Path']) {
        const th = document.createElement('th');
        th.textContent = h;
        trh.appendChild(th);
      }
      thead.appendChild(trh);
      const tbody = document.createElement('tbody');
      for (const m of d.modules) {
        const tr = document.createElement('tr');
        for (const val of [m.Name, m.SizeKB, m.Version, m.Path]) {
          const td = document.createElement('td');
          td.textContent = String(val ?? '');
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      }
      tbl.append(thead, tbody);
      wrap.appendChild(tbl);
      body.appendChild(wrap);
    }
  }

  renderActiveTabTable() {
    const spec = this._getTabTableSpec();
    const sortedRows = this._sortRows(spec.rows);
    const hasActions = (this.activeTab === 'processes' || this.activeTab === 'connections' || this.activeTab === 'smbpipes');

    this.dom.tabHead.replaceChildren();
    this.dom.tabBody.replaceChildren();

    const trh = document.createElement('tr');
    for (const c of spec.cols) {
      const th = document.createElement('th');
      th.className = 'perf-sortable-th';
      const indicator = this.sortState.key === c.key ? (this.sortState.dir === 'asc' ? ' ▲' : ' ▼') : '';
      th.textContent = `${c.label}${indicator}`;
      th.title = `Click to sort by ${c.label}`;
      th.addEventListener('click', () => this._toggleSort(c.key));
      trh.appendChild(th);
    }
    if (hasActions) {
      const thAct = document.createElement('th');
      thAct.textContent = 'Actions';
      trh.appendChild(thAct);
    }
    this.dom.tabHead.appendChild(trh);

    const activeFilters = this.getFilters();
    const frag = document.createDocumentFragment();
    for (const r of sortedRows) {
      const tr = document.createElement('tr');
      const rowKey = this._getRowIdentityKey(r);
      if (this.selectedRowKey === rowKey) {
        tr.classList.add('perf-row-selected');
      }
      tr.addEventListener('click', () => {
        this.selectedRowKey = rowKey;
        for (const rowEl of this.dom.tabBody.querySelectorAll('tr')) {
          rowEl.classList.remove('perf-row-selected');
        }
        tr.classList.add('perf-row-selected');
      });

      for (const c of spec.cols) {
        const td = document.createElement('td');
        const val = r[c.key];
        const strVal = val === null || val === undefined ? '' : String(val);
        td.textContent = strVal;
        if (c.highlightIfPositive && Number(val) > 0) {
          td.className = 'cell-err-highlight';
        } else if (c.filterKey && strVal !== '' && !((c.filterKey === 'localPort' || c.filterKey === 'remotePort') && Number(val) <= 0)) {
          const isActive = (activeFilters[c.filterKey] || '').toLowerCase() === strVal.toLowerCase();
          td.className = isActive ? 'perf-click-filter active' : 'perf-click-filter';
          td.title = isActive
            ? `Filtered by ${c.label}: ${strVal} (click to remove filter)`
            : `Click to filter by ${c.label}: ${strVal}`;
          td.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCellFilter(c.filterKey, strVal);
          });
        }
        tr.appendChild(td);
      }

      if (hasActions) {
        const actTd = document.createElement('td');
        const wrap = document.createElement('div');
        wrap.className = 'perf-row-actions';

        const pidVal = Number(r.pid || 0);
        const procNameVal = String(r.proc_name || r.process_name || '');

        if (pidVal > 0 || procNameVal) {
          const analyzeBtn = document.createElement('button');
          analyzeBtn.type = 'button';
          analyzeBtn.className = 'btn btn-secondary btn-sm';
          analyzeBtn.textContent = 'Analyze in Detail';
          analyzeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.openProcessDetail({ pid: pidVal, processName: procNameVal });
          });
          wrap.appendChild(analyzeBtn);
        }

        if (this.activeTab === 'processes' && pidVal > 4) {
          const killBtn = document.createElement('button');
          killBtn.type = 'button';
          killBtn.className = 'btn btn-danger btn-sm';
          killBtn.textContent = 'Kill';
          killBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.confirmAndKillProcess(pidVal, procNameVal);
          });
          wrap.appendChild(killBtn);
        }

        actTd.appendChild(wrap);
        tr.appendChild(actTd);
      }

      frag.appendChild(tr);
    }
    this.dom.tabBody.appendChild(frag);
  }

  exportCurrentTabCsv() {
    if (!this.lastHistory) return;
    const spec = this._getTabTableSpec();
    exportRowsToCsv({
      schema: spec.cols,
      rows: spec.rows,
      serverName: this.lastHistory.session?.server_name || 'server',
      scriptId: `perf_${this.activeTab}`,
      suffix: 'db',
    });
  }
}
