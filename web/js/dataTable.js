/**
 * Dynamic Schema-Driven Table with Type-Aware Sorting, Multi-Facet Focus Filtering,
 * Time Window Narrowing, Column Picker, and Row Detail Drawer (100% XSS-safe).
 */

const SEVERITY_RANK = { critical: 4, error: 3, warning: 2, info: 1 };

function formatDateTime(val) {
  if (!val) return '';
  const d = new Date(val);
  if (Number.isNaN(d.getTime())) return String(val);
  return d.toLocaleString();
}

function ipToNumber(ip) {
  const parts = String(ip || '').split('.');
  if (parts.length !== 4) return -1;
  return parts.reduce((acc, oct) => (acc << 8) + (parseInt(oct, 10) || 0), 0) >>> 0;
}

export class DynamicDataTable {
  constructor(dom) {
    this.dom = dom;
    this.schema = [];
    this.allRows = [];
    this.filteredRows = [];
    this.visibleKeys = new Set();
    this.sortKey = null;
    this.sortDir = 'desc';
    this.globalQuery = '';
    this.facetFilters = {}; // { [colKey]: string }
    this.timeFrom = '';
    this.timeTo = '';
    this.dateColKey = null;
    this.selectedRowRaw = '';

    this._bindStaticEvents();
  }

  _bindStaticEvents() {
    this.dom.globalSearch.addEventListener('input', () => {
      this.globalQuery = this.dom.globalSearch.value.trim().toLowerCase();
      this.applyFiltersAndRender();
    });

    this.dom.timeFromInput.addEventListener('change', () => {
      this.timeFrom = this.dom.timeFromInput.value;
      this.applyFiltersAndRender();
    });

    this.dom.timeToInput.addEventListener('change', () => {
      this.timeTo = this.dom.timeToInput.value;
      this.applyFiltersAndRender();
    });

    this.dom.columnsBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.dom.columnsMenu.classList.toggle('hidden');
    });

    document.addEventListener('click', (e) => {
      if (!this.dom.columnsMenu.contains(e.target) && e.target !== this.dom.columnsBtn) {
        this.dom.columnsMenu.classList.add('hidden');
      }
    });

    this.dom.closeDrawerBtn.addEventListener('click', () => this.closeDrawer());
    this.dom.drawerBackdrop.addEventListener('click', () => this.closeDrawer());
    this.dom.copyRawBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(this.selectedRowRaw || '');
        const prev = this.dom.copyRawBtn.textContent;
        this.dom.copyRawBtn.textContent = 'Copied!';
        setTimeout(() => { this.dom.copyRawBtn.textContent = prev; }, 1200);
      } catch {
        // Clipboard unavailable on insecure origins
      }
    });
  }

  setData({ schema, rows }) {
    this.schema = schema || [];
    this.allRows = rows || [];
    this.facetFilters = {};
    this.globalQuery = '';
    this.timeFrom = '';
    this.timeTo = '';
    this.dom.globalSearch.value = '';
    this.dom.timeFromInput.value = '';
    this.dom.timeToInput.value = '';

    this.visibleKeys = new Set(
      this.schema.filter((c) => c.defaultVisible !== false).map((c) => c.key)
    );

    const dateCol = this.schema.find((c) => c.type === 'datetime');
    this.dateColKey = dateCol ? dateCol.key : null;
    this.dom.timeFilterGroup.classList.toggle('hidden', !this.dateColKey);

    // Default sort by datetime descending if present
    this.sortKey = this.dateColKey || null;
    this.sortDir = 'desc';

    this._renderColumnsMenu();
    this._renderFacetDropdowns();
    this.applyFiltersAndRender();
  }

  getVisibleSchema() {
    return this.schema.filter((c) => this.visibleKeys.has(c.key));
  }

  setFacetFilter(key, value) {
    if (!value) {
      delete this.facetFilters[key];
    } else {
      this.facetFilters[key] = String(value);
    }
    this._syncFacetDropdownValues();
    this.applyFiltersAndRender();
  }

  clearAllFilters() {
    this.facetFilters = {};
    this.globalQuery = '';
    this.timeFrom = '';
    this.timeTo = '';
    this.dom.globalSearch.value = '';
    this.dom.timeFromInput.value = '';
    this.dom.timeToInput.value = '';
    this._syncFacetDropdownValues();
    this.applyFiltersAndRender();
  }

  _renderColumnsMenu() {
    this.dom.columnsMenu.replaceChildren();
    for (const col of this.schema) {
      const label = document.createElement('label');
      label.className = 'checkbox-inline';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = this.visibleKeys.has(col.key);
      cb.addEventListener('change', () => {
        if (cb.checked) this.visibleKeys.add(col.key);
        else this.visibleKeys.delete(col.key);
        this._renderTable();
      });
      const txt = document.createElement('span');
      txt.textContent = col.label || col.key;
      label.append(cb, txt);
      this.dom.columnsMenu.appendChild(label);
    }
  }

  _renderFacetDropdowns() {
    this.dom.facetBar.replaceChildren();
    const facetCols = this.schema.filter((c) => c.facet);

    for (const col of facetCols) {
      const counts = new Map();
      for (const row of this.allRows) {
        const val = row[col.key];
        if (val === null || val === undefined || String(val).trim() === '') continue;
        const s = String(val);
        counts.set(s, (counts.get(s) || 0) + 1);
      }

      if (counts.size === 0) continue;

      const wrap = document.createElement('div');
      wrap.className = 'facet-select-wrap';

      const lbl = document.createElement('label');
      lbl.textContent = col.label || col.key;

      const select = document.createElement('select');
      select.dataset.facetKey = col.key;

      const allOpt = document.createElement('option');
      allOpt.value = '';
      allOpt.textContent = `All (${counts.size})`;
      select.appendChild(allOpt);

      const sortedEntries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
      for (const [val, cnt] of sortedEntries.slice(0, 100)) {
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = `${val} (${cnt})`;
        select.appendChild(opt);
      }

      select.addEventListener('change', () => {
        this.setFacetFilter(col.key, select.value);
      });

      wrap.append(lbl, select);
      this.dom.facetBar.appendChild(wrap);
    }
  }

  _syncFacetDropdownValues() {
    const selects = this.dom.facetBar.querySelectorAll('select[data-facet-key]');
    for (const sel of selects) {
      sel.value = this.facetFilters[sel.dataset.facetKey] || '';
    }
  }

  _renderActivePills() {
    this.dom.activePillsBar.replaceChildren();
    const entries = Object.entries(this.facetFilters);
    const hasExtra = Boolean(this.globalQuery || this.timeFrom || this.timeTo);

    if (entries.length === 0 && !hasExtra) {
      this.dom.activePillsBar.classList.add('hidden');
      return;
    }

    this.dom.activePillsBar.classList.remove('hidden');

    for (const [key, val] of entries) {
      const col = this.schema.find((c) => c.key === key);
      const pill = document.createElement('span');
      pill.className = 'filter-pill';
      const txt = document.createElement('span');
      txt.textContent = `${col?.label || key}: ${val}`;
      const xBtn = document.createElement('button');
      xBtn.type = 'button';
      xBtn.textContent = '×';
      xBtn.title = 'Remove filter';
      xBtn.addEventListener('click', () => this.setFacetFilter(key, ''));
      pill.append(txt, xBtn);
      this.dom.activePillsBar.appendChild(pill);
    }

    const clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'btn btn-ghost btn-sm';
    clearBtn.textContent = 'Clear All Filters';
    clearBtn.addEventListener('click', () => this.clearAllFilters());
    this.dom.activePillsBar.appendChild(clearBtn);
  }

  applyFiltersAndRender() {
    const fromMs = this.timeFrom ? new Date(this.timeFrom).getTime() : null;
    const toMs = this.timeTo ? new Date(this.timeTo).getTime() : null;

    this.filteredRows = this.allRows.filter((row) => {
      // 1. Facet filters
      for (const [k, expected] of Object.entries(this.facetFilters)) {
        if (String(row[k] ?? '') !== expected) return false;
      }

      // 2. Time range filter
      if (this.dateColKey && (fromMs || toMs)) {
        const ts = new Date(row[this.dateColKey]).getTime();
        if (!Number.isNaN(ts)) {
          if (fromMs && ts < fromMs) return false;
          if (toMs && ts > toMs) return false;
        }
      }

      // 3. Global text search across all schema columns
      if (this.globalQuery) {
        const matched = this.schema.some((col) =>
          String(row[col.key] ?? '').toLowerCase().includes(this.globalQuery)
        );
        if (!matched) return false;
      }

      return true;
    });

    // 4. Sort
    if (this.sortKey) {
      const col = this.schema.find((c) => c.key === this.sortKey);
      const mult = this.sortDir === 'asc' ? 1 : -1;
      this.filteredRows.sort((a, b) => {
        const va = a[this.sortKey];
        const vb = b[this.sortKey];
        if (col?.type === 'number') {
          return ((Number(va) || 0) - (Number(vb) || 0)) * mult;
        }
        if (col?.type === 'datetime') {
          return ((new Date(va).getTime() || 0) - (new Date(vb).getTime() || 0)) * mult;
        }
        if (col?.type === 'severity') {
          const ra = SEVERITY_RANK[String(va || '').toLowerCase()] || 0;
          const rb = SEVERITY_RANK[String(vb || '').toLowerCase()] || 0;
          return (ra - rb) * mult;
        }
        if (col?.type === 'ip') {
          return (ipToNumber(va) - ipToNumber(vb)) * mult;
        }
        return String(va ?? '').localeCompare(String(vb ?? '')) * mult;
      });
    }

    this._renderActivePills();
    this._renderTable();
  }

  _renderTable() {
    const visibleCols = this.getVisibleSchema();
    this.dom.thead.replaceChildren();
    this.dom.tbody.replaceChildren();

    this.dom.rowCountBadge.textContent =
      this.filteredRows.length === this.allRows.length
        ? `${this.allRows.length} rows`
        : `${this.filteredRows.length} of ${this.allRows.length} rows`;

    // Header row
    const trHead = document.createElement('tr');
    for (const col of visibleCols) {
      const th = document.createElement('th');
      const arrow = this.sortKey === col.key ? (this.sortDir === 'asc' ? ' ▲' : ' ▼') : '';
      th.textContent = `${col.label || col.key}${arrow}`;
      th.addEventListener('click', () => {
        if (this.sortKey === col.key) {
          this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          this.sortKey = col.key;
          this.sortDir = col.type === 'datetime' || col.type === 'severity' ? 'desc' : 'asc';
        }
        this.applyFiltersAndRender();
      });
      trHead.appendChild(th);
    }
    this.dom.thead.appendChild(trHead);

    // Empty state
    this.dom.emptyState.classList.toggle('hidden', this.filteredRows.length > 0);

    // Body rows (XSS-safe textContent everywhere)
    const frag = document.createDocumentFragment();
    for (const row of this.filteredRows) {
      const tr = document.createElement('tr');
      tr.addEventListener('click', () => this.openDrawer(row));

      for (const col of visibleCols) {
        const td = document.createElement('td');
        const rawVal = row[col.key];
        const strVal = rawVal === null || rawVal === undefined ? '' : String(rawVal);

        if (col.type === 'severity' && strVal) {
          const badge = document.createElement('span');
          badge.className = `sev-badge sev-${strVal.toLowerCase()}`;
          badge.textContent = strVal;
          badge.title = 'Click to filter by this severity';
          badge.addEventListener('click', (e) => {
            e.stopPropagation();
            this.setFacetFilter(col.key, strVal);
          });
          td.appendChild(badge);
        } else if (col.type === 'datetime') {
          td.className = 'cell-mono';
          td.textContent = formatDateTime(strVal);
          td.title = strVal;
        } else if (col.facet && strVal && strVal !== '0') {
          const chip = document.createElement('span');
          chip.className = 'focus-link';
          if (col.type === 'ip' || col.type === 'number') chip.classList.add('cell-mono');
          chip.textContent = strVal;
          chip.title = `Click to focus on ${col.label || col.key} = ${strVal}`;
          chip.addEventListener('click', (e) => {
            e.stopPropagation();
            this.setFacetFilter(col.key, strVal);
          });
          td.appendChild(chip);
        } else {
          if (col.type === 'ip' || col.type === 'number') td.className = 'cell-mono';
          td.textContent = strVal;
          td.title = strVal;
        }

        tr.appendChild(td);
      }

      frag.appendChild(tr);
    }
    this.dom.tbody.appendChild(frag);
  }

  openDrawer(row) {
    this.dom.drawerBody.replaceChildren();
    this.selectedRowRaw = row.RawMessage || JSON.stringify(row, null, 2);

    const kv = document.createElement('div');
    kv.className = 'detail-kv';

    for (const col of this.schema) {
      if (col.key === 'RawMessage') continue;
      const kEl = document.createElement('div');
      kEl.className = 'detail-k';
      kEl.textContent = col.label || col.key;

      const vEl = document.createElement('div');
      vEl.className = 'detail-v';
      const val = row[col.key];
      vEl.textContent = col.type === 'datetime' ? `${formatDateTime(val)} (${val || ''})` : String(val ?? '');
      kv.append(kEl, vEl);
    }

    this.dom.drawerBody.appendChild(kv);

    if (row.RawMessage) {
      const preLabel = document.createElement('div');
      preLabel.className = 'detail-k';
      preLabel.style.marginTop = '12px';
      preLabel.textContent = 'Full Raw Details / Event Message';

      const pre = document.createElement('pre');
      pre.className = 'detail-raw';
      pre.textContent = String(row.RawMessage);

      this.dom.drawerBody.append(preLabel, pre);
    }

    this.dom.drawerBackdrop.classList.remove('hidden');
    this.dom.drawer.classList.remove('hidden');
  }

  closeDrawer() {
    this.dom.drawerBackdrop.classList.add('hidden');
    this.dom.drawer.classList.add('hidden');
  }
}
