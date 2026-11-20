/**
 * WinInspector REST API client (talks to Pode backend behind IIS or DevMode).
 */

async function parseResponse(res) {
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    if (res.status === 401) {
      window.location.replace('/login');
    }
    throw new Error(`Invalid JSON from server (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
  if (res.status === 401) {
    window.location.replace(json.loginUrl || '/login');
    throw new Error(json.error || 'Authentication required');
  }
  if (!res.ok) {
    throw new Error(json.error || `Server error (HTTP ${res.status})`);
  }
  return json;
}

export async function logoutSession() {
  const res = await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'include',
  });
  return res.ok ? res.json() : { ok: true, loginUrl: '/login' };
}

export async function fetchHealth() {
  const res = await fetch('/api/health', { credentials: 'include' });
  return parseResponse(res);
}

export async function fetchCatalog() {
  const res = await fetch('/api/catalog', { credentials: 'include' });
  return parseResponse(res);
}

export async function testServerConnection({ computerName, protocol, authMode, credential }) {
  const payload = { computerName, protocol, authMode };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/connect/test', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}

export async function runDiagnostic({ computerName, scriptId, protocol, authMode, credential, parameters, signal }) {
  const payload = { computerName, scriptId, protocol, authMode, parameters };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/diagnostics/run', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal,
  });
  return parseResponse(res);
}

export async function startPerfSession({ computerName, intervalSec, protocol }) {
  const res = await fetch('/api/perf/start', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ computerName, intervalSec, protocol }),
  });
  return parseResponse(res);
}

export async function collectPerfSample({ sessionId, computerName, protocol, authMode, credential, topProcesses, filters, signal }) {
  const payload = { sessionId, computerName, protocol, authMode, topProcesses, filters };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/perf/sample', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal,
  });
  return parseResponse(res);
}

export async function stopPerfSession({ sessionId }) {
  const res = await fetch('/api/perf/stop', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId }),
  });
  return parseResponse(res);
}

export async function fetchPerfSessions() {
  const res = await fetch('/api/perf/sessions', { credentials: 'include' });
  return parseResponse(res);
}

export async function fetchPerfHistory({ sessionId, filters = {} }) {
  const qs = new URLSearchParams({ sessionId });
  if (filters.clientIp)    qs.set('clientIp', filters.clientIp);
  if (filters.protocol)    qs.set('protocol', filters.protocol);
  if (filters.serviceName) qs.set('serviceName', filters.serviceName);
  if (filters.processName) qs.set('processName', filters.processName);
  if (filters.localPort)   qs.set('localPort', filters.localPort);
  if (filters.remotePort)  qs.set('remotePort', filters.remotePort);
  if (filters.search)      qs.set('search', filters.search);
  const res = await fetch(`/api/perf/history?${qs.toString()}`, { credentials: 'include' });
  return parseResponse(res);
}

export async function resetTerminalSession({ computerName, sessionTarget, logonId = '', method = 'Auto', protocol, authMode, credential }) {
  const payload = { computerName, sessionTarget, logonId, method, protocol, authMode };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/rdp/reset', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}

export async function runTerminalCommand({ command, shell = 'PowerShell', cwd = '', timeoutSeconds = 30, signal }) {
  const res = await fetch('/api/terminal/run', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command, shell, cwd, timeoutSeconds }),
    signal,
  });
  return parseResponse(res);
}

export async function fetchProcessDetails({ computerName, protocol, authMode, credential, processId = 0, processName = '' }) {
  const payload = { computerName, protocol, authMode, processId, processName };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/perf/process-details', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}

export async function killTargetProcess({ computerName, protocol, authMode, credential, processId }) {
  const payload = { computerName, protocol, authMode, processId };
  if (authMode === 'CustomCredentials' && credential) {
    payload.credential = credential;
  }
  const res = await fetch('/api/perf/process-kill', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}
