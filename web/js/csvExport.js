/**
 * RFC 4180 CSV Exporter with UTF-8 BOM and CSV formula-injection neutralization.
 */

function sanitizeCsvCell(rawValue) {
  if (rawValue === null || rawValue === undefined) return '""';
  let str = String(rawValue);

  // Neutralize spreadsheet formula injection (=, +, -, @, tab, CR)
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }

  // RFC 4180 escaping
  const escaped = str.replace(/"/g, '""');
  return `"${escaped}"`;
}

export function exportRowsToCsv({ schema, rows, serverName, scriptId, suffix = '' }) {
  if (!schema || !schema.length) return;

  const headers = schema.map((col) => sanitizeCsvCell(col.label || col.key)).join(',');
  const lines = [headers];

  for (const row of rows) {
    const line = schema.map((col) => sanitizeCsvCell(row[col.key])).join(',');
    lines.push(line);
  }

  // UTF-8 BOM ensures Excel parses Unicode cleanly
  const csvContent = '\uFEFF' + lines.join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const safeServer = (serverName || 'server').replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeScript = (scriptId || 'report').replace(/[^a-zA-Z0-9._-]/g, '_');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const tag = suffix ? `_${suffix}` : '';
  const fileName = `WinInspector_${safeServer}_${safeScript}${tag}_${stamp}.csv`;

  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
