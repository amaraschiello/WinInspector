#Requires -Version 5.1
<#
.SYNOPSIS
    Zero-dependency SQLite persistence layer using Windows built-in winsqlite3.dll.
.DESCRIPTION
    Stores Live Performance & Network/GPU monitoring sessions, samples, adapter
    packet-error stats, top processes, and open connections/SMB files/pipes in
    data\wininspector.db so Pode memory stays flat during continuous monitoring.
#>

Set-StrictMode -Version Latest

if (-not ('WinInspector.NativeSqlite' -as [type])) {
    $csSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WinInspector
{
    public static class NativeSqlite
    {
        private static readonly object _dbLock = new object();

        private const int SQLITE_OK   = 0;
        private const int SQLITE_ROW  = 100;
        private const int SQLITE_DONE = 101;
        private const int SQLITE_INTEGER = 1;
        private const int SQLITE_FLOAT   = 2;
        private const int SQLITE_TEXT    = 3;
        private const int SQLITE_NULL    = 5;
        private const int SQLITE_OPEN_READWRITE = 0x00000002;
        private const int SQLITE_OPEN_CREATE    = 0x00000004;

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_open_v2(byte[] filename, out IntPtr ppDb, int flags, IntPtr zVfs);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close_v2(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_exec(IntPtr db, byte[] sql, IntPtr callback, IntPtr arg, out IntPtr errmsg);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void sqlite3_free(IntPtr ptr);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_prepare_v2(IntPtr db, byte[] zSql, int nByte, out IntPtr ppStmt, out IntPtr pzTail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr pStmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr pStmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_null(IntPtr pStmt, int idx);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_int64(IntPtr pStmt, int idx, long val);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_double(IntPtr pStmt, int idx, double val);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_bind_text(IntPtr pStmt, int idx, byte[] val, int nBytes, IntPtr destructor);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_count(IntPtr pStmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_name(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_type(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long sqlite3_column_int64(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern double sqlite3_column_double(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_text(IntPtr pStmt, int iCol);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long sqlite3_last_insert_rowid(IntPtr db);

        private static byte[] ToUtf8Z(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
            byte[] z = new byte[bytes.Length + 1];
            Buffer.BlockCopy(bytes, 0, z, 0, bytes.Length);
            return z;
        }

        private static string PtrToUtf8(IntPtr p)
        {
            if (p == IntPtr.Zero) return string.Empty;
            int len = 0;
            while (Marshal.ReadByte(p, len) != 0) len++;
            if (len == 0) return string.Empty;
            byte[] buf = new byte[len];
            Marshal.Copy(p, buf, 0, len);
            return Encoding.UTF8.GetString(buf);
        }

        private static IntPtr OpenDb(string dbPath)
        {
            IntPtr db;
            int rc = sqlite3_open_v2(ToUtf8Z(dbPath), out db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, IntPtr.Zero);
            if (rc != SQLITE_OK)
            {
                string msg = db != IntPtr.Zero ? PtrToUtf8(sqlite3_errmsg(db)) : ("rc=" + rc);
                if (db != IntPtr.Zero) sqlite3_close_v2(db);
                throw new Exception("SQLite open failed: " + msg);
            }
            ExecNoLock(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;");
            return db;
        }

        private static void ExecNoLock(IntPtr db, string sql)
        {
            IntPtr errPtr;
            int rc = sqlite3_exec(db, ToUtf8Z(sql), IntPtr.Zero, IntPtr.Zero, out errPtr);
            if (rc != SQLITE_OK)
            {
                string msg = errPtr != IntPtr.Zero ? PtrToUtf8(errPtr) : PtrToUtf8(sqlite3_errmsg(db));
                if (errPtr != IntPtr.Zero) sqlite3_free(errPtr);
                throw new Exception("SQLite exec failed: " + msg);
            }
        }

        private static void BindParams(IntPtr stmt, object[] args)
        {
            if (args == null) return;
            for (int i = 0; i < args.Length; i++)
            {
                int idx = i + 1;
                object val = args[i];
                if (val == null || val == DBNull.Value)
                {
                    sqlite3_bind_null(stmt, idx);
                }
                else if (val is bool)
                {
                    sqlite3_bind_int64(stmt, idx, ((bool)val) ? 1L : 0L);
                }
                else if (val is sbyte || val is byte || val is short || val is ushort || val is int || val is uint || val is long)
                {
                    sqlite3_bind_int64(stmt, idx, Convert.ToInt64(val));
                }
                else if (val is float || val is double || val is decimal)
                {
                    sqlite3_bind_double(stmt, idx, Convert.ToDouble(val));
                }
                else
                {
                    byte[] utf8 = Encoding.UTF8.GetBytes(Convert.ToString(val) ?? string.Empty);
                    // Pass SQLITE_TRANSIENT (-1) so SQLite copies the buffer immediately
                    sqlite3_bind_text(stmt, idx, utf8, utf8.Length, new IntPtr(-1));
                }
            }
        }

        public static void ExecuteSchema(string dbPath, string ddl)
        {
            lock (_dbLock)
            {
                IntPtr db = OpenDb(dbPath);
                try { ExecNoLock(db, ddl); }
                finally { sqlite3_close_v2(db); }
            }
        }

        public static long ExecuteNonQuery(string dbPath, string sql, object[] args)
        {
            lock (_dbLock)
            {
                IntPtr db = OpenDb(dbPath);
                try
                {
                    IntPtr stmt;
                    IntPtr tail;
                    byte[] sqlBytes = ToUtf8Z(sql);
                    int rc = sqlite3_prepare_v2(db, sqlBytes, sqlBytes.Length - 1, out stmt, out tail);
                    if (rc != SQLITE_OK) throw new Exception("SQLite prepare failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                    try
                    {
                        BindParams(stmt, args);
                        rc = sqlite3_step(stmt);
                        if (rc != SQLITE_DONE && rc != SQLITE_ROW)
                            throw new Exception("SQLite step failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                        return sqlite3_last_insert_rowid(db);
                    }
                    finally { sqlite3_finalize(stmt); }
                }
                finally { sqlite3_close_v2(db); }
            }
        }

        public static void ExecuteBatch(string dbPath, List<string> sqls, List<object[]> paramSets)
        {
            lock (_dbLock)
            {
                IntPtr db = OpenDb(dbPath);
                try
                {
                    ExecNoLock(db, "BEGIN IMMEDIATE TRANSACTION;");
                    try
                    {
                        for (int q = 0; q < sqls.Count; q++)
                        {
                            IntPtr stmt;
                            IntPtr tail;
                            byte[] sqlBytes = ToUtf8Z(sqls[q]);
                            int rc = sqlite3_prepare_v2(db, sqlBytes, sqlBytes.Length - 1, out stmt, out tail);
                            if (rc != SQLITE_OK) throw new Exception("SQLite prepare failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                            try
                            {
                                BindParams(stmt, paramSets[q]);
                                rc = sqlite3_step(stmt);
                                if (rc != SQLITE_DONE && rc != SQLITE_ROW)
                                    throw new Exception("SQLite step failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                            }
                            finally { sqlite3_finalize(stmt); }
                        }
                        ExecNoLock(db, "COMMIT;");
                    }
                    catch
                    {
                        try { ExecNoLock(db, "ROLLBACK;"); } catch { }
                        throw;
                    }
                }
                finally { sqlite3_close_v2(db); }
            }
        }

        public static List<Dictionary<string, object>> ExecuteQuery(string dbPath, string sql, object[] args)
        {
            lock (_dbLock)
            {
                var rows = new List<Dictionary<string, object>>();
                IntPtr db = OpenDb(dbPath);
                try
                {
                    IntPtr stmt;
                    IntPtr tail;
                    byte[] sqlBytes = ToUtf8Z(sql);
                    int rc = sqlite3_prepare_v2(db, sqlBytes, sqlBytes.Length - 1, out stmt, out tail);
                    if (rc != SQLITE_OK) throw new Exception("SQLite prepare failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                    try
                    {
                        BindParams(stmt, args);
                        int colCount = sqlite3_column_count(stmt);
                        string[] colNames = new string[colCount];
                        for (int c = 0; c < colCount; c++) colNames[c] = PtrToUtf8(sqlite3_column_name(stmt, c));

                        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
                        {
                            var row = new Dictionary<string, object>(colCount, StringComparer.OrdinalIgnoreCase);
                            for (int c = 0; c < colCount; c++)
                            {
                                int t = sqlite3_column_type(stmt, c);
                                if (t == SQLITE_NULL) row[colNames[c]] = null;
                                else if (t == SQLITE_INTEGER) row[colNames[c]] = sqlite3_column_int64(stmt, c);
                                else if (t == SQLITE_FLOAT) row[colNames[c]] = sqlite3_column_double(stmt, c);
                                else row[colNames[c]] = PtrToUtf8(sqlite3_column_text(stmt, c));
                            }
                            rows.Add(row);
                        }
                        if (rc != SQLITE_DONE) throw new Exception("SQLite query step failed: " + PtrToUtf8(sqlite3_errmsg(db)));
                        return rows;
                    }
                    finally { sqlite3_finalize(stmt); }
                }
                finally { sqlite3_close_v2(db); }
            }
        }
    }
}
'@
    Add-Type -TypeDefinition $csSource -Language CSharp
}

function Initialize-WinInspectorDb {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DbPath
    )

    $dir = Split-Path -Parent $DbPath
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }

    $ddl = @'
CREATE TABLE IF NOT EXISTS perf_sessions (
    session_id    TEXT PRIMARY KEY,
    server_name   TEXT NOT NULL,
    started_utc   TEXT NOT NULL,
    stopped_utc   TEXT,
    interval_sec  INTEGER NOT NULL,
    status        TEXT NOT NULL,
    executed_by   TEXT,
    protocol_used TEXT
);

CREATE TABLE IF NOT EXISTS perf_samples (
    sample_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    ts_utc          TEXT NOT NULL,
    cpu_pct         REAL NOT NULL DEFAULT 0,
    mem_used_pct    REAL NOT NULL DEFAULT 0,
    mem_avail_mb    REAL NOT NULL DEFAULT 0,
    disk_read_ms    REAL NOT NULL DEFAULT 0,
    disk_write_ms   REAL NOT NULL DEFAULT 0,
    disk_queue      REAL NOT NULL DEFAULT 0,
    gpu_util_pct    REAL NOT NULL DEFAULT 0,
    gpu_mem_mb      REAL NOT NULL DEFAULT 0,
    net_rx_kbps     REAL NOT NULL DEFAULT 0,
    net_tx_kbps     REAL NOT NULL DEFAULT 0,
    net_rx_errors   INTEGER NOT NULL DEFAULT 0,
    net_tx_errors   INTEGER NOT NULL DEFAULT 0,
    net_rx_discards INTEGER NOT NULL DEFAULT 0,
    net_tx_discards INTEGER NOT NULL DEFAULT 0,
    tcp_established INTEGER NOT NULL DEFAULT 0,
    smb_open_files  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_perf_samples_sess ON perf_samples(session_id, sample_id);

CREATE TABLE IF NOT EXISTS perf_adapter_metrics (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id    INTEGER NOT NULL,
    session_id   TEXT NOT NULL,
    ts_utc       TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    link_speed   TEXT,
    rx_kbps      REAL NOT NULL DEFAULT 0,
    tx_kbps      REAL NOT NULL DEFAULT 0,
    rx_errors    INTEGER NOT NULL DEFAULT 0,
    tx_errors    INTEGER NOT NULL DEFAULT 0,
    rx_discards  INTEGER NOT NULL DEFAULT 0,
    tx_discards  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_perf_adapters_sess ON perf_adapter_metrics(session_id, sample_id);

CREATE TABLE IF NOT EXISTS perf_top_processes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id  INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    ts_utc     TEXT NOT NULL,
    proc_name  TEXT NOT NULL,
    pid        INTEGER NOT NULL,
    cpu_pct    REAL NOT NULL DEFAULT 0,
    cpu_sec    REAL NOT NULL DEFAULT 0,
    mem_mb     REAL NOT NULL DEFAULT 0,
    gpu_pct    REAL NOT NULL DEFAULT 0,
    gpu_mem_mb REAL NOT NULL DEFAULT 0,
    handles    INTEGER NOT NULL DEFAULT 0,
    threads    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_perf_procs_sess ON perf_top_processes(session_id, sample_id);

CREATE TABLE IF NOT EXISTS perf_network_details (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id     INTEGER NOT NULL,
    session_id    TEXT NOT NULL,
    ts_utc        TEXT NOT NULL,
    detail_type   TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    service_name  TEXT NOT NULL,
    client_ip     TEXT,
    local_port    INTEGER,
    remote_port   INTEGER,
    user_name     TEXT,
    process_name  TEXT,
    resource_path TEXT,
    state         TEXT
);
CREATE INDEX IF NOT EXISTS idx_perf_netdet_sess ON perf_network_details(session_id, sample_id);
'@
    [WinInspector.NativeSqlite]::ExecuteSchema($DbPath, $ddl)
}

function Start-PerfSessionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DbPath,
        [Parameter(Mandatory)] [string]$ServerName,
        [Parameter(Mandatory)] [int]$IntervalSec,
        [Parameter()] [string]$ExecutedBy = '',
        [Parameter()] [string]$ProtocolUsed = 'Auto'
    )

    Initialize-WinInspectorDb -DbPath $DbPath
    $sessionId = [guid]::NewGuid().ToString('N').Substring(0, 16)
    $startedUtc = (Get-Date).ToUniversalTime().ToString('o')

    $sql = 'INSERT INTO perf_sessions (session_id, server_name, started_utc, interval_sec, status, executed_by, protocol_used) VALUES (?, ?, ?, ?, ?, ?, ?);'
    $null = [WinInspector.NativeSqlite]::ExecuteNonQuery($DbPath, $sql, @($sessionId, $ServerName, $startedUtc, $IntervalSec, 'Running', $ExecutedBy, $ProtocolUsed))

    return [ordered]@{
        sessionId   = $sessionId
        serverName  = $ServerName
        startedUtc  = $startedUtc
        intervalSec = $IntervalSec
        status      = 'Running'
    }
}

function Stop-PerfSessionRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DbPath,
        [Parameter(Mandatory)] [string]$SessionId
    )

    Initialize-WinInspectorDb -DbPath $DbPath
    $stoppedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $sql = 'UPDATE perf_sessions SET status = ?, stopped_utc = ? WHERE session_id = ?;'
    $null = [WinInspector.NativeSqlite]::ExecuteNonQuery($DbPath, $sql, @('Stopped', $stoppedUtc, $SessionId))

    return [ordered]@{
        sessionId  = $SessionId
        status     = 'Stopped'
        stoppedUtc = $stoppedUtc
    }
}

function Save-PerfSampleRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DbPath,
        [Parameter(Mandatory)] [string]$SessionId,
        [Parameter(Mandatory)] [object]$Payload
    )

    Initialize-WinInspectorDb -DbPath $DbPath
    $ts = if ($Payload.tsUtc) { [string]$Payload.tsUtc } else { (Get-Date).ToUniversalTime().ToString('o') }
    $sum = $Payload.summary

    # Update protocol_used on session if first sample resolved it
    if ($Payload.protocolUsed) {
        $null = [WinInspector.NativeSqlite]::ExecuteNonQuery($DbPath, 'UPDATE perf_sessions SET protocol_used = ? WHERE session_id = ?;', @([string]$Payload.protocolUsed, $SessionId))
    }

    $sampleSql = @'
INSERT INTO perf_samples (
    session_id, ts_utc, cpu_pct, mem_used_pct, mem_avail_mb,
    disk_read_ms, disk_write_ms, disk_queue, gpu_util_pct, gpu_mem_mb,
    net_rx_kbps, net_tx_kbps, net_rx_errors, net_tx_errors, net_rx_discards, net_tx_discards,
    tcp_established, smb_open_files
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
'@
    $sampleId = [WinInspector.NativeSqlite]::ExecuteNonQuery($DbPath, $sampleSql, @(
        $SessionId,
        $ts,
        [double]$sum.cpuPct,
        [double]$sum.memUsedPct,
        [double]$sum.memAvailMB,
        [double]$sum.diskReadMs,
        [double]$sum.diskWriteMs,
        [double]$sum.diskQueue,
        [double]$sum.gpuUtilPct,
        [double]$sum.gpuMemMB,
        [double]$sum.netRxKbps,
        [double]$sum.netTxKbps,
        [long]$sum.netRxErrors,
        [long]$sum.netTxErrors,
        [long]$sum.netRxDiscards,
        [long]$sum.netTxDiscards,
        [int]$sum.tcpEstablished,
        [int]$sum.smbOpenFiles
    ))

    # Batch-insert adapters, top processes, and network/SMB/pipe details in a single transaction
    $sqlList   = [System.Collections.Generic.List[string]]::new()
    $paramList = [System.Collections.Generic.List[object[]]]::new()

    $adapterSql = 'INSERT INTO perf_adapter_metrics (sample_id, session_id, ts_utc, adapter_name, link_speed, rx_kbps, tx_kbps, rx_errors, tx_errors, rx_discards, tx_discards) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'
    foreach ($a in @($Payload.adapters)) {
        $sqlList.Add($adapterSql)
        $paramList.Add(@($sampleId, $SessionId, $ts, [string]$a.adapterName, [string]$a.linkSpeed, [double]$a.rxKbps, [double]$a.txKbps, [long]$a.rxErrors, [long]$a.txErrors, [long]$a.rxDiscards, [long]$a.txDiscards))
    }

    $procSql = 'INSERT INTO perf_top_processes (sample_id, session_id, ts_utc, proc_name, pid, cpu_pct, cpu_sec, mem_mb, gpu_pct, gpu_mem_mb, handles, threads) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'
    foreach ($p in @($Payload.topProcesses)) {
        $sqlList.Add($procSql)
        $paramList.Add(@($sampleId, $SessionId, $ts, [string]$p.procName, [int]$p.pid, [double]$p.cpuPct, [double]$p.cpuSec, [double]$p.memMB, [double]$p.gpuPct, [double]$p.gpuMemMB, [int]$p.handles, [int]$p.threads))
    }

    $netSql = 'INSERT INTO perf_network_details (sample_id, session_id, ts_utc, detail_type, protocol, service_name, client_ip, local_port, remote_port, user_name, process_name, resource_path, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'
    foreach ($n in @($Payload.networkDetails)) {
        $sqlList.Add($netSql)
        $paramList.Add(@($sampleId, $SessionId, $ts, [string]$n.detailType, [string]$n.protocol, [string]$n.serviceName, [string]$n.clientIp, [int]$n.localPort, [int]$n.remotePort, [string]$n.userName, [string]$n.processName, [string]$n.resourcePath, [string]$n.state))
    }

    if ($sqlList.Count -gt 0) {
        [WinInspector.NativeSqlite]::ExecuteBatch($DbPath, $sqlList, $paramList)
    }

    return $sampleId
}

function Get-PerfSessionsList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DbPath,
        [Parameter()] [int]$Limit = 30
    )

    Initialize-WinInspectorDb -DbPath $DbPath
    $sql = @'
SELECT s.session_id, s.server_name, s.started_utc, s.stopped_utc, s.interval_sec, s.status, s.executed_by, s.protocol_used,
       COUNT(p.sample_id) AS sample_count
FROM perf_sessions s
LEFT JOIN perf_samples p ON p.session_id = s.session_id
GROUP BY s.session_id
ORDER BY s.started_utc DESC
LIMIT ?;
'@
    $rows = [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, $sql, @($Limit))
    return $rows.ToArray()
}

function Get-PerfSessionHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DbPath,
        [Parameter(Mandatory)] [string]$SessionId,
        [Parameter()] [string]$ClientIp = '',
        [Parameter()] [string]$Protocol = '',
        [Parameter()] [string]$ServiceName = '',
        [Parameter()] [string]$ProcessName = '',
        [Parameter()] [string]$LocalPort = '',
        [Parameter()] [string]$RemotePort = '',
        [Parameter()] [string]$Search = '',
        [Parameter()] [int]$TimelineLimit = 300
    )

    Initialize-WinInspectorDb -DbPath $DbPath

    $sessRows = [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, 'SELECT * FROM perf_sessions WHERE session_id = ? LIMIT 1;', @($SessionId))
    $sessionInfo = if ($sessRows.Count -gt 0) { $sessRows[0] } else { $null }

    $timeline = [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, @'
SELECT * FROM (
    SELECT sample_id, ts_utc, cpu_pct, mem_used_pct, mem_avail_mb, disk_read_ms, disk_write_ms, disk_queue,
           gpu_util_pct, gpu_mem_mb, net_rx_kbps, net_tx_kbps, net_rx_errors, net_tx_errors, net_rx_discards, net_tx_discards,
           tcp_established, smb_open_files
    FROM perf_samples
    WHERE session_id = ?
    ORDER BY sample_id DESC
    LIMIT ?
) sub ORDER BY sample_id ASC;
'@, @($SessionId, $TimelineLimit))

    $latestSampleId = if ($timeline.Count -gt 0) { [long]$timeline[$timeline.Count - 1]['sample_id'] } else { 0 }

    $adapters = if ($latestSampleId -gt 0) {
        [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, 'SELECT adapter_name, link_speed, rx_kbps, tx_kbps, rx_errors, tx_errors, rx_discards, tx_discards FROM perf_adapter_metrics WHERE session_id = ? AND sample_id = ? ORDER BY adapter_name;', @($SessionId, $latestSampleId)).ToArray()
    } else { @() }

    $topProcs = if ($latestSampleId -gt 0) {
        if (-not [string]::IsNullOrWhiteSpace($ProcessName)) {
            [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, 'SELECT proc_name, pid, cpu_pct, cpu_sec, mem_mb, gpu_pct, gpu_mem_mb, handles, threads FROM perf_top_processes WHERE session_id = ? AND sample_id = ? AND proc_name LIKE ? ORDER BY cpu_pct DESC, mem_mb DESC;', @($SessionId, $latestSampleId, "%$($ProcessName.Trim())%")).ToArray()
        } else {
            [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, 'SELECT proc_name, pid, cpu_pct, cpu_sec, mem_mb, gpu_pct, gpu_mem_mb, handles, threads FROM perf_top_processes WHERE session_id = ? AND sample_id = ? ORDER BY cpu_pct DESC, mem_mb DESC;', @($SessionId, $latestSampleId)).ToArray()
        }
    } else { @() }

    # Filtered Network Connections / SMB Files / SQL & System Pipes from latest sample
    $netDetails = @()
    $serviceBreakdown = @()
    if ($latestSampleId -gt 0) {
        $whereParts = [System.Collections.Generic.List[string]]::new()
        $qArgs      = [System.Collections.Generic.List[object]]::new()
        $whereParts.Add('session_id = ?'); $qArgs.Add($SessionId)
        $whereParts.Add('sample_id = ?');  $qArgs.Add($latestSampleId)

        if (-not [string]::IsNullOrWhiteSpace($ClientIp)) {
            $whereParts.Add('client_ip LIKE ?'); $qArgs.Add("%$($ClientIp.Trim())%")
        }
        if (-not [string]::IsNullOrWhiteSpace($Protocol)) {
            $whereParts.Add('protocol = ?'); $qArgs.Add($Protocol.Trim())
        }
        if (-not [string]::IsNullOrWhiteSpace($ServiceName)) {
            $whereParts.Add('service_name = ?'); $qArgs.Add($ServiceName.Trim())
        }
        if (-not [string]::IsNullOrWhiteSpace($ProcessName)) {
            $whereParts.Add('process_name LIKE ?'); $qArgs.Add("%$($ProcessName.Trim())%")
        }
        $lpNum = 0
        if (-not [string]::IsNullOrWhiteSpace($LocalPort) -and [int]::TryParse($LocalPort.Trim(), [ref]$lpNum)) {
            $whereParts.Add('local_port = ?'); $qArgs.Add($lpNum)
        }
        $rpNum = 0
        if (-not [string]::IsNullOrWhiteSpace($RemotePort) -and [int]::TryParse($RemotePort.Trim(), [ref]$rpNum)) {
            $whereParts.Add('remote_port = ?'); $qArgs.Add($rpNum)
        }
        if (-not [string]::IsNullOrWhiteSpace($Search)) {
            $like = "%$($Search.Trim())%"
            $whereParts.Add('(client_ip LIKE ? OR service_name LIKE ? OR process_name LIKE ? OR resource_path LIKE ? OR user_name LIKE ?)')
            $qArgs.Add($like); $qArgs.Add($like); $qArgs.Add($like); $qArgs.Add($like); $qArgs.Add($like)
        }

        $whereClause = $whereParts -join ' AND '
        $detSql = "SELECT detail_type, protocol, service_name, client_ip, local_port, remote_port, user_name, process_name, resource_path, state FROM perf_network_details WHERE $whereClause ORDER BY detail_type, service_name, local_port LIMIT 500;"
        $netDetails = [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, $detSql, $qArgs.ToArray()).ToArray()

        $brkSql = "SELECT service_name, protocol, COUNT(*) AS cnt FROM perf_network_details WHERE $whereClause GROUP BY service_name, protocol ORDER BY cnt DESC LIMIT 20;"
        $serviceBreakdown = [WinInspector.NativeSqlite]::ExecuteQuery($DbPath, $brkSql, $qArgs.ToArray()).ToArray()
    }

    return [ordered]@{
        session          = $sessionInfo
        latestSampleId   = $latestSampleId
        timeline         = $timeline.ToArray()
        adapters         = $adapters
        topProcesses     = $topProcs
        networkDetails   = $netDetails
        serviceBreakdown = $serviceBreakdown
    }
}

Export-ModuleMember -Function @(
    'Initialize-WinInspectorDb',
    'Start-PerfSessionRecord',
    'Stop-PerfSessionRecord',
    'Save-PerfSampleRecord',
    'Get-PerfSessionsList',
    'Get-PerfSessionHistory'
)
