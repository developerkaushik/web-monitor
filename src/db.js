const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { hashPassword, SESSION_TTL_HOURS } = require('./auth');

/**
 * Creates and initializes a SQLite database instance.
 * @param {string} dbPath
 * @param {{ adminUsername?: string, adminPassword?: string }} [options]
 */
function createDatabase(dbPath, options = {}) {
  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS monitors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT 'GET',
      interval_seconds INTEGER NOT NULL DEFAULT 60,
      timeout_ms INTEGER NOT NULL DEFAULT 10000,
      expected_status INTEGER NOT NULL DEFAULT 200,
      keyword TEXT DEFAULT '',
      detect_db_errors INTEGER NOT NULL DEFAULT 1,
      failure_threshold INTEGER NOT NULL DEFAULT 1,
      alert_emails TEXT NOT NULL DEFAULT '[]',
      paused INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'unknown',
      consecutive_failures INTEGER NOT NULL DEFAULT 0,
      last_checked_at TEXT,
      last_status_code INTEGER,
      last_latency_ms INTEGER,
      last_error TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      status_code INTEGER,
      latency_ms INTEGER NOT NULL,
      error_message TEXT,
      checked_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_checks_monitor_time
      ON checks(monitor_id, checked_at DESC);

    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      severity TEXT NOT NULL DEFAULT 'critical',
      error_type TEXT NOT NULL,
      status_code INTEGER,
      error_message TEXT NOT NULL,
      acknowledged INTEGER NOT NULL DEFAULT 0,
      notes TEXT DEFAULT '',
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      resolved_at TEXT,
      duration_seconds INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_monitor_status
      ON incidents(monitor_id, status, started_at DESC);

    CREATE TABLE IF NOT EXISTS alert_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
      monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      recipients TEXT NOT NULL,
      subject TEXT NOT NULL,
      delivery_status TEXT NOT NULL,
      error_message TEXT,
      sent_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Safe migration for existing databases missing detect_db_errors
  const monitorCols = db.prepare('PRAGMA table_info(monitors)').all();
  if (!monitorCols.some((c) => c.name === 'detect_db_errors')) {
    db.exec('ALTER TABLE monitors ADD COLUMN detect_db_errors INTEGER NOT NULL DEFAULT 1;');
  }

  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (userCount.count === 0) {
    const adminUser = (options.adminUsername || process.env.ADMIN_USERNAME || 'admin').trim();
    const adminPass = options.adminPassword || process.env.ADMIN_PASSWORD || 'admin123';
    db.prepare(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')"
    ).run(adminUser, hashPassword(adminPass));
  }

  const defaultSettings = {
    smtp_host: process.env.SMTP_HOST || '',
    smtp_port: process.env.SMTP_PORT || '587',
    smtp_secure: process.env.SMTP_SECURE || 'false',
    smtp_user: process.env.SMTP_USER || '',
    smtp_pass: process.env.SMTP_PASS || '',
    smtp_from: process.env.SMTP_FROM || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
    global_alert_emails: process.env.GLOBAL_ALERT_EMAILS || '',
    notify_on_recovery: 'true',
    retention_days: '30',
  };

  const insertSetting = db.prepare(
    'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)'
  );
  for (const [k, v] of Object.entries(defaultSettings)) {
    insertSetting.run(k, String(v));
  }

  return createStore(db);
}

/**
 * Parses JSON email list safely.
 * @param {string} raw
 * @returns {string[]}
 */
function parseEmails(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return String(raw)
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }
}

/**
 * Wraps the DatabaseSync instance with domain-specific queries.
 * @param {import('node:sqlite').DatabaseSync} db
 */
function createStore(db) {
  function serializeMonitor(row) {
    if (!row) return null;
    return {
      ...row,
      paused: Boolean(row.paused),
      detect_db_errors: row.detect_db_errors === undefined ? true : Boolean(row.detect_db_errors),
      alert_emails: parseEmails(row.alert_emails),
    };
  }

  function listMonitors() {
    const rows = db.prepare('SELECT * FROM monitors ORDER BY id DESC').all();
    return rows.map((row) => {
      const monitor = serializeMonitor(row);
      const recentChecks = db
        .prepare(
          'SELECT id, status, status_code, latency_ms, error_message, checked_at FROM checks WHERE monitor_id = ? ORDER BY id DESC LIMIT 30'
        )
        .all(monitor.id)
        .reverse();

      const stats24h = db
        .prepare(
          `SELECT
            COUNT(*) AS total_checks,
            SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) AS up_checks,
            ROUND(AVG(latency_ms)) AS avg_latency_ms
          FROM checks
          WHERE monitor_id = ? AND checked_at >= datetime('now', '-1 day')`
        )
        .get(monitor.id);

      const uptime24h =
        stats24h && stats24h.total_checks > 0
          ? Number(((stats24h.up_checks / stats24h.total_checks) * 100).toFixed(2))
          : null;

      const openIncident = db
        .prepare(
          "SELECT * FROM incidents WHERE monitor_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1"
        )
        .get(monitor.id);

      return {
        ...monitor,
        uptime_24h: uptime24h,
        avg_latency_24h: stats24h?.avg_latency_ms ?? null,
        recent_checks: recentChecks,
        open_incident: openIncident || null,
      };
    });
  }

  function getMonitorById(id) {
    const row = db.prepare('SELECT * FROM monitors WHERE id = ?').get(id);
    if (!row) return null;
    const monitor = serializeMonitor(row);
    const recentChecks = db
      .prepare(
        'SELECT id, status, status_code, latency_ms, error_message, checked_at FROM checks WHERE monitor_id = ? ORDER BY id DESC LIMIT 60'
      )
      .all(id)
      .reverse();
    const openIncident = db
      .prepare(
        "SELECT * FROM incidents WHERE monitor_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1"
      )
      .get(id);
    return { ...monitor, recent_checks: recentChecks, open_incident: openIncident || null };
  }

  function createMonitor(input) {
    const emails = parseEmails(input.alert_emails);
    const stmt = db.prepare(`
      INSERT INTO monitors (
        name, url, method, interval_seconds, timeout_ms,
        expected_status, keyword, detect_db_errors, failure_threshold, alert_emails, paused
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      input.name.trim(),
      input.url.trim(),
      (input.method || 'GET').toUpperCase(),
      Number(input.interval_seconds || 60),
      Number(input.timeout_ms || 10000),
      Number(input.expected_status || 200),
      (input.keyword || '').trim(),
      input.detect_db_errors === false ? 0 : 1,
      Math.max(1, Number(input.failure_threshold || 1)),
      JSON.stringify(emails),
      input.paused ? 1 : 0
    );
    return getMonitorById(Number(result.lastInsertRowid));
  }

  function updateMonitor(id, input) {
    const existing = db.prepare('SELECT * FROM monitors WHERE id = ?').get(id);
    if (!existing) return null;

    const emails =
      input.alert_emails !== undefined
        ? parseEmails(input.alert_emails)
        : parseEmails(existing.alert_emails);

    db.prepare(`
      UPDATE monitors SET
        name = ?,
        url = ?,
        method = ?,
        interval_seconds = ?,
        timeout_ms = ?,
        expected_status = ?,
        keyword = ?,
        detect_db_errors = ?,
        failure_threshold = ?,
        alert_emails = ?,
        paused = ?,
        updated_at = datetime('now')
      WHERE id = ?
    `).run(
      input.name !== undefined ? input.name.trim() : existing.name,
      input.url !== undefined ? input.url.trim() : existing.url,
      input.method !== undefined ? input.method.toUpperCase() : existing.method,
      input.interval_seconds !== undefined
        ? Number(input.interval_seconds)
        : existing.interval_seconds,
      input.timeout_ms !== undefined ? Number(input.timeout_ms) : existing.timeout_ms,
      input.expected_status !== undefined
        ? Number(input.expected_status)
        : existing.expected_status,
      input.keyword !== undefined ? input.keyword.trim() : existing.keyword,
      input.detect_db_errors !== undefined
        ? (input.detect_db_errors ? 1 : 0)
        : existing.detect_db_errors,
      input.failure_threshold !== undefined
        ? Math.max(1, Number(input.failure_threshold))
        : existing.failure_threshold,
      JSON.stringify(emails),
      input.paused !== undefined ? (input.paused ? 1 : 0) : existing.paused,
      id
    );
    return getMonitorById(id);
  }

  function deleteMonitor(id) {
    const res = db.prepare('DELETE FROM monitors WHERE id = ?').run(id);
    return res.changes > 0;
  }

  function getDueMonitors() {
    const rows = db
      .prepare(
        `SELECT * FROM monitors
         WHERE paused = 0
           AND (
             last_checked_at IS NULL
             OR datetime(last_checked_at, '+' || interval_seconds || ' seconds') <= datetime('now')
           )`
      )
      .all();
    return rows.map(serializeMonitor);
  }

  function recordCheck(monitorId, check) {
    const res = db
      .prepare(
        `INSERT INTO checks (monitor_id, status, status_code, latency_ms, error_message, checked_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`
      )
      .run(
        monitorId,
        check.status,
        check.status_code ?? null,
        check.latency_ms,
        check.error_message || null
      );
    return Number(res.lastInsertRowid);
  }

  function updateMonitorRuntime(id, fields) {
    db.prepare(
      `UPDATE monitors SET
        status = ?,
        consecutive_failures = ?,
        last_checked_at = datetime('now'),
        last_status_code = ?,
        last_latency_ms = ?,
        last_error = ?,
        updated_at = datetime('now')
       WHERE id = ?`
    ).run(
      fields.status,
      fields.consecutive_failures,
      fields.last_status_code ?? null,
      fields.last_latency_ms ?? null,
      fields.last_error || null,
      id
    );
  }

  function getOpenIncident(monitorId) {
    return (
      db
        .prepare(
          "SELECT * FROM incidents WHERE monitor_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1"
        )
        .get(monitorId) || null
    );
  }

  function createIncident(data) {
    const res = db
      .prepare(
        `INSERT INTO incidents (
          monitor_id, title, status, severity, error_type, status_code, error_message, started_at
        ) VALUES (?, ?, 'open', ?, ?, ?, ?, datetime('now'))`
      )
      .run(
        data.monitor_id,
        data.title,
        data.severity || 'critical',
        data.error_type,
        data.status_code ?? null,
        data.error_message
      );
    return db
      .prepare('SELECT * FROM incidents WHERE id = ?')
      .get(Number(res.lastInsertRowid));
  }

  function resolveIncident(incidentId, notes) {
    const existing = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    if (!existing || existing.status === 'resolved') return existing || null;

    db.prepare(
      `UPDATE incidents SET
        status = 'resolved',
        resolved_at = datetime('now'),
        duration_seconds = MAX(0, CAST((julianday('now') - julianday(started_at)) * 86400 AS INTEGER)),
        notes = CASE WHEN ? != '' THEN ? ELSE notes END
       WHERE id = ?`
    ).run(notes || '', notes || '', incidentId);

    return db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
  }

  function updateIncident(incidentId, { acknowledged, notes }) {
    const existing = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    if (!existing) return null;
    db.prepare(
      `UPDATE incidents SET
        acknowledged = COALESCE(?, acknowledged),
        notes = COALESCE(?, notes)
       WHERE id = ?`
    ).run(
      acknowledged === undefined ? null : acknowledged ? 1 : 0,
      notes === undefined ? null : notes,
      incidentId
    );
    return db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
  }

  function listIncidents({ status, monitorId, limit = 100 } = {}) {
    const clauses = [];
    const params = [];
    if (status && status !== 'all') {
      clauses.push('i.status = ?');
      params.push(status);
    }
    if (monitorId) {
      clauses.push('i.monitor_id = ?');
      params.push(Number(monitorId));
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(Number(limit));

    return db
      .prepare(
        `SELECT i.*, m.name AS monitor_name, m.url AS monitor_url
         FROM incidents i
         JOIN monitors m ON m.id = i.monitor_id
         ${where}
         ORDER BY i.id DESC
         LIMIT ?`
      )
      .all(...params);
  }

  function recordAlertLog(entry) {
    const res = db
      .prepare(
        `INSERT INTO alert_logs (
          incident_id, monitor_id, event_type, recipients, subject, delivery_status, error_message, sent_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .run(
        entry.incident_id ?? null,
        entry.monitor_id,
        entry.event_type,
        JSON.stringify(entry.recipients || []),
        entry.subject,
        entry.delivery_status,
        entry.error_message || null
      );
    return db
      .prepare('SELECT * FROM alert_logs WHERE id = ?')
      .get(Number(res.lastInsertRowid));
  }

  function listAlertLogs(limit = 100) {
    return db
      .prepare(
        `SELECT a.*, m.name AS monitor_name, m.url AS monitor_url
         FROM alert_logs a
         LEFT JOIN monitors m ON m.id = a.monitor_id
         ORDER BY a.id DESC
         LIMIT ?`
      )
      .all(Number(limit))
      .map((row) => ({
        ...row,
        recipients: parseEmails(row.recipients),
      }));
  }

  function getSettings() {
    const rows = db.prepare('SELECT key, value FROM settings').all();
    const result = {};
    for (const row of rows) {
      result[row.key] = row.value;
    }
    return result;
  }

  function updateSettings(updates) {
    const stmt = db.prepare(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    );
    for (const [k, v] of Object.entries(updates)) {
      if (v !== undefined && v !== null) {
        stmt.run(k, String(v));
      }
    }
    return getSettings();
  }

  function pruneOldChecks(days = 30) {
    const res = db
      .prepare("DELETE FROM checks WHERE checked_at < datetime('now', ?)")
      .run(`-${Math.max(1, Number(days))} days`);
    return res.changes;
  }

  function getSummary() {
    const counts = db
      .prepare(
        `SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN paused = 0 AND status = 'up' THEN 1 ELSE 0 END) AS up,
          SUM(CASE WHEN paused = 0 AND status = 'down' THEN 1 ELSE 0 END) AS down,
          SUM(CASE WHEN paused = 1 THEN 1 ELSE 0 END) AS paused,
          ROUND(AVG(CASE WHEN paused = 0 AND last_latency_ms IS NOT NULL THEN last_latency_ms END)) AS avg_latency_ms
        FROM monitors`
      )
      .get();

    const openIncidents = db
      .prepare("SELECT COUNT(*) AS count FROM incidents WHERE status = 'open'")
      .get();

    const checks24h = db
      .prepare(
        `SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) AS up
        FROM checks
        WHERE checked_at >= datetime('now', '-1 day')`
      )
      .get();

    const overallUptime24h =
      checks24h && checks24h.total > 0
        ? Number(((checks24h.up / checks24h.total) * 100).toFixed(2))
        : 100;

    return {
      total_monitors: counts.total || 0,
      up_monitors: counts.up || 0,
      down_monitors: counts.down || 0,
      paused_monitors: counts.paused || 0,
      avg_latency_ms: counts.avg_latency_ms ?? null,
      open_incidents: openIncidents.count || 0,
      overall_uptime_24h: overallUptime24h,
    };
  }

  function getUserByUsername(username) {
    return db
      .prepare('SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?')
      .get(String(username).trim()) || null;
  }

  function getUserById(id) {
    return db
      .prepare('SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?')
      .get(Number(id)) || null;
  }

  function updateUserPassword(userId, newPasswordHash) {
    const res = db
      .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
      .run(newPasswordHash, Number(userId));
    return res.changes > 0;
  }

  function createSession(userId, ttlHours = SESSION_TTL_HOURS) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare(
      `INSERT INTO sessions (token, user_id, expires_at)
       VALUES (?, ?, datetime('now', ?))`
    ).run(token, Number(userId), `+${Math.max(1, Number(ttlHours))} hours`);
    return token;
  }

  function getSession(token) {
    if (!token) return null;
    return db
      .prepare(
        `SELECT s.token, s.user_id, s.expires_at, u.username, u.role
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token = ? AND s.expires_at > datetime('now')`
      )
      .get(String(token)) || null;
  }

  function deleteSession(token) {
    if (!token) return false;
    const res = db.prepare('DELETE FROM sessions WHERE token = ?').run(String(token));
    return res.changes > 0;
  }

  function deleteUserSessions(userId) {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(Number(userId));
  }

  function pruneExpiredSessions() {
    db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  }

  function close() {
    db.close();
  }

  return {
    db,
    listMonitors,
    getMonitorById,
    createMonitor,
    updateMonitor,
    deleteMonitor,
    getDueMonitors,
    recordCheck,
    updateMonitorRuntime,
    getOpenIncident,
    createIncident,
    resolveIncident,
    updateIncident,
    listIncidents,
    recordAlertLog,
    listAlertLogs,
    getSettings,
    updateSettings,
    pruneOldChecks,
    getSummary,
    getUserByUsername,
    getUserById,
    updateUserPassword,
    createSession,
    getSession,
    deleteSession,
    deleteUserSessions,
    pruneExpiredSessions,
    close,
  };
}

module.exports = { createDatabase, parseEmails };
