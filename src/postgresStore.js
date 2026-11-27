const crypto = require('node:crypto');
const { Pool } = require('pg');
const { hashPassword, SESSION_TTL_HOURS } = require('./auth');

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
 * Creates a PostgreSQL (Neon) store with the same domain API as SQLite/JSON stores.
 * @param {string} connectionString
 * @param {{ adminUsername?: string, adminPassword?: string }} [options]
 */
function createPostgresStore(connectionString, options = {}) {
  const needsSsl =
    connectionString.includes('sslmode=require') ||
    connectionString.includes('neon.tech') ||
    Boolean(process.env.VERCEL);

  const pool = new Pool({
    connectionString,
    ssl: needsSsl
      ? { rejectUnauthorized: process.env.PG_SSL_REJECT_UNAUTHORIZED !== 'false' }
      : undefined,
    max: 5,
    idleTimeoutMillis: 20000,
    connectionTimeoutMillis: 15000,
  });

  pool.on('error', (err) => {
    console.error('[pg] idle client error:', err.message);
  });

  let initialized = false;
  let initPromise = null;

  async function init() {
    if (initialized) return;
    if (initPromise) return initPromise;

    initPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS monitors (
          id SERIAL PRIMARY KEY,
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
          last_checked_at TIMESTAMPTZ,
          last_status_code INTEGER,
          last_latency_ms INTEGER,
          last_error TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS checks (
          id SERIAL PRIMARY KEY,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          status TEXT NOT NULL,
          status_code INTEGER,
          latency_ms INTEGER NOT NULL,
          error_message TEXT,
          checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_checks_monitor_time
          ON checks(monitor_id, checked_at DESC);

        CREATE TABLE IF NOT EXISTS incidents (
          id SERIAL PRIMARY KEY,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          severity TEXT NOT NULL DEFAULT 'critical',
          error_type TEXT NOT NULL,
          status_code INTEGER,
          error_message TEXT NOT NULL,
          acknowledged INTEGER NOT NULL DEFAULT 0,
          notes TEXT DEFAULT '',
          started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          resolved_at TIMESTAMPTZ,
          duration_seconds INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_monitor_status
          ON incidents(monitor_id, status, started_at DESC);

        CREATE TABLE IF NOT EXISTS alert_logs (
          id SERIAL PRIMARY KEY,
          incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
          monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
          event_type TEXT NOT NULL,
          recipients TEXT NOT NULL,
          subject TEXT NOT NULL,
          delivery_status TEXT NOT NULL,
          error_message TEXT,
          sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'admin',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

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

      for (const [k, v] of Object.entries(defaultSettings)) {
        await pool.query(
          'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
          [k, String(v)]
        );
      }

      const { rows: userCountRows } = await pool.query('SELECT COUNT(*)::int AS count FROM users');
      if (userCountRows[0].count === 0) {
        const adminUser = (options.adminUsername || process.env.ADMIN_USERNAME || 'admin').trim();
        const adminPass = options.adminPassword || process.env.ADMIN_PASSWORD || 'admin123';
        await pool.query(
          "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')",
          [adminUser, hashPassword(adminPass)]
        );
      }

      initialized = true;
    })();

    return initPromise;
  }

  function serializeMonitor(row) {
    if (!row) return null;
    return {
      ...row,
      paused: Boolean(row.paused),
      detect_db_errors: row.detect_db_errors === undefined ? true : Boolean(row.detect_db_errors),
      alert_emails: parseEmails(row.alert_emails),
    };
  }

  async function listMonitors() {
    await init();
    const { rows } = await pool.query('SELECT * FROM monitors ORDER BY id DESC');
    return Promise.all(
      rows.map(async (row) => {
        const monitor = serializeMonitor(row);
        const { rows: recentDesc } = await pool.query(
          'SELECT id, status, status_code, latency_ms, error_message, checked_at FROM checks WHERE monitor_id = $1 ORDER BY id DESC LIMIT 30',
          [monitor.id]
        );
        const { rows: statsRows } = await pool.query(
          `SELECT
            COUNT(*)::int AS total_checks,
            SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END)::int AS up_checks,
            ROUND(AVG(latency_ms))::int AS avg_latency_ms
          FROM checks
          WHERE monitor_id = $1 AND checked_at >= NOW() - INTERVAL '1 day'`,
          [monitor.id]
        );
        const stats = statsRows[0];
        const uptime24h =
          stats && stats.total_checks > 0
            ? Number(((stats.up_checks / stats.total_checks) * 100).toFixed(2))
            : null;
        const { rows: openIncRows } = await pool.query(
          "SELECT * FROM incidents WHERE monitor_id = $1 AND status = 'open' ORDER BY id DESC LIMIT 1",
          [monitor.id]
        );
        return {
          ...monitor,
          uptime_24h: uptime24h,
          avg_latency_24h: stats?.avg_latency_ms ?? null,
          recent_checks: recentDesc.reverse(),
          open_incident: openIncRows[0] || null,
        };
      })
    );
  }

  async function getMonitorById(id) {
    await init();
    const { rows } = await pool.query('SELECT * FROM monitors WHERE id = $1', [Number(id)]);
    if (!rows[0]) return null;
    const monitor = serializeMonitor(rows[0]);
    const { rows: recentDesc } = await pool.query(
      'SELECT id, status, status_code, latency_ms, error_message, checked_at FROM checks WHERE monitor_id = $1 ORDER BY id DESC LIMIT 60',
      [monitor.id]
    );
    const { rows: openIncRows } = await pool.query(
      "SELECT * FROM incidents WHERE monitor_id = $1 AND status = 'open' ORDER BY id DESC LIMIT 1",
      [monitor.id]
    );
    return {
      ...monitor,
      recent_checks: recentDesc.reverse(),
      open_incident: openIncRows[0] || null,
    };
  }

  async function createMonitor(input) {
    await init();
    const emails = parseEmails(input.alert_emails);
    const { rows } = await pool.query(
      `INSERT INTO monitors (
        name, url, method, interval_seconds, timeout_ms,
        expected_status, keyword, detect_db_errors, failure_threshold, alert_emails, paused
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id`,
      [
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
        input.paused ? 1 : 0,
      ]
    );
    return getMonitorById(rows[0].id);
  }

  async function updateMonitor(id, input) {
    await init();
    const { rows } = await pool.query('SELECT * FROM monitors WHERE id = $1', [Number(id)]);
    const existing = rows[0];
    if (!existing) return null;

    const emails =
      input.alert_emails !== undefined
        ? parseEmails(input.alert_emails)
        : parseEmails(existing.alert_emails);

    await pool.query(
      `UPDATE monitors SET
        name = $1,
        url = $2,
        method = $3,
        interval_seconds = $4,
        timeout_ms = $5,
        expected_status = $6,
        keyword = $7,
        detect_db_errors = $8,
        failure_threshold = $9,
        alert_emails = $10,
        paused = $11,
        updated_at = NOW()
      WHERE id = $12`,
      [
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
          ? input.detect_db_errors
            ? 1
            : 0
          : existing.detect_db_errors,
        input.failure_threshold !== undefined
          ? Math.max(1, Number(input.failure_threshold))
          : existing.failure_threshold,
        JSON.stringify(emails),
        input.paused !== undefined ? (input.paused ? 1 : 0) : existing.paused,
        Number(id),
      ]
    );
    return getMonitorById(id);
  }

  async function deleteMonitor(id) {
    await init();
    const res = await pool.query('DELETE FROM monitors WHERE id = $1', [Number(id)]);
    return res.rowCount > 0;
  }

  async function getDueMonitors() {
    await init();
    const { rows } = await pool.query(
      `SELECT * FROM monitors
       WHERE paused = 0
         AND (
           last_checked_at IS NULL
           OR last_checked_at + (interval_seconds * INTERVAL '1 second') <= NOW()
         )`
    );
    return rows.map(serializeMonitor);
  }

  async function recordCheck(monitorId, check) {
    await init();
    const { rows } = await pool.query(
      `INSERT INTO checks (monitor_id, status, status_code, latency_ms, error_message, checked_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING id`,
      [
        Number(monitorId),
        check.status,
        check.status_code ?? null,
        check.latency_ms,
        check.error_message || null,
      ]
    );
    return rows[0].id;
  }

  async function updateMonitorRuntime(id, fields) {
    await init();
    await pool.query(
      `UPDATE monitors SET
        status = $1,
        consecutive_failures = $2,
        last_checked_at = NOW(),
        last_status_code = $3,
        last_latency_ms = $4,
        last_error = $5,
        updated_at = NOW()
      WHERE id = $6`,
      [
        fields.status,
        fields.consecutive_failures,
        fields.last_status_code ?? null,
        fields.last_latency_ms ?? null,
        fields.last_error || null,
        Number(id),
      ]
    );
  }

  async function getOpenIncident(monitorId) {
    await init();
    const { rows } = await pool.query(
      "SELECT * FROM incidents WHERE monitor_id = $1 AND status = 'open' ORDER BY id DESC LIMIT 1",
      [Number(monitorId)]
    );
    return rows[0] || null;
  }

  async function createIncident(data) {
    await init();
    const { rows } = await pool.query(
      `INSERT INTO incidents (
        monitor_id, title, status, severity, error_type, status_code, error_message, started_at
      ) VALUES ($1, $2, 'open', $3, $4, $5, $6, NOW())
      RETURNING *`,
      [
        Number(data.monitor_id),
        data.title,
        data.severity || 'critical',
        data.error_type,
        data.status_code ?? null,
        data.error_message,
      ]
    );
    return rows[0];
  }

  async function resolveIncident(incidentId, notes) {
    await init();
    const { rows } = await pool.query('SELECT * FROM incidents WHERE id = $1', [Number(incidentId)]);
    const existing = rows[0];
    if (!existing || existing.status === 'resolved') return existing || null;

    const { rows: updated } = await pool.query(
      `UPDATE incidents SET
        status = 'resolved',
        resolved_at = NOW(),
        duration_seconds = GREATEST(0, EXTRACT(EPOCH FROM (NOW() - started_at))::int),
        notes = CASE WHEN $1 <> '' THEN $1 ELSE notes END
       WHERE id = $2
       RETURNING *`,
      [notes || '', Number(incidentId)]
    );
    return updated[0];
  }

  async function updateIncident(incidentId, { acknowledged, notes }) {
    await init();
    const { rows } = await pool.query('SELECT * FROM incidents WHERE id = $1', [Number(incidentId)]);
    if (!rows[0]) return null;
    const { rows: updated } = await pool.query(
      `UPDATE incidents SET
        acknowledged = COALESCE($1, acknowledged),
        notes = COALESCE($2, notes)
       WHERE id = $3
       RETURNING *`,
      [
        acknowledged === undefined ? null : acknowledged ? 1 : 0,
        notes === undefined ? null : notes,
        Number(incidentId),
      ]
    );
    return updated[0];
  }

  async function listIncidents({ status, monitorId, limit = 100 } = {}) {
    await init();
    const clauses = [];
    const params = [];
    if (status && status !== 'all') {
      params.push(status);
      clauses.push(`i.status = $${params.length}`);
    }
    if (monitorId) {
      params.push(Number(monitorId));
      clauses.push(`i.monitor_id = $${params.length}`);
    }
    params.push(Number(limit));
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT i.*, m.name AS monitor_name, m.url AS monitor_url
       FROM incidents i
       JOIN monitors m ON m.id = i.monitor_id
       ${where}
       ORDER BY i.id DESC
       LIMIT $${params.length}`,
      params
    );
    return rows;
  }

  async function recordAlertLog(entry) {
    await init();
    const { rows } = await pool.query(
      `INSERT INTO alert_logs (
        incident_id, monitor_id, event_type, recipients, subject, delivery_status, error_message, sent_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *`,
      [
        entry.incident_id ?? null,
        Number(entry.monitor_id),
        entry.event_type,
        JSON.stringify(entry.recipients || []),
        entry.subject,
        entry.delivery_status,
        entry.error_message || null,
      ]
    );
    return rows[0];
  }

  async function listAlertLogs(limit = 100) {
    await init();
    const { rows } = await pool.query(
      `SELECT a.*, m.name AS monitor_name, m.url AS monitor_url
       FROM alert_logs a
       LEFT JOIN monitors m ON m.id = a.monitor_id
       ORDER BY a.id DESC
       LIMIT $1`,
      [Number(limit)]
    );
    return rows.map((r) => ({ ...r, recipients: parseEmails(r.recipients) }));
  }

  async function getSettings() {
    await init();
    const { rows } = await pool.query('SELECT key, value FROM settings');
    const result = {};
    for (const row of rows) {
      result[row.key] = row.value;
    }
    return result;
  }

  async function updateSettings(updates) {
    await init();
    for (const [k, v] of Object.entries(updates)) {
      if (v !== undefined && v !== null) {
        await pool.query(
          'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
          [k, String(v)]
        );
      }
    }
    return getSettings();
  }

  async function pruneOldChecks(days = 30) {
    await init();
    const res = await pool.query(
      "DELETE FROM checks WHERE checked_at < NOW() - ($1 * INTERVAL '1 day')",
      [Math.max(1, Number(days))]
    );
    return res.rowCount;
  }

  async function getSummary() {
    await init();
    const { rows: countRows } = await pool.query(
      `SELECT
        COUNT(*)::int AS total,
        COALESCE(SUM(CASE WHEN paused = 0 AND status = 'up' THEN 1 ELSE 0 END), 0)::int AS up,
        COALESCE(SUM(CASE WHEN paused = 0 AND status = 'down' THEN 1 ELSE 0 END), 0)::int AS down,
        COALESCE(SUM(CASE WHEN paused = 1 THEN 1 ELSE 0 END), 0)::int AS paused,
        ROUND(AVG(CASE WHEN paused = 0 AND last_latency_ms IS NOT NULL THEN last_latency_ms END))::int AS avg_latency_ms
      FROM monitors`
    );
    const counts = countRows[0];
    const { rows: incRows } = await pool.query(
      "SELECT COUNT(*)::int AS count FROM incidents WHERE status = 'open'"
    );
    const { rows: checkRows } = await pool.query(
      `SELECT
        COUNT(*)::int AS total,
        COALESCE(SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END), 0)::int AS up
      FROM checks
      WHERE checked_at >= NOW() - INTERVAL '1 day'`
    );
    const checks24h = checkRows[0];
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
      open_incidents: incRows[0].count || 0,
      overall_uptime_24h: overallUptime24h,
    };
  }

  async function getUserByUsername(username) {
    await init();
    const { rows } = await pool.query(
      'SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1',
      [String(username).trim()]
    );
    return rows[0] || null;
  }

  async function getUserById(id) {
    await init();
    const { rows } = await pool.query(
      'SELECT id, username, password_hash, role, created_at FROM users WHERE id = $1',
      [Number(id)]
    );
    return rows[0] || null;
  }

  async function updateUserPassword(userId, newPasswordHash) {
    await init();
    const res = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [
      newPasswordHash,
      Number(userId),
    ]);
    return res.rowCount > 0;
  }

  async function createSession(userId, ttlHours = SESSION_TTL_HOURS) {
    await init();
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 hour'))",
      [token, Number(userId), Math.max(1, Number(ttlHours))]
    );
    return token;
  }

  async function getSession(token) {
    await init();
    if (!token) return null;
    const { rows } = await pool.query(
      `SELECT s.token, s.user_id, s.expires_at, u.username, u.role
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.expires_at > NOW()`,
      [String(token)]
    );
    return rows[0] || null;
  }

  async function deleteSession(token) {
    await init();
    if (!token) return false;
    const res = await pool.query('DELETE FROM sessions WHERE token = $1', [String(token)]);
    return res.rowCount > 0;
  }

  async function deleteUserSessions(userId) {
    await init();
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [Number(userId)]);
  }

  async function pruneExpiredSessions() {
    await init();
    await pool.query('DELETE FROM sessions WHERE expires_at <= NOW()');
  }

  async function close() {
    await pool.end();
  }

  return {
    db: pool,
    init,
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

module.exports = { createPostgresStore };
