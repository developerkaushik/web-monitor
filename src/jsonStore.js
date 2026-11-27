const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
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

function nowIsoSql() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function parseSqlDate(str) {
  if (!str) return 0;
  return Date.parse(str.includes('T') ? str : `${str.replace(' ', 'T')}Z`) || 0;
}

/**
 * Pure-JS file-backed fallback store for environments without node:sqlite (e.g., Node 18/20/22).
 * @param {string} dbPath
 * @param {{ adminUsername?: string, adminPassword?: string }} [options]
 */
function createJsonStore(dbPath, options = {}) {
  const isMemory = dbPath === ':memory:';
  const filePath = isMemory
    ? null
    : dbPath.endsWith('.db')
      ? dbPath.replace(/\.db$/, '.json')
      : `${dbPath}.json`;

  let state = {
    seq: { monitors: 0, checks: 0, incidents: 0, alert_logs: 0, users: 0 },
    monitors: [],
    checks: [],
    incidents: [],
    alert_logs: [],
    settings: {
      smtp_host: process.env.SMTP_HOST || '',
      smtp_port: process.env.SMTP_PORT || '587',
      smtp_secure: process.env.SMTP_SECURE || 'false',
      smtp_user: process.env.SMTP_USER || '',
      smtp_pass: process.env.SMTP_PASS || '',
      smtp_from: process.env.SMTP_FROM || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
      global_alert_emails: process.env.GLOBAL_ALERT_EMAILS || '',
      notify_on_recovery: 'true',
      retention_days: '30',
    },
    users: [],
    sessions: [],
  };

  if (filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (fs.existsSync(filePath)) {
      try {
        const loaded = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        state = { ...state, ...loaded };
      } catch {
        // Start fresh if file is corrupt/empty
      }
    }
  }

  function persist() {
    if (!filePath) return;
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state), 'utf8');
    fs.renameSync(tmp, filePath);
  }

  if (state.users.length === 0) {
    const adminUser = (options.adminUsername || process.env.ADMIN_USERNAME || 'admin').trim();
    const adminPass = options.adminPassword || process.env.ADMIN_PASSWORD || 'admin123';
    state.seq.users += 1;
    state.users.push({
      id: state.seq.users,
      username: adminUser,
      password_hash: hashPassword(adminPass),
      role: 'admin',
      created_at: nowIsoSql(),
    });
    persist();
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

  function enrichMonitor(row, checkLimit) {
    const monitor = serializeMonitor(row);
    const allChecks = state.checks.filter((c) => c.monitor_id === monitor.id);
    const recentChecks = allChecks.slice(-checkLimit);
    const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const dayChecks = allChecks.filter((c) => parseSqlDate(c.checked_at) >= dayAgo);
    const upChecks = dayChecks.filter((c) => c.status === 'up').length;
    const avgLatency =
      dayChecks.length > 0
        ? Math.round(dayChecks.reduce((acc, c) => acc + c.latency_ms, 0) / dayChecks.length)
        : null;
    const uptime24h =
      dayChecks.length > 0 ? Number(((upChecks / dayChecks.length) * 100).toFixed(2)) : null;

    const openIncident =
      [...state.incidents]
        .reverse()
        .find((i) => i.monitor_id === monitor.id && i.status === 'open') || null;

    return {
      ...monitor,
      uptime_24h: uptime24h,
      avg_latency_24h: avgLatency,
      recent_checks: recentChecks,
      open_incident: openIncident,
    };
  }

  return {
    db: null,
    listMonitors() {
      return [...state.monitors].sort((a, b) => b.id - a.id).map((m) => enrichMonitor(m, 30));
    },
    getMonitorById(id) {
      const row = state.monitors.find((m) => m.id === Number(id));
      return row ? enrichMonitor(row, 60) : null;
    },
    createMonitor(input) {
      state.seq.monitors += 1;
      const now = nowIsoSql();
      const row = {
        id: state.seq.monitors,
        name: input.name.trim(),
        url: input.url.trim(),
        method: (input.method || 'GET').toUpperCase(),
        interval_seconds: Number(input.interval_seconds || 60),
        timeout_ms: Number(input.timeout_ms || 10000),
        expected_status: Number(input.expected_status || 200),
        keyword: (input.keyword || '').trim(),
        detect_db_errors: input.detect_db_errors === false ? 0 : 1,
        failure_threshold: Math.max(1, Number(input.failure_threshold || 1)),
        alert_emails: parseEmails(input.alert_emails),
        paused: input.paused ? 1 : 0,
        status: 'unknown',
        consecutive_failures: 0,
        last_checked_at: null,
        last_status_code: null,
        last_latency_ms: null,
        last_error: null,
        created_at: now,
        updated_at: now,
      };
      state.monitors.push(row);
      persist();
      return this.getMonitorById(row.id);
    },
    updateMonitor(id, input) {
      const idx = state.monitors.findIndex((m) => m.id === Number(id));
      if (idx === -1) return null;
      const existing = state.monitors[idx];
      state.monitors[idx] = {
        ...existing,
        name: input.name !== undefined ? input.name.trim() : existing.name,
        url: input.url !== undefined ? input.url.trim() : existing.url,
        method: input.method !== undefined ? input.method.toUpperCase() : existing.method,
        interval_seconds:
          input.interval_seconds !== undefined ? Number(input.interval_seconds) : existing.interval_seconds,
        timeout_ms: input.timeout_ms !== undefined ? Number(input.timeout_ms) : existing.timeout_ms,
        expected_status:
          input.expected_status !== undefined ? Number(input.expected_status) : existing.expected_status,
        keyword: input.keyword !== undefined ? input.keyword.trim() : existing.keyword,
        detect_db_errors:
          input.detect_db_errors !== undefined ? (input.detect_db_errors ? 1 : 0) : existing.detect_db_errors,
        failure_threshold:
          input.failure_threshold !== undefined
            ? Math.max(1, Number(input.failure_threshold))
            : existing.failure_threshold,
        alert_emails:
          input.alert_emails !== undefined ? parseEmails(input.alert_emails) : existing.alert_emails,
        paused: input.paused !== undefined ? (input.paused ? 1 : 0) : existing.paused,
        updated_at: nowIsoSql(),
      };
      persist();
      return this.getMonitorById(id);
    },
    deleteMonitor(id) {
      const before = state.monitors.length;
      state.monitors = state.monitors.filter((m) => m.id !== Number(id));
      if (state.monitors.length === before) return false;
      state.checks = state.checks.filter((c) => c.monitor_id !== Number(id));
      state.incidents = state.incidents.filter((i) => i.monitor_id !== Number(id));
      state.alert_logs = state.alert_logs.filter((a) => a.monitor_id !== Number(id));
      persist();
      return true;
    },
    getDueMonitors() {
      const now = Date.now();
      return state.monitors
        .filter(
          (m) =>
            !m.paused &&
            (!m.last_checked_at || parseSqlDate(m.last_checked_at) + m.interval_seconds * 1000 <= now)
        )
        .map(serializeMonitor);
    },
    recordCheck(monitorId, check) {
      state.seq.checks += 1;
      state.checks.push({
        id: state.seq.checks,
        monitor_id: Number(monitorId),
        status: check.status,
        status_code: check.status_code ?? null,
        latency_ms: check.latency_ms,
        error_message: check.error_message || null,
        checked_at: nowIsoSql(),
      });
      persist();
      return state.seq.checks;
    },
    updateMonitorRuntime(id, fields) {
      const m = state.monitors.find((item) => item.id === Number(id));
      if (!m) return;
      m.status = fields.status;
      m.consecutive_failures = fields.consecutive_failures;
      m.last_checked_at = nowIsoSql();
      m.last_status_code = fields.last_status_code ?? null;
      m.last_latency_ms = fields.last_latency_ms ?? null;
      m.last_error = fields.last_error || null;
      m.updated_at = nowIsoSql();
      persist();
    },
    getOpenIncident(monitorId) {
      return (
        [...state.incidents]
          .reverse()
          .find((i) => i.monitor_id === Number(monitorId) && i.status === 'open') || null
      );
    },
    createIncident(data) {
      state.seq.incidents += 1;
      const inc = {
        id: state.seq.incidents,
        monitor_id: Number(data.monitor_id),
        title: data.title,
        status: 'open',
        severity: data.severity || 'critical',
        error_type: data.error_type,
        status_code: data.status_code ?? null,
        error_message: data.error_message,
        acknowledged: 0,
        notes: '',
        started_at: nowIsoSql(),
        resolved_at: null,
        duration_seconds: null,
      };
      state.incidents.push(inc);
      persist();
      return inc;
    },
    resolveIncident(incidentId, notes) {
      const inc = state.incidents.find((i) => i.id === Number(incidentId));
      if (!inc || inc.status === 'resolved') return inc || null;
      inc.status = 'resolved';
      inc.resolved_at = nowIsoSql();
      inc.duration_seconds = Math.max(
        0,
        Math.floor((parseSqlDate(inc.resolved_at) - parseSqlDate(inc.started_at)) / 1000)
      );
      if (notes) inc.notes = notes;
      persist();
      return inc;
    },
    updateIncident(incidentId, { acknowledged, notes }) {
      const inc = state.incidents.find((i) => i.id === Number(incidentId));
      if (!inc) return null;
      if (acknowledged !== undefined) inc.acknowledged = acknowledged ? 1 : 0;
      if (notes !== undefined) inc.notes = notes;
      persist();
      return inc;
    },
    listIncidents({ status, monitorId, limit = 100 } = {}) {
      return [...state.incidents]
        .reverse()
        .filter((i) => (!status || status === 'all' || i.status === status))
        .filter((i) => (!monitorId || i.monitor_id === Number(monitorId)))
        .slice(0, Number(limit))
        .map((i) => {
          const m = state.monitors.find((mon) => mon.id === i.monitor_id);
          return { ...i, monitor_name: m?.name || '', monitor_url: m?.url || '' };
        });
    },
    recordAlertLog(entry) {
      state.seq.alert_logs += 1;
      const log = {
        id: state.seq.alert_logs,
        incident_id: entry.incident_id ?? null,
        monitor_id: Number(entry.monitor_id),
        event_type: entry.event_type,
        recipients: entry.recipients || [],
        subject: entry.subject,
        delivery_status: entry.delivery_status,
        error_message: entry.error_message || null,
        sent_at: nowIsoSql(),
      };
      state.alert_logs.push(log);
      persist();
      return log;
    },
    listAlertLogs(limit = 100) {
      return [...state.alert_logs]
        .reverse()
        .slice(0, Number(limit))
        .map((a) => {
          const m = state.monitors.find((mon) => mon.id === a.monitor_id);
          return { ...a, monitor_name: m?.name || null, monitor_url: m?.url || null };
        });
    },
    getSettings() {
      return { ...state.settings };
    },
    updateSettings(updates) {
      for (const [k, v] of Object.entries(updates)) {
        if (v !== undefined && v !== null) {
          state.settings[k] = String(v);
        }
      }
      persist();
      return this.getSettings();
    },
    pruneOldChecks(days = 30) {
      const cutoff = Date.now() - Math.max(1, Number(days)) * 86400 * 1000;
      const before = state.checks.length;
      state.checks = state.checks.filter((c) => parseSqlDate(c.checked_at) >= cutoff);
      const removed = before - state.checks.length;
      if (removed > 0) persist();
      return removed;
    },
    getSummary() {
      const active = state.monitors.filter((m) => !m.paused);
      const up = active.filter((m) => m.status === 'up').length;
      const down = active.filter((m) => m.status === 'down').length;
      const paused = state.monitors.filter((m) => m.paused).length;
      const withLat = active.filter((m) => m.last_latency_ms != null);
      const avgLat =
        withLat.length > 0
          ? Math.round(withLat.reduce((a, m) => a + m.last_latency_ms, 0) / withLat.length)
          : null;
      const openIncidents = state.incidents.filter((i) => i.status === 'open').length;
      const dayAgo = Date.now() - 86400 * 1000;
      const dayChecks = state.checks.filter((c) => parseSqlDate(c.checked_at) >= dayAgo);
      const overallUptime24h =
        dayChecks.length > 0
          ? Number(((dayChecks.filter((c) => c.status === 'up').length / dayChecks.length) * 100).toFixed(2))
          : 100;
      return {
        total_monitors: state.monitors.length,
        up_monitors: up,
        down_monitors: down,
        paused_monitors: paused,
        avg_latency_ms: avgLat,
        open_incidents: openIncidents,
        overall_uptime_24h: overallUptime24h,
      };
    },
    getUserByUsername(username) {
      return state.users.find((u) => u.username === String(username).trim()) || null;
    },
    getUserById(id) {
      return state.users.find((u) => u.id === Number(id)) || null;
    },
    updateUserPassword(userId, newPasswordHash) {
      const u = state.users.find((item) => item.id === Number(userId));
      if (!u) return false;
      u.password_hash = newPasswordHash;
      persist();
      return true;
    },
    createSession(userId, ttlHours = SESSION_TTL_HOURS) {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + Math.max(1, Number(ttlHours)) * 3600 * 1000)
        .toISOString()
        .replace('T', ' ')
        .slice(0, 19);
      state.sessions.push({
        token,
        user_id: Number(userId),
        expires_at: expiresAt,
        created_at: nowIsoSql(),
      });
      persist();
      return token;
    },
    getSession(token) {
      if (!token) return null;
      const s = state.sessions.find((item) => item.token === String(token));
      if (!s || parseSqlDate(s.expires_at) <= Date.now()) return null;
      const u = state.users.find((user) => user.id === s.user_id);
      if (!u) return null;
      return { token: s.token, user_id: s.user_id, expires_at: s.expires_at, username: u.username, role: u.role };
    },
    deleteSession(token) {
      const before = state.sessions.length;
      state.sessions = state.sessions.filter((s) => s.token !== String(token));
      if (state.sessions.length !== before) {
        persist();
        return true;
      }
      return false;
    },
    deleteUserSessions(userId) {
      state.sessions = state.sessions.filter((s) => s.user_id !== Number(userId));
      persist();
    },
    pruneExpiredSessions() {
      const now = Date.now();
      const before = state.sessions.length;
      state.sessions = state.sessions.filter((s) => parseSqlDate(s.expires_at) > now);
      if (state.sessions.length !== before) persist();
    },
    close() {
      persist();
    },
  };
}

module.exports = { createJsonStore };
