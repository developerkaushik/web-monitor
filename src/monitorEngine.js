const { broadcast } = require('./events');

const DB_ERROR_PATTERNS = [
  { label: 'Database connection error', regex: /error establishing a database connection/i },
  { label: 'Database connection failed', regex: /database connection (?:failed|error|lost|refused|timed out)/i },
  { label: 'Unable to connect to database', regex: /unable to connect to (?:the )?database/i },
  { label: 'SQLSTATE database error', regex: /SQLSTATE\[[0-9A-Z]+\]/i },
  { label: 'MySQL connection error', regex: /(?:mysqli?_connect|MySQL server has gone away|Too many connections|Access denied for user|Unknown database)/i },
  { label: 'PostgreSQL connection error', regex: /(?:could not connect to server|PG::ConnectionBad|remaining connection slots are reserved|FATAL:\s+.*database)/i },
  { label: 'Prisma/Sequelize DB error', regex: /(?:PrismaClientInitializationError|SequelizeConnectionError|SequelizeConnectionRefusedError)/i },
  { label: 'MongoDB connection error', regex: /(?:MongoServerSelectionError|MongoNetworkError)/i },
  { label: 'SQLite database error', regex: /(?:SQLITE_CANTOPEN|SQLITE_BUSY|SQLITE_CORRUPT)/i },
  { label: 'Oracle database error', regex: /\bORA-\d{4,5}\b/ },
  { label: 'Database port connection refused', regex: /ECONNREFUSED[^\n]*(?:5432|3306|27017|6379|1433)/i },
];

/**
 * Inspects an HTTP response body (HTML, text, or JSON) for database or backend fatal errors.
 * @param {string} body
 * @param {string} contentType
 * @returns {{ error_type: 'DB_ERROR'|'APP_ERROR', message: string } | null}
 */
function detectResponseError(body, contentType = '') {
  if (!body) return null;
  const sample = body.slice(0, 200000);

  for (const pattern of DB_ERROR_PATTERNS) {
    const match = sample.match(pattern.regex);
    if (match) {
      return {
        error_type: 'DB_ERROR',
        message: `${pattern.label}: "${match[0]}"`,
      };
    }
  }

  if (contentType.toLowerCase().includes('application/json')) {
    try {
      const json = JSON.parse(sample);
      const dbField = json?.db ?? json?.database ?? json?.postgres ?? json?.mysql ?? json?.mongodb ?? json?.redis;
      if (typeof dbField === 'string' && /^(down|error|disconnected|failed|unhealthy)$/i.test(dbField.trim())) {
        return {
          error_type: 'DB_ERROR',
          message: `Health JSON reported database status "${dbField}"`,
        };
      }
      if (dbField && typeof dbField === 'object' && /^(down|error|disconnected|failed|unhealthy)$/i.test(String(dbField.status || dbField.state || '').trim())) {
        return {
          error_type: 'DB_ERROR',
          message: `Health JSON reported database error${dbField.error ? `: ${dbField.error}` : ''}`,
        };
      }
      const appStatus = json?.status ?? json?.state;
      if (typeof appStatus === 'string' && /^(error|down|unhealthy|failed)$/i.test(appStatus.trim())) {
        return {
          error_type: 'APP_ERROR',
          message: `Health JSON reported status "${appStatus}"${json.error || json.message ? ` (${json.error || json.message})` : ''}`,
        };
      }
    } catch {
      // Ignore invalid JSON payloads
    }
  }

  return null;
}

/**
 * Performs a single HTTP/HTTPS probe against a monitor target.
 * @param {object} monitor
 * @returns {Promise<{ok: boolean, status: 'up'|'down', status_code: number|null, latency_ms: number, error_type: string|null, error_message: string|null}>}
 */
async function performHttpCheck(monitor) {
  const controller = new AbortController();
  const timeoutMs = Math.max(500, Number(monitor.timeout_ms || 10000));
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = performance.now();

  try {
    const method = (monitor.method || 'GET').toUpperCase();
    const response = await fetch(monitor.url, {
      method,
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'UptimeSentinel/1.0 (+https://uptime-sentinel.local)',
        Accept: '*/*',
      },
    });

    const latencyMs = Math.max(1, Math.round(performance.now() - start));
    const expected = Number(monitor.expected_status || 200);
    const contentType = response.headers.get('content-type') || '';
    const inspectBody = monitor.detect_db_errors !== false;
    const body = method !== 'HEAD' && (inspectBody || monitor.keyword) ? await response.text() : '';
    const detected = inspectBody ? detectResponseError(body, contentType) : null;

    if (response.status !== expected) {
      if (detected) {
        return {
          ok: false,
          status: 'down',
          status_code: response.status,
          latency_ms: latencyMs,
          error_type: detected.error_type,
          error_message: `HTTP ${response.status} — ${detected.message}`,
        };
      }
      return {
        ok: false,
        status: 'down',
        status_code: response.status,
        latency_ms: latencyMs,
        error_type: 'HTTP_STATUS',
        error_message: `Expected HTTP ${expected}, received HTTP ${response.status} ${response.statusText || ''}`.trim(),
      };
    }

    if (detected) {
      return {
        ok: false,
        status: 'down',
        status_code: response.status,
        latency_ms: latencyMs,
        error_type: detected.error_type,
        error_message: detected.message,
      };
    }

    if (monitor.keyword && !body.includes(monitor.keyword)) {
      return {
        ok: false,
        status: 'down',
        status_code: response.status,
        latency_ms: latencyMs,
        error_type: 'KEYWORD_MISMATCH',
        error_message: `Response body missing expected keyword "${monitor.keyword}"`,
      };
    }

    return {
      ok: true,
      status: 'up',
      status_code: response.status,
      latency_ms: latencyMs,
      error_type: null,
      error_message: null,
    };
  } catch (err) {
    const latencyMs = Math.max(1, Math.round(performance.now() - start));
    const isTimeout = err?.name === 'AbortError' || err?.code === 'ABORT_ERR';
    const causeMsg = err?.cause?.message ? ` (${err.cause.message})` : '';
    return {
      ok: false,
      status: 'down',
      status_code: null,
      latency_ms: latencyMs,
      error_type: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR',
      error_message: isTimeout
        ? `Request timed out after ${timeoutMs}ms`
        : `${err?.message || 'Network failure'}${causeMsg}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Creates the background monitoring engine.
 * @param {ReturnType<import('./db').createDatabase>} store
 * @param {ReturnType<import('./mailer').createMailer>} mailer
 * @param {{ tickMs?: number, emitEvents?: boolean }} [options]
 */
function createMonitorEngine(store, mailer, options = {}) {
  const tickMs = options.tickMs ?? 5000;
  const emitEvents = options.emitEvents !== false;
  const inFlight = new Map();
  let intervalHandle = null;
  let pruneHandle = null;

  async function checkMonitor(monitorOrId) {
    const monitor =
      typeof monitorOrId === 'number' ? store.getMonitorById(monitorOrId) : monitorOrId;
    if (!monitor) return null;
    if (inFlight.has(monitor.id)) return inFlight.get(monitor.id);

    const promise = (async () => {
      const result = await performHttpCheck(monitor);
      store.recordCheck(monitor.id, {
        status: result.status,
        status_code: result.status_code,
        latency_ms: result.latency_ms,
        error_message: result.error_message,
      });

      let openedIncident = null;
      let resolvedIncident = null;
      let alertLog = null;

      if (result.ok) {
        store.updateMonitorRuntime(monitor.id, {
          status: 'up',
          consecutive_failures: 0,
          last_status_code: result.status_code,
          last_latency_ms: result.latency_ms,
          last_error: null,
        });

        const openIncident = store.getOpenIncident(monitor.id);
        if (openIncident) {
          resolvedIncident = store.resolveIncident(openIncident.id);
          alertLog = await mailer.sendRecoveryAlert(monitor, resolvedIncident);
          if (emitEvents) {
            broadcast('incident:resolved', { monitorId: monitor.id, incident: resolvedIncident, alertLog });
          }
        }
      } else {
        const failures = (monitor.consecutive_failures || 0) + 1;
        const threshold = Math.max(1, Number(monitor.failure_threshold || 1));
        const reachedThreshold = failures >= threshold;
        const nextStatus = reachedThreshold ? 'down' : monitor.status || 'unknown';

        store.updateMonitorRuntime(monitor.id, {
          status: nextStatus,
          consecutive_failures: failures,
          last_status_code: result.status_code,
          last_latency_ms: result.latency_ms,
          last_error: result.error_message,
        });

        if (reachedThreshold) {
          const existingOpen = store.getOpenIncident(monitor.id);
          if (!existingOpen) {
            openedIncident = store.createIncident({
              monitor_id: monitor.id,
              title: `${monitor.name} is down`,
              severity: 'critical',
              error_type: result.error_type || 'UNKNOWN',
              status_code: result.status_code,
              error_message: result.error_message || 'Monitor check failed',
            });
            alertLog = await mailer.sendDownAlert(monitor, openedIncident);
            if (emitEvents) {
              broadcast('incident:opened', { monitorId: monitor.id, incident: openedIncident, alertLog });
            }
          }
        }
      }

      if (emitEvents) {
        const updated = store.getMonitorById(monitor.id);
        broadcast('monitor:checked', {
          monitor: updated,
          check: result,
        });
      }

      return { result, openedIncident, resolvedIncident, alertLog };
    })().finally(() => {
      inFlight.delete(monitor.id);
    });

    inFlight.set(monitor.id, promise);
    return promise;
  }

  let lastSystemAlertAt = 0;

  async function notifySystemError(component, err) {
    const now = Date.now();
    // Throttle repeated system/DB alerts to once per 15 minutes
    if (now - lastSystemAlertAt < 15 * 60 * 1000) return;
    lastSystemAlertAt = now;
    try {
      await mailer.sendSystemErrorAlert({
        component,
        errorType: err?.code || 'INTERNAL_DB_ERROR',
        message: err?.message || String(err),
      });
    } catch (mailErr) {
      console.error('[monitorEngine] failed to send system error alert:', mailErr);
    }
  }

  async function tick() {
    try {
      const due = store.getDueMonitors();
      if (due.length === 0) return;
      await Promise.allSettled(due.map((m) => checkMonitor(m)));
    } catch (err) {
      console.error('[monitorEngine] tick error:', err);
      await notifySystemError('Monitor Scheduler / SQLite', err);
    }
  }

  function start() {
    if (intervalHandle) return;
    // Run initial tick shortly after startup
    setTimeout(() => {
      tick().catch((err) => console.error('[monitorEngine] initial tick error:', err));
    }, 500);

    intervalHandle = setInterval(() => {
      tick().catch((err) => console.error('[monitorEngine] tick error:', err));
    }, tickMs);

    pruneHandle = setInterval(() => {
      try {
        const settings = store.getSettings();
        store.pruneOldChecks(Number(settings.retention_days || 30));
      } catch (err) {
        console.error('[monitorEngine] prune error:', err);
      }
    }, 6 * 60 * 60 * 1000);
  }

  function stop() {
    if (intervalHandle) {
      clearInterval(intervalHandle);
      intervalHandle = null;
    }
    if (pruneHandle) {
      clearInterval(pruneHandle);
      pruneHandle = null;
    }
  }

  return {
    performHttpCheck,
    checkMonitor,
    tick,
    start,
    stop,
  };
}

module.exports = { createMonitorEngine, performHttpCheck, detectResponseError };
