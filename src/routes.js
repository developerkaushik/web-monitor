const express = require('express');
const { addClient, broadcast } = require('./events');
const {
  verifyPassword,
  hashPassword,
  signSessionToken,
  verifySessionToken,
  revokeSessionToken,
  extractToken,
  requireAuth,
  buildSessionCookie,
  SESSION_COOKIE,
} = require('./auth');

/**
 * Validates HTTP/HTTPS URLs.
 * @param {string} rawUrl
 * @returns {boolean}
 */
function isValidHttpUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Creates the API router.
 * @param {{ store: ReturnType<import('./db').createDatabase>, engine: ReturnType<import('./monitorEngine').createMonitorEngine>, mailer: ReturnType<import('./mailer').createMailer> }} deps
 */
function createApiRouter({ store, engine, mailer }) {
  const router = express.Router();

  // Simple in-memory rate limiter for login attempts (15 attempts / 15 min per IP)
  const loginAttempts = new Map();
  function checkLoginRateLimit(ip) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const entry = loginAttempts.get(ip);
    if (!entry || now - entry.windowStart > windowMs) {
      loginAttempts.set(ip, { count: 1, windowStart: now });
      return true;
    }
    entry.count += 1;
    return entry.count <= 15;
  }

  router.get('/health', (_req, res) => {
    const hasPg = Boolean(
      process.env.DATABASE_URL ||
        process.env.POSTGRES_URL ||
        process.env.POSTGRES_URL_NON_POOLING ||
        process.env.NEON_DATABASE_URL
    );
    res.json({
      ok: true,
      storage: hasPg ? 'postgres' : 'local',
      timestamp: new Date().toISOString(),
    });
  });

  // Serverless Cron endpoint (e.g. Vercel Cron or cron-job.org)
  async function handleCronCheck(req, res) {
    const cronSecret = process.env.CRON_SECRET;
    if (cronSecret) {
      const authHeader = req.headers.authorization || '';
      const querySecret = req.query?.secret || '';
      const validBearer = authHeader === `Bearer ${cronSecret}`;
      const validQuery = querySecret === cronSecret;
      if (!validBearer && !validQuery) {
        return res.status(401).json({ error: 'Invalid cron secret' });
      }
    }
    const checked = await engine.tick();
    res.json({ ok: true, checked, timestamp: new Date().toISOString() });
  }

  router.get('/cron/check', handleCronCheck);
  router.post('/cron/check', handleCronCheck);

  router.post('/auth/login', async (req, res) => {
    if (!checkLoginRateLimit(req.ip || 'unknown')) {
      return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await store.getUserByUsername(String(username));
    if (!user || !verifyPassword(String(password), user.password_hash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    await store.pruneExpiredSessions();
    const token = signSessionToken(user);
    res.setHeader('Set-Cookie', buildSessionCookie(token, req));
    res.json({
      user: { id: user.id, username: user.username, role: user.role },
    });
  });

  router.post('/auth/logout', async (req, res) => {
    const token = extractToken(req);
    if (token) {
      revokeSessionToken(token);
      await store.deleteSession(token);
    }
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.json({ ok: true });
  });

  router.get('/auth/me', async (req, res) => {
    const token = extractToken(req);
    const session = token ? verifySessionToken(token) || (await store.getSession(token)) : null;
    if (!session) {
      return res.status(401).json({ authenticated: false });
    }
    res.json({
      authenticated: true,
      user: { id: session.user_id, username: session.username, role: session.role },
    });
  });

  // Protect all monitoring, incident, alert, settings, and SSE routes
  router.use(requireAuth(store));

  router.post('/auth/change-password', async (req, res) => {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    if (String(new_password).length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const user = await store.getUserById(req.user.id);
    if (!user || !verifyPassword(String(current_password), user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    await store.updateUserPassword(user.id, hashPassword(String(new_password)));
    res.json({ ok: true });
  });

  router.get('/events', (req, res) => {
    if (process.env.VERCEL) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
      });
      res.write(`event: connected\ndata: ${JSON.stringify({ mode: 'poll', ts: new Date().toISOString() })}\n\n`);
      res.end();
      return;
    }
    addClient(res);
    req.on('close', () => {});
  });

  router.get('/summary', async (_req, res) => {
    res.json(await store.getSummary());
  });

  router.get('/monitors', async (_req, res) => {
    res.json(await store.listMonitors());
  });

  router.post('/monitors/check-due', async (_req, res) => {
    const checked = await engine.tick();
    res.json({ ok: true, checked });
  });

  router.get('/monitors/:id', async (req, res) => {
    const id = Number(req.params.id);
    const monitor = await store.getMonitorById(id);
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' });
    res.json(monitor);
  });

  router.post('/monitors', async (req, res) => {
    const { name, url, interval_seconds, timeout_ms, expected_status, failure_threshold } = req.body || {};
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Monitor name is required' });
    }
    if (!url || !isValidHttpUrl(String(url).trim())) {
      return res.status(400).json({ error: 'A valid http:// or https:// URL is required' });
    }
    if (interval_seconds !== undefined && Number(interval_seconds) < 5) {
      return res.status(400).json({ error: 'Interval must be at least 5 seconds' });
    }
    if (timeout_ms !== undefined && Number(timeout_ms) < 500) {
      return res.status(400).json({ error: 'Timeout must be at least 500 ms' });
    }
    if (expected_status !== undefined && (Number(expected_status) < 100 || Number(expected_status) > 599)) {
      return res.status(400).json({ error: 'Expected status must be between 100 and 599' });
    }
    if (failure_threshold !== undefined && Number(failure_threshold) < 1) {
      return res.status(400).json({ error: 'Failure threshold must be at least 1' });
    }

    const created = await store.createMonitor(req.body);
    broadcast('monitor:created', created);

    // On serverless (Vercel), await the initial check before returning so it finishes before freeze
    if (!created.paused) {
      if (process.env.VERCEL) {
        await engine.checkMonitor(created.id).catch((err) => {
          console.error('[routes] initial check error:', err);
        });
      } else {
        engine.checkMonitor(created.id).catch((err) => {
          console.error('[routes] initial check error:', err);
        });
      }
    }

    res.status(201).json(await store.getMonitorById(created.id));
  });

  router.put('/monitors/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (req.body?.url !== undefined && !isValidHttpUrl(String(req.body.url).trim())) {
      return res.status(400).json({ error: 'A valid http:// or https:// URL is required' });
    }
    if (req.body?.interval_seconds !== undefined && Number(req.body.interval_seconds) < 5) {
      return res.status(400).json({ error: 'Interval must be at least 5 seconds' });
    }
    const updated = await store.updateMonitor(id, req.body || {});
    if (!updated) return res.status(404).json({ error: 'Monitor not found' });
    broadcast('monitor:updated', updated);
    res.json(updated);
  });

  router.delete('/monitors/:id', async (req, res) => {
    const id = Number(req.params.id);
    const deleted = await store.deleteMonitor(id);
    if (!deleted) return res.status(404).json({ error: 'Monitor not found' });
    broadcast('monitor:deleted', { id });
    res.json({ deleted: true, id });
  });

  router.post('/monitors/:id/check', async (req, res) => {
    const id = Number(req.params.id);
    const monitor = await store.getMonitorById(id);
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' });

    const outcome = await engine.checkMonitor(id);
    const fresh = await store.getMonitorById(id);
    res.json({ monitor: fresh, outcome });
  });

  router.post('/monitors/:id/toggle', async (req, res) => {
    const id = Number(req.params.id);
    const monitor = await store.getMonitorById(id);
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' });
    const updated = await store.updateMonitor(id, { paused: !monitor.paused });
    broadcast('monitor:updated', updated);
    res.json(updated);
  });

  router.get('/incidents', async (req, res) => {
    const { status, monitorId, limit } = req.query;
    res.json(
      await store.listIncidents({
        status: status ? String(status) : 'all',
        monitorId: monitorId ? Number(monitorId) : undefined,
        limit: limit ? Number(limit) : 100,
      })
    );
  });

  router.patch('/incidents/:id', async (req, res) => {
    const id = Number(req.params.id);
    const { acknowledged, notes, resolve } = req.body || {};

    let incident = null;
    if (resolve) {
      incident = await store.resolveIncident(id, notes);
    } else {
      incident = await store.updateIncident(id, { acknowledged, notes });
    }

    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    broadcast('incident:updated', incident);
    res.json(incident);
  });

  router.get('/alerts', async (req, res) => {
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    res.json(await store.listAlertLogs(limit));
  });

  router.get('/settings', async (_req, res) => {
    const settings = await store.getSettings();
    const hasPassword = Boolean(settings.smtp_pass);
    res.json({
      ...settings,
      smtp_pass: '',
      has_smtp_pass: hasPassword,
    });
  });

  router.put('/settings', async (req, res) => {
    const allowedKeys = [
      'smtp_host',
      'smtp_port',
      'smtp_secure',
      'smtp_user',
      'smtp_pass',
      'smtp_from',
      'global_alert_emails',
      'notify_on_recovery',
      'retention_days',
    ];
    const updates = {};
    for (const key of allowedKeys) {
      if (req.body?.[key] !== undefined) {
        // Keep existing password if blank string is sent
        if (key === 'smtp_pass' && req.body[key] === '') continue;
        updates[key] = req.body[key];
      }
    }
    const saved = await store.updateSettings(updates);
    res.json({
      ...saved,
      smtp_pass: '',
      has_smtp_pass: Boolean(saved.smtp_pass),
    });
  });

  router.post('/settings/test-email', async (req, res) => {
    const { recipients } = req.body || {};
    const result = await mailer.sendTestEmail(recipients);
    res.json(result);
  });

  return router;
}

module.exports = { createApiRouter, isValidHttpUrl };
