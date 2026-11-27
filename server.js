const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');

// Load .env if present (Node 24 built-in, with fallback for older Node 22)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  if (typeof process.loadEnvFile === 'function') {
    process.loadEnvFile(envPath);
  } else {
    for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
      if (key && process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
  }
}
const { createDatabase } = require('./src/db');
const { createMailer } = require('./src/mailer');
const { createMonitorEngine } = require('./src/monitorEngine');
const { createApiRouter } = require('./src/routes');

function createApp(options = {}) {
  const tmpDbPath = path.join(os.tmpdir(), 'uptime-sentinel', 'monitor.db');
  let dbPath = options.dbPath || process.env.DB_PATH || path.join(__dirname, 'data', 'monitor.db');
  if (process.env.VERCEL && dbPath !== ':memory:' && !dbPath.startsWith(os.tmpdir())) {
    dbPath = tmpDbPath;
  }
  const store = createDatabase(dbPath, {
    adminUsername: options.adminUsername,
    adminPassword: options.adminPassword,
    forceJsonStore: options.forceJsonStore,
  });
  const mailer = createMailer(store, { transport: options.transport });
  const engine = createMonitorEngine(store, mailer, {
    tickMs: options.tickMs ?? 5000,
    emitEvents: options.emitEvents !== false,
  });

  const app = express();
  // Trust reverse proxy (Hostinger Nginx/LiteSpeed SSL termination)
  app.set('trust proxy', 1);

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use('/api', createApiRouter({ store, engine, mailer }));

  app.get('/{*splat}', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // Global error handler (prevents leaking stack traces in production)
  app.use((err, _req, res, _next) => {
    console.error('[server] unhandled error:', err);
    if (res.headersSent) return;
    res.status(err?.status || 500).json({ error: 'Internal server error' });
  });

  return { app, store, mailer, engine };
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const { app, store, engine } = createApp();

  const server = app.listen(port, () => {
    console.log(`Uptime Sentinel running at http://localhost:${port}`);
    engine.start();
  });

  function shutdown() {
    console.log('\nShutting down Uptime Sentinel...');
    engine.stop();
    server.close(() => {
      store.close();
      process.exit(0);
    });
  }

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (process.env.VERCEL) {
  let cachedApp = null;
  let initError = null;
  try {
    cachedApp = createApp().app;
  } catch (err) {
    initError = err;
    console.error('[vercel] Failed to initialize Express app:', err);
  }
  const vercelHandler = (req, res) => {
    if (initError || !cachedApp) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Server initialization failed', details: initError?.message || 'Unknown' }));
      return;
    }
    return cachedApp(req, res);
  };
  vercelHandler.createApp = createApp;
  module.exports = vercelHandler;
} else {
  module.exports = { createApp };
}
