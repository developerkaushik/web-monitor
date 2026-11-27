const { createApp } = require('../server');

let cachedApp = null;
let initError = null;

try {
  const instance = createApp();
  cachedApp = instance.app;
} catch (err) {
  initError = err;
  console.error('[vercel] Failed to initialize Express app:', err);
}

module.exports = (req, res) => {
  if (initError || !cachedApp) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: 'Server initialization failed',
        details: initError?.message || 'Unknown error',
      })
    );
    return;
  }
  return cachedApp(req, res);
};
