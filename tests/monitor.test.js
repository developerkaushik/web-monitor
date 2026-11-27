const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApp } = require('../server');

function createMockTransport() {
  const sent = [];
  return {
    sent,
    async sendMail(mail) {
      sent.push(mail);
      return { messageId: `mock-${sent.length}` };
    },
  };
}

function startTargetServer() {
  let mode = 'up';
  const server = http.createServer((req, res) => {
    if (mode === 'up') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('service healthy');
    } else if (mode === 'bad_keyword') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('service degraded');
    } else if (mode === 'down') {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Service Unavailable');
    } else if (mode === 'db_error_200') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Error establishing a database connection</h1></body></html>');
    } else if (mode === 'db_error_500') {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('SQLSTATE[HY000] [2002] Connection refused');
    } else if (mode === 'db_error_json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', database: 'disconnected' }));
    } else if (mode === 'timeout') {
      // Never respond within short timeout
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200);
          res.end('late');
        }
      }, 2000);
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        url: `http://127.0.0.1:${addr.port}/health`,
        setMode(next) {
          mode = next;
        },
        close() {
          return new Promise((r) => server.close(r));
        },
      });
    });
  });
}

test('Monitor engine captures incidents and sends multi-recipient emails on down & recovery', async () => {
  const target = await startTargetServer();
  const transport = createMockTransport();
  const { store, engine } = createApp({
    dbPath: ':memory:',
    transport,
    emitEvents: false,
  });

  try {
    store.updateSettings({
      smtp_host: 'smtp.test.local',
      smtp_from: 'alerts@test.local',
      global_alert_emails: 'oncall@example.com, ops@example.com',
    });

    const monitor = store.createMonitor({
      name: 'Test API',
      url: target.url,
      interval_seconds: 30,
      timeout_ms: 600,
      expected_status: 200,
      keyword: 'healthy',
      failure_threshold: 2,
      alert_emails: ['dev@example.com', 'ops@example.com'], // ops@ overlaps with global -> should dedupe
    });

    // 1. Healthy check
    const check1 = await engine.checkMonitor(monitor.id);
    assert.equal(check1.result.ok, true);
    assert.equal(store.getMonitorById(monitor.id).status, 'up');
    assert.equal(transport.sent.length, 0);

    // 2. First failure (below threshold of 2 -> no incident yet)
    target.setMode('down');
    const check2 = await engine.checkMonitor(monitor.id);
    assert.equal(check2.result.ok, false);
    assert.equal(check2.openedIncident, null);
    assert.equal(store.listIncidents({ status: 'open' }).length, 0);

    // 3. Second consecutive failure -> opens incident & sends multi-recipient email
    const check3 = await engine.checkMonitor(monitor.id);
    assert.equal(check3.result.ok, false);
    assert.ok(check3.openedIncident);
    assert.equal(check3.openedIncident.error_type, 'HTTP_STATUS');
    assert.equal(check3.openedIncident.status_code, 503);
    assert.equal(store.getMonitorById(monitor.id).status, 'down');

    assert.equal(transport.sent.length, 1);
    assert.match(transport.sent[0].subject, /\[DOWN\] Test API/);
    assert.equal(transport.sent[0].to, 'dev@example.com, ops@example.com, oncall@example.com');

    // 4. Third failure while still down -> should NOT duplicate incident or spam emails
    const check4 = await engine.checkMonitor(monitor.id);
    assert.equal(check4.openedIncident, null);
    assert.equal(store.listIncidents({ status: 'open' }).length, 1);
    assert.equal(transport.sent.length, 1);

    // 5. Recovery -> resolves incident & sends recovery email to all recipients
    target.setMode('up');
    const check5 = await engine.checkMonitor(monitor.id);
    assert.equal(check5.result.ok, true);
    assert.ok(check5.resolvedIncident);
    assert.equal(check5.resolvedIncident.status, 'resolved');
    assert.equal(store.getMonitorById(monitor.id).status, 'up');

    assert.equal(transport.sent.length, 2);
    assert.match(transport.sent[1].subject, /\[RESOLVED\] Test API/);
    assert.equal(transport.sent[1].to, 'dev@example.com, ops@example.com, oncall@example.com');

    // 6. Keyword mismatch detection
    target.setMode('bad_keyword');
    const check6 = await engine.checkMonitor(monitor.id);
    assert.equal(check6.result.ok, false);
    assert.equal(check6.result.error_type, 'KEYWORD_MISMATCH');

    // 7. Timeout detection
    target.setMode('timeout');
    const check7 = await engine.checkMonitor(monitor.id);
    assert.equal(check7.result.ok, false);
    assert.equal(check7.result.error_type, 'TIMEOUT');
  } finally {
    store.close();
    await target.close();
  }
});

test('JSON fallback store works identically when node:sqlite is unavailable (Node 18/20/22)', async () => {
  const target = await startTargetServer();
  const transport = createMockTransport();
  const { app, store, engine } = createApp({
    dbPath: ':memory:',
    forceJsonStore: true,
    transport,
    emitEvents: false,
    adminUsername: 'admin',
    adminPassword: 'json-password',
  });

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'json-password' }),
    });
    assert.equal(loginRes.status, 200);
    const cookieHeader = loginRes.headers.get('set-cookie').split(';')[0];

    const m = store.createMonitor({
      name: 'Hostinger Target',
      url: target.url,
      alert_emails: ['a@example.com', 'b@example.com'],
    });
    target.setMode('db_error_200');
    const outcome = await engine.checkMonitor(m.id);
    assert.equal(outcome.result.ok, false);
    assert.equal(outcome.result.error_type, 'DB_ERROR');
    assert.ok(outcome.openedIncident);

    const incRes = await fetch(`${baseUrl}/api/incidents`, { headers: { Cookie: cookieHeader } });
    assert.equal(incRes.status, 200);
    const incidents = await incRes.json();
    assert.equal(incidents.length, 1);
  } finally {
    await new Promise((r) => server.close(r));
    store.close();
    await target.close();
  }
});

test('REST API requires admin login and supports CRUD, validation, password change, and logout', async () => {
  const target = await startTargetServer();
  const transport = createMockTransport();
  const { app, store } = createApp({
    dbPath: ':memory:',
    transport,
    emitEvents: false,
    adminUsername: 'admin',
    adminPassword: 'initial-password',
  });

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // 1. Unauthenticated requests must be rejected with 401
    for (const endpoint of ['/api/monitors', '/api/incidents', '/api/summary', '/api/alerts', '/api/settings', '/api/auth/me']) {
      const unauthRes = await fetch(`${baseUrl}${endpoint}`);
      assert.equal(unauthRes.status, 401, `Expected 401 for unauthenticated ${endpoint}`);
    }

    // 2. Invalid login must fail with 401
    const badLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
    });
    assert.equal(badLogin.status, 401);

    // 3. Valid login sets HttpOnly session cookie
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'initial-password' }),
    });
    assert.equal(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.equal(loginData.user.username, 'admin');

    const setCookie = loginRes.headers.get('set-cookie');
    assert.ok(setCookie && setCookie.includes('us_session='));
    assert.ok(setCookie.includes('HttpOnly'));
    const cookieHeader = setCookie.split(';')[0];

    // Validation failure (authenticated)
    const badRes = await fetch(`${baseUrl}/api/monitors`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({ name: 'Bad', url: 'ftp://invalid.local' }),
    });
    assert.equal(badRes.status, 400);

    // Create valid monitor (authenticated)
    const createRes = await fetch(`${baseUrl}/api/monitors`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({
        name: 'Checkout Web',
        url: target.url,
        interval_seconds: 30,
        alert_emails: ['team1@example.com', 'team2@example.com'],
      }),
    });
    assert.equal(createRes.status, 201);
    const created = await createRes.json();
    assert.equal(created.name, 'Checkout Web');
    assert.deepEqual(created.alert_emails, ['team1@example.com', 'team2@example.com']);

    // Manual check
    const checkRes = await fetch(`${baseUrl}/api/monitors/${created.id}/check`, {
      method: 'POST',
      headers: { Cookie: cookieHeader },
    });
    assert.equal(checkRes.status, 200);
    const checked = await checkRes.json();
    assert.equal(checked.monitor.status, 'up');

    // Settings update & password masking
    await fetch(`${baseUrl}/api/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({
        smtp_host: 'smtp.example.com',
        smtp_pass: 'super-secret',
        global_alert_emails: 'a@example.com, b@example.com',
      }),
    });
    const settingsRes = await fetch(`${baseUrl}/api/settings`, {
      headers: { Cookie: cookieHeader },
    });
    const settings = await settingsRes.json();
    assert.equal(settings.smtp_pass, '');
    assert.equal(settings.has_smtp_pass, true);

    // Test email endpoint
    const testEmailRes = await fetch(`${baseUrl}/api/settings/test-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({ recipients: ['c@example.com'] }),
    });
    const testEmail = await testEmailRes.json();
    assert.equal(testEmail.delivery_status, 'sent');
    assert.deepEqual(testEmail.recipients, ['c@example.com', 'a@example.com', 'b@example.com']);

    // Change password
    const changePwRes = await fetch(`${baseUrl}/api/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({
        current_password: 'initial-password',
        new_password: 'updated-password-123',
      }),
    });
    assert.equal(changePwRes.status, 200);

    // Logout invalidates session
    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: cookieHeader },
    });
    assert.equal(logoutRes.status, 200);

    const afterLogoutRes = await fetch(`${baseUrl}/api/monitors`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(afterLogoutRes.status, 401);

    // Old password rejected, new password accepted
    const oldPwLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'initial-password' }),
    });
    assert.equal(oldPwLogin.status, 401);

    const newPwLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'updated-password-123' }),
    });
    assert.equal(newPwLogin.status, 200);
  } finally {
    await new Promise((r) => server.close(r));
    store.close();
    await target.close();
  }
});

test('Captures database connection errors (HTTP 200, HTTP 500, and JSON health) and notifies multiple emails', async () => {
  const target = await startTargetServer();
  const transport = createMockTransport();
  const { store, engine } = createApp({
    dbPath: ':memory:',
    transport,
    emitEvents: false,
  });

  try {
    store.updateSettings({
      smtp_host: 'smtp.test.local',
      smtp_from: 'alerts@test.local',
      global_alert_emails: 'dba@example.com',
    });

    const monitor = store.createMonitor({
      name: 'Customer Portal',
      url: target.url,
      interval_seconds: 30,
      timeout_ms: 1000,
      expected_status: 200,
      failure_threshold: 1,
      alert_emails: ['backend@example.com', 'oncall@example.com'],
    });

    // 1. WordPress/HTML DB error returned with HTTP 200
    target.setMode('db_error_200');
    const c1 = await engine.checkMonitor(monitor.id);
    assert.equal(c1.result.ok, false);
    assert.equal(c1.result.error_type, 'DB_ERROR');
    assert.match(c1.result.error_message, /Database connection error/i);
    assert.ok(c1.openedIncident);
    assert.equal(c1.openedIncident.error_type, 'DB_ERROR');
    assert.equal(transport.sent.length, 1);
    assert.match(transport.sent[0].subject, /DB_ERROR/);
    assert.equal(transport.sent[0].to, 'backend@example.com, oncall@example.com, dba@example.com');

    // Recover
    target.setMode('up');
    await engine.checkMonitor(monitor.id);
    assert.equal(transport.sent.length, 2);

    // 2. SQLSTATE DB error returned with HTTP 500
    target.setMode('db_error_500');
    const c2 = await engine.checkMonitor(monitor.id);
    assert.equal(c2.result.ok, false);
    assert.equal(c2.result.error_type, 'DB_ERROR');
    assert.match(c2.result.error_message, /HTTP 500.*SQLSTATE/);
    assert.equal(transport.sent.length, 3);

    // Recover
    target.setMode('up');
    await engine.checkMonitor(monitor.id);
    assert.equal(transport.sent.length, 4);

    // 3. JSON health endpoint reporting database disconnected
    target.setMode('db_error_json');
    const c3 = await engine.checkMonitor(monitor.id);
    assert.equal(c3.result.ok, false);
    assert.equal(c3.result.error_type, 'DB_ERROR');
    assert.match(c3.result.error_message, /database status "disconnected"/i);
    assert.equal(transport.sent.length, 5);
  } finally {
    store.close();
    await target.close();
  }
});

test('JSON fallback store works identically when node:sqlite is unavailable (Node 18/20/22)', async () => {
  const target = await startTargetServer();
  const transport = createMockTransport();
  const { app, store, engine } = createApp({
    dbPath: ':memory:',
    forceJsonStore: true,
    transport,
    emitEvents: false,
    adminUsername: 'admin',
    adminPassword: 'json-password',
  });

  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'json-password' }),
    });
    assert.equal(loginRes.status, 200);
    const cookieHeader = loginRes.headers.get('set-cookie').split(';')[0];

    const m = store.createMonitor({
      name: 'Hostinger Target',
      url: target.url,
      alert_emails: ['a@example.com', 'b@example.com'],
    });
    target.setMode('db_error_200');
    const outcome = await engine.checkMonitor(m.id);
    assert.equal(outcome.result.ok, false);
    assert.equal(outcome.result.error_type, 'DB_ERROR');
    assert.ok(outcome.openedIncident);

    const incRes = await fetch(`${baseUrl}/api/incidents`, { headers: { Cookie: cookieHeader } });
    assert.equal(incRes.status, 200);
    const incidents = await incRes.json();
    assert.equal(incidents.length, 1);
  } finally {
    await new Promise((r) => server.close(r));
    store.close();
    await target.close();
  }
});
