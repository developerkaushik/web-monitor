const state = {
  user: null,
  monitors: [],
  incidents: [],
  alerts: [],
  summary: null,
  settings: null,
  activeTab: 'monitors',
  monitorFilter: 'all',
  monitorSearch: '',
  incidentFilter: 'all',
};

let sseSource = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  $('#toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return 'Ongoing';
  const s = Math.max(0, Number(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  if (m < 60) return `${m}m ${remS}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !url.startsWith('/api/auth/')) {
    exitDashboard();
    throw new Error(data.error || 'Session expired. Please sign in.');
  }
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

async function loadAll() {
  const [summary, monitors, incidents, alerts, settings] = await Promise.all([
    api('/api/summary'),
    api('/api/monitors'),
    api(`/api/incidents?status=${state.incidentFilter}`),
    api('/api/alerts'),
    api('/api/settings'),
  ]);
  state.summary = summary;
  state.monitors = monitors;
  state.incidents = incidents;
  state.alerts = alerts;
  state.settings = settings;
  renderAll();
}

function renderAll() {
  renderKPIs();
  renderMonitors();
  renderIncidents();
  renderAlerts();
  renderSettings();
}

function renderKPIs() {
  const s = state.summary || {};
  const activeTotal = Math.max(0, (s.total_monitors || 0) - (s.paused_monitors || 0));
  $('#kpiUp').textContent = `${s.up_monitors || 0} / ${activeTotal}`;
  $('#kpiDown').textContent = String(s.down_monitors || 0);
  $('#kpiIncidents').textContent = String(s.open_incidents || 0);
  $('#kpiUptime').textContent = `${s.overall_uptime_24h ?? 100}%`;
  $('#kpiLatency').textContent = s.avg_latency_ms != null ? `${s.avg_latency_ms} ms` : '—';
  $('#tabIncidentBadge').textContent = String(s.open_incidents || 0);
}

function renderMonitors() {
  const container = $('#monitorsList');
  const q = state.monitorSearch.trim().toLowerCase();
  const filtered = state.monitors.filter((m) => {
    if (state.monitorFilter === 'paused' && !m.paused) return false;
    if (state.monitorFilter === 'up' && (m.paused || m.status !== 'up')) return false;
    if (state.monitorFilter === 'down' && (m.paused || m.status !== 'down')) return false;
    if (q) {
      const hay = `${m.name} ${m.url} ${(m.alert_emails || []).join(' ')}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>${state.monitors.length === 0 ? 'No monitors configured yet. Click "+ Add Monitor" to start tracking your first website.' : 'No monitors match the current filter.'}</p>
      </div>`;
    return;
  }

  container.innerHTML = filtered
    .map((m) => {
      const statusClass = m.paused ? 'paused' : m.status || 'unknown';
      const statusLabel = m.paused ? 'PAUSED' : (m.status || 'UNKNOWN').toUpperCase();
      const bars = buildHeartbeatStrip(m.recent_checks || []);
      const emails = (m.alert_emails || [])
        .map((e) => `<span class="email-chip">${esc(e)}</span>`)
        .join('');

      return `
        <article class="monitor-card ${!m.paused && m.status === 'down' ? 'is-down' : ''}" data-id="${m.id}">
          <div>
            <div class="monitor-head">
              <span class="status-pill status-${statusClass}">${statusLabel}</span>
              <span class="monitor-name">${esc(m.name)}</span>
            </div>
            <div class="monitor-url">${esc(m.method)} ${esc(m.url)}</div>
            <div class="monitor-meta">
              <span>Every ${m.interval_seconds}s</span>
              <span>Expect ${m.expected_status}</span>
              ${m.keyword ? `<span>Keyword: "${esc(m.keyword)}"</span>` : ''}
              ${emails || '<span class="muted">Global emails only</span>'}
            </div>
            ${!m.paused && m.status === 'down' && m.last_error ? `<div class="error-banner">${esc(m.last_error)}</div>` : ''}
          </div>

          <div class="monitor-metrics">
            <div class="heartbeat-strip" title="Last 30 checks">${bars}</div>
            <div class="metrics-row">
              <span>24h Uptime: <strong>${m.uptime_24h !== null ? `${m.uptime_24h}%` : '—'}</strong></span>
              <span>Latency: <strong class="mono">${m.last_latency_ms != null ? `${m.last_latency_ms} ms` : '—'}</strong></span>
              <span>HTTP: <strong class="mono">${m.last_status_code ?? '—'}</strong></span>
            </div>
          </div>

          <div class="monitor-actions">
            <button class="btn btn-secondary btn-sm" data-action="check" data-id="${m.id}">Check Now</button>
            <button class="btn btn-ghost btn-sm" data-action="toggle" data-id="${m.id}">${m.paused ? 'Resume' : 'Pause'}</button>
            <button class="btn btn-ghost btn-sm" data-action="edit" data-id="${m.id}">Edit</button>
            <button class="btn btn-danger btn-sm" data-action="delete" data-id="${m.id}">Delete</button>
          </div>
        </article>`;
    })
    .join('');
}

function buildHeartbeatStrip(checks) {
  const slots = 30;
  const padded = new Array(Math.max(0, slots - checks.length)).fill(null).concat(checks.slice(-slots));
  return padded
    .map((c) => {
      if (!c) return '<span class="hb-bar" title="No data"></span>';
      const title = `${c.status.toUpperCase()} | ${c.status_code ?? 'ERR'} | ${c.latency_ms}ms | ${c.checked_at} UTC`;
      return `<span class="hb-bar ${c.status}" title="${esc(title)}"></span>`;
    })
    .join('');
}

function renderIncidents() {
  const container = $('#incidentsList');
  if (state.incidents.length === 0) {
    container.innerHTML = `<div class="empty-state"><p>No incidents recorded for this filter. All systems operational.</p></div>`;
    return;
  }

  container.innerHTML = state.incidents
    .map((inc) => {
      const isOpen = inc.status === 'open';
      return `
        <article class="incident-card ${inc.status}">
          <div>
            <div class="incident-title">
              <span class="status-pill ${isOpen ? 'status-down' : 'status-up'}">${esc(inc.status.toUpperCase())}</span>
              <span>#${inc.id} — ${esc(inc.monitor_name)}</span>
              <span class="email-chip">${esc(inc.error_type)}</span>
              ${inc.acknowledged ? '<span class="status-pill status-paused">ACKNOWLEDGED</span>' : ''}
            </div>
            <div class="incident-details">${esc(inc.error_message)}</div>
            <div class="incident-meta">
              <span>URL: ${esc(inc.monitor_url)}</span>
              <span>Started: ${esc(inc.started_at)} UTC</span>
              <span>Duration: ${formatDuration(inc.duration_seconds)}</span>
              ${inc.resolved_at ? `<span>Resolved: ${esc(inc.resolved_at)} UTC</span>` : ''}
            </div>
          </div>
          <div class="incident-actions">
            ${
              isOpen
                ? `${!inc.acknowledged ? `<button class="btn btn-secondary btn-sm" data-inc-action="ack" data-id="${inc.id}">Acknowledge</button>` : ''}
                   <button class="btn btn-primary btn-sm" data-inc-action="resolve" data-id="${inc.id}">Resolve</button>`
                : ''
            }
          </div>
        </article>`;
    })
    .join('');
}

function renderAlerts() {
  const tbody = $('#alertsTableBody');
  if (state.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No email alerts dispatched yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = state.alerts
    .map((a) => {
      const statusBadge =
        a.delivery_status === 'sent'
          ? 'status-up'
          : a.delivery_status === 'failed'
            ? 'status-down'
            : 'status-paused';
      const eventBadge = a.event_type === 'down' ? 'status-down' : 'status-up';
      return `
        <tr>
          <td class="mono">${esc(a.sent_at)}</td>
          <td><span class="status-pill ${eventBadge}">${esc(a.event_type)}</span></td>
          <td>${esc(a.monitor_name || `#${a.monitor_id}`)}</td>
          <td>${(a.recipients || []).map((r) => `<span class="email-chip">${esc(r)}</span>`).join(' ') || '<span class="muted">None</span>'}</td>
          <td>${esc(a.subject)}${a.error_message ? `<div class="muted">${esc(a.error_message)}</div>` : ''}</td>
          <td><span class="status-pill ${statusBadge}">${esc(a.delivery_status)}</span></td>
        </tr>`;
    })
    .join('');
}

function renderSettings() {
  if (!state.settings) return;
  const form = $('#settingsForm');
  for (const key of [
    'smtp_host',
    'smtp_port',
    'smtp_secure',
    'smtp_user',
    'smtp_from',
    'global_alert_emails',
    'notify_on_recovery',
    'retention_days',
  ]) {
    if (form.elements[key]) {
      form.elements[key].value = state.settings[key] ?? '';
    }
  }
  $('#smtpPassHint').textContent = state.settings.has_smtp_pass ? '(configured)' : '(not set)';
}

function openMonitorModal(monitor = null) {
  const form = $('#monitorForm');
  form.reset();
  form.elements.id.value = monitor ? monitor.id : '';
  $('#modalTitle').textContent = monitor ? `Edit Monitor: ${monitor.name}` : 'Add Website Monitor';

  if (monitor) {
    form.elements.name.value = monitor.name;
    form.elements.url.value = monitor.url;
    form.elements.method.value = monitor.method || 'GET';
    form.elements.interval_seconds.value = monitor.interval_seconds;
    form.elements.timeout_ms.value = monitor.timeout_ms;
    form.elements.expected_status.value = monitor.expected_status;
    form.elements.failure_threshold.value = monitor.failure_threshold;
    form.elements.keyword.value = monitor.keyword || '';
    form.elements.alert_emails.value = (monitor.alert_emails || []).join(', ');
    form.elements.detect_db_errors.checked = monitor.detect_db_errors !== false;
  } else {
    form.elements.detect_db_errors.checked = true;
  }

  $('#monitorModal').classList.remove('hidden');
}

function closeMonitorModal() {
  $('#monitorModal').classList.add('hidden');
}

function setupSSE() {
  if (sseSource) {
    sseSource.close();
  }
  const badge = $('#sseStatus');
  const text = badge.querySelector('.sse-text');
  sseSource = new EventSource('/api/events');

  sseSource.addEventListener('connected', () => {
    badge.className = 'sse-badge connected';
    text.textContent = 'Live';
  });

  sseSource.onerror = () => {
    badge.className = 'sse-badge disconnected';
    text.textContent = 'Reconnecting...';
  };

  const refresh = () => loadAll().catch(() => {});
  sseSource.addEventListener('monitor:created', refresh);
  sseSource.addEventListener('monitor:updated', refresh);
  sseSource.addEventListener('monitor:deleted', refresh);
  sseSource.addEventListener('monitor:checked', refresh);
  sseSource.addEventListener('incident:opened', (e) => {
    const data = JSON.parse(e.data);
    toast(`Incident opened: ${data.incident?.title}`, 'error');
    refresh();
  });
  sseSource.addEventListener('incident:resolved', (e) => {
    const data = JSON.parse(e.data);
    toast(`Incident resolved (#${data.incident?.id})`, 'success');
    refresh();
  });
  sseSource.addEventListener('incident:updated', refresh);
}

// Event Listeners
$$('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('.tab').forEach((t) => t.classList.remove('active'));
    $$('.view').forEach((v) => v.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    state.activeTab = tab;
    $(`#view-${tab}`).classList.add('active');
  });
});

$('#monitorSearch').addEventListener('input', (e) => {
  state.monitorSearch = e.target.value;
  renderMonitors();
});

$$('#view-monitors .pill').forEach((pill) => {
  pill.addEventListener('click', () => {
    $$('#view-monitors .pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    state.monitorFilter = pill.dataset.filter;
    renderMonitors();
  });
});

$$('#incidentFilters .pill').forEach((pill) => {
  pill.addEventListener('click', async () => {
    $$('#incidentFilters .pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    state.incidentFilter = pill.dataset.incidentStatus;
    state.incidents = await api(`/api/incidents?status=${state.incidentFilter}`);
    renderIncidents();
  });
});

$('#btnNewMonitor').addEventListener('click', () => openMonitorModal(null));
$('#btnCloseModal').addEventListener('click', closeMonitorModal);
$('#btnCancelModal').addEventListener('click', closeMonitorModal);

$('#monitorForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = fd.get('id');
  const payload = {
    name: fd.get('name'),
    url: fd.get('url'),
    method: fd.get('method'),
    interval_seconds: Number(fd.get('interval_seconds')),
    timeout_ms: Number(fd.get('timeout_ms')),
    expected_status: Number(fd.get('expected_status')),
    failure_threshold: Number(fd.get('failure_threshold')),
    keyword: fd.get('keyword'),
    detect_db_errors: e.target.elements.detect_db_errors.checked,
    alert_emails: String(fd.get('alert_emails') || '')
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean),
  };

  try {
    if (id) {
      await api(`/api/monitors/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      toast('Monitor updated', 'success');
    } else {
      await api('/api/monitors', { method: 'POST', body: JSON.stringify(payload) });
      toast('Monitor created & initial check started', 'success');
    }
    closeMonitorModal();
    await loadAll();
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('#monitorsList').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const action = btn.dataset.action;

  try {
    if (action === 'check') {
      btn.disabled = true;
      btn.textContent = 'Checking...';
      await api(`/api/monitors/${id}/check`, { method: 'POST' });
      await loadAll();
      toast('Check completed', 'success');
    } else if (action === 'toggle') {
      await api(`/api/monitors/${id}/toggle`, { method: 'POST' });
      await loadAll();
    } else if (action === 'edit') {
      const m = state.monitors.find((item) => item.id === id);
      if (m) openMonitorModal(m);
    } else if (action === 'delete') {
      if (!confirm('Delete this monitor and its history?')) return;
      await api(`/api/monitors/${id}`, { method: 'DELETE' });
      await loadAll();
      toast('Monitor deleted', 'info');
    }
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('#incidentsList').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-inc-action]');
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const action = btn.dataset.incAction;
  try {
    if (action === 'ack') {
      await api(`/api/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ acknowledged: true }),
      });
      toast('Incident acknowledged', 'info');
    } else if (action === 'resolve') {
      await api(`/api/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ resolve: true }),
      });
      toast('Incident resolved', 'success');
    }
    await loadAll();
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('#settingsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  try {
    state.settings = await api('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    renderSettings();
    e.target.elements.smtp_pass.value = '';
    toast('Settings saved', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
});

$('#btnTestEmail').addEventListener('click', async () => {
  const raw = $('#testEmailInput').value;
  const recipients = raw
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const box = $('#testEmailResult');
  box.classList.remove('hidden');
  box.textContent = 'Sending test email...';

  try {
    const res = await api('/api/settings/test-email', {
      method: 'POST',
      body: JSON.stringify({ recipients }),
    });
    box.innerHTML = `<strong>Status: ${esc(res.delivery_status.toUpperCase())}</strong><br/>Recipients: ${esc((res.recipients || []).join(', ') || 'None')}${res.error_message ? `<br/><span class="muted">${esc(res.error_message)}</span>` : ''}`;
  } catch (err) {
    box.textContent = `Error: ${err.message}`;
  }
});

function enterDashboard(user) {
  state.user = user;
  $('#currentUserBadge').textContent = user.username;
  $('#loginScreen').classList.add('hidden');
  $('#appShell').classList.remove('hidden');
  loadAll().catch((err) => toast(err.message, 'error'));
  setupSSE();
}

function exitDashboard() {
  state.user = null;
  state.monitors = [];
  state.incidents = [];
  state.alerts = [];
  state.summary = null;
  state.settings = null;
  if (sseSource) {
    sseSource.close();
    sseSource = null;
  }
  $('#appShell').classList.add('hidden');
  $('#loginScreen').classList.remove('hidden');
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = $('#loginError');
  errBox.classList.add('hidden');
  const btn = $('#btnLogin');
  btn.disabled = true;
  btn.textContent = 'Signing in...';

  const fd = new FormData(e.target);
  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: fd.get('username'),
        password: fd.get('password'),
      }),
    });
    e.target.reset();
    enterDashboard(res.user);
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In to Dashboard';
  }
});

$('#btnLogout').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch {
    // Ignore errors on logout
  }
  exitDashboard();
});

$('#changePasswordForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await api('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        current_password: fd.get('current_password'),
        new_password: fd.get('new_password'),
      }),
    });
    e.target.reset();
    toast('Admin password updated', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
});

async function initAuth() {
  try {
    const res = await api('/api/auth/me');
    if (res.authenticated && res.user) {
      enterDashboard(res.user);
      return;
    }
  } catch {
    // Not authenticated
  }
  exitDashboard();
}

initAuth();
