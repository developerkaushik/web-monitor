const nodemailer = require('nodemailer');
const { parseEmails } = require('./db');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Formats seconds into a human-readable duration string.
 * @param {number} totalSeconds
 * @returns {string}
 */
function formatDuration(totalSeconds) {
  const sec = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  if (sec < 60) return `${sec}s`;
  const mins = Math.floor(sec / 60);
  const remSec = sec % 60;
  if (mins < 60) return `${mins}m ${remSec}s`;
  const hrs = Math.floor(mins / 60);
  const remMin = mins % 60;
  return `${hrs}h ${remMin}m ${remSec}s`;
}

/**
 * Deduplicates and validates recipient email addresses.
 * @param {...(string|string[])} lists
 * @returns {string[]}
 */
function resolveRecipients(...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const email of parseEmails(list)) {
      const normalized = email.trim().toLowerCase();
      if (EMAIL_RE.test(normalized) && !seen.has(normalized)) {
        seen.add(normalized);
        out.push(email.trim());
      }
    }
  }
  return out;
}

/**
 * Escapes HTML special characters for safe email templates.
 * @param {string} str
 */
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Creates a mailer service bound to a store.
 * @param {ReturnType<import('./db').createDatabase>} store
 * @param {{ transport?: import('nodemailer').Transporter }} [options]
 */
function createMailer(store, options = {}) {
  function buildTransport(settings) {
    if (options.transport) return options.transport;
    if (!settings.smtp_host) return null;

    const port = Number(settings.smtp_port || 587);
    // Port 465 uses implicit TLS; ports 587/25/2525 use plaintext + STARTTLS (setting secure:true on 587 causes SSL wrong version number)
    const isStartTlsPort = port === 587 || port === 25 || port === 2525;
    const secure = port === 465 ? true : isStartTlsPort ? false : settings.smtp_secure === 'true';

    const config = {
      host: settings.smtp_host,
      port,
      secure,
      ...(isStartTlsPort && settings.smtp_secure === 'true' ? { requireTLS: true } : {}),
    };

    if (settings.smtp_user) {
      config.auth = {
        user: settings.smtp_user,
        pass: settings.smtp_pass || '',
      };
    }

    return nodemailer.createTransport(config);
  }

  /**
   * Sends an email to multiple recipients and records the delivery attempt.
   */
  async function dispatch({ monitor, incident, eventType, subject, text, html, explicitRecipients }) {
    const settings = await store.getSettings();
    const recipients = explicitRecipients
      ? resolveRecipients(explicitRecipients)
      : resolveRecipients(monitor?.alert_emails, settings.global_alert_emails);

    if (recipients.length === 0) {
      return await store.recordAlertLog({
        incident_id: incident?.id ?? null,
        monitor_id: monitor?.id ?? 0,
        event_type: eventType,
        recipients: [],
        subject,
        delivery_status: 'skipped',
        error_message: 'No valid recipient emails configured',
      });
    }

    const transport = buildTransport(settings);
    if (!transport) {
      return await store.recordAlertLog({
        incident_id: incident?.id ?? null,
        monitor_id: monitor?.id ?? 0,
        event_type: eventType,
        recipients,
        subject,
        delivery_status: 'simulated',
        error_message: 'SMTP not configured — logged locally only',
      });
    }

    try {
      await transport.sendMail({
        from: settings.smtp_from || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
        to: recipients.join(', '),
        subject,
        text,
        html,
      });

      return await store.recordAlertLog({
        incident_id: incident?.id ?? null,
        monitor_id: monitor?.id ?? 0,
        event_type: eventType,
        recipients,
        subject,
        delivery_status: 'sent',
      });
    } catch (err) {
      return await store.recordAlertLog({
        incident_id: incident?.id ?? null,
        monitor_id: monitor?.id ?? 0,
        event_type: eventType,
        recipients,
        subject,
        delivery_status: 'failed',
        error_message: err?.message || String(err),
      });
    }
  }

  async function sendDownAlert(monitor, incident) {
    const subject = `[DOWN] ${monitor.name} is unreachable (${incident.error_type})`;
    const text = [
      `INCIDENT OPENED #${incident.id}`,
      `Monitor: ${monitor.name}`,
      `URL: ${monitor.url}`,
      `Error Type: ${incident.error_type}`,
      incident.status_code ? `HTTP Status: ${incident.status_code}` : null,
      `Details: ${incident.error_message}`,
      `Started At (UTC): ${incident.started_at}`,
    ]
      .filter(Boolean)
      .join('\n');

    const html = `
      <div style="font-family:Inter,Arial,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:24px;border-radius:10px;border:1px solid #334155;">
        <div style="display:inline-block;background:#ef4444;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:999px;letter-spacing:.04em;">DOWNTIME ALERT</div>
        <h2 style="margin:14px 0 6px;color:#f8fafc;">${escapeHtml(monitor.name)} is DOWN</h2>
        <p style="margin:0 0 18px;color:#94a3b8;font-size:14px;">Incident #${incident.id} opened at ${escapeHtml(incident.started_at)} UTC</p>
        <table style="width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;">
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;border-bottom:1px solid #334155;">Target URL</td><td style="padding:10px 14px;color:#f8fafc;font-size:13px;border-bottom:1px solid #334155;">${escapeHtml(monitor.url)}</td></tr>
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;border-bottom:1px solid #334155;">Error Type</td><td style="padding:10px 14px;color:#fca5a5;font-size:13px;border-bottom:1px solid #334155;">${escapeHtml(incident.error_type)}</td></tr>
          ${incident.status_code ? `<tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;border-bottom:1px solid #334155;">HTTP Status</td><td style="padding:10px 14px;color:#fca5a5;font-size:13px;border-bottom:1px solid #334155;">${incident.status_code}</td></tr>` : ''}
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;">Reason</td><td style="padding:10px 14px;color:#f8fafc;font-size:13px;">${escapeHtml(incident.error_message)}</td></tr>
        </table>
      </div>
    `;

    return dispatch({ monitor, incident, eventType: 'down', subject, text, html });
  }

  async function sendRecoveryAlert(monitor, incident) {
    const settings = await store.getSettings();
    if (settings.notify_on_recovery === 'false') return null;

    const durationStr = formatDuration(incident.duration_seconds);
    const subject = `[RESOLVED] ${monitor.name} is back UP (downtime: ${durationStr})`;
    const text = [
      `INCIDENT RESOLVED #${incident.id}`,
      `Monitor: ${monitor.name}`,
      `URL: ${monitor.url}`,
      `Total Downtime: ${durationStr}`,
      `Resolved At (UTC): ${incident.resolved_at}`,
    ].join('\n');

    const html = `
      <div style="font-family:Inter,Arial,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:24px;border-radius:10px;border:1px solid #334155;">
        <div style="display:inline-block;background:#10b981;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:999px;letter-spacing:.04em;">RECOVERED</div>
        <h2 style="margin:14px 0 6px;color:#f8fafc;">${escapeHtml(monitor.name)} is back UP</h2>
        <p style="margin:0 0 18px;color:#94a3b8;font-size:14px;">Incident #${incident.id} resolved after ${escapeHtml(durationStr)}</p>
        <table style="width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;">
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;border-bottom:1px solid #334155;">Target URL</td><td style="padding:10px 14px;color:#f8fafc;font-size:13px;border-bottom:1px solid #334155;">${escapeHtml(monitor.url)}</td></tr>
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;border-bottom:1px solid #334155;">Downtime</td><td style="padding:10px 14px;color:#6ee7b7;font-size:13px;border-bottom:1px solid #334155;">${escapeHtml(durationStr)}</td></tr>
          <tr><td style="padding:10px 14px;color:#94a3b8;font-size:13px;">Resolved At</td><td style="padding:10px 14px;color:#f8fafc;font-size:13px;">${escapeHtml(incident.resolved_at)} UTC</td></tr>
        </table>
      </div>
    `;

    return dispatch({ monitor, incident, eventType: 'recovery', subject, text, html });
  }

  async function sendTestEmail(explicitRecipients) {
    const settings = await store.getSettings();
    const recipients = resolveRecipients(explicitRecipients, settings.global_alert_emails);
    const subject = '[TEST] Uptime Sentinel Alert Verification';
    const text = `This is a test email from Uptime Sentinel confirming multi-recipient alerting works (${recipients.join(', ')}).`;
    const html = `
      <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:24px;border-radius:10px;border:1px solid #334155;">
        <div style="display:inline-block;background:#3b82f6;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:999px;">TEST ALERT</div>
        <h2 style="margin:14px 0 8px;color:#f8fafc;">SMTP &amp; Alerting Configured</h2>
        <p style="margin:0;color:#cbd5e1;font-size:14px;">Your Uptime Sentinel instance can successfully deliver incident emails to: <strong>${escapeHtml(recipients.join(', '))}</strong>.</p>
      </div>
    `;

    if (recipients.length === 0) {
      return {
        delivery_status: 'skipped',
        recipients: [],
        error_message: 'No valid recipient emails provided',
      };
    }

    const transport = buildTransport(settings);
    if (!transport) {
      return {
        delivery_status: 'simulated',
        recipients,
        error_message: 'SMTP host is not configured yet. Configure SMTP settings to send real emails.',
      };
    }

    try {
      await transport.sendMail({
        from: settings.smtp_from || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
        to: recipients.join(', '),
        subject,
        text,
        html,
      });
      return { delivery_status: 'sent', recipients };
    } catch (err) {
      return {
        delivery_status: 'failed',
        recipients,
        error_message: err?.message || String(err),
      };
    }
  }

  async function sendSystemErrorAlert({ component, errorType, message }) {
    let settings = {};
    try {
      settings = await store.getSettings();
    } catch {
      settings = {
        smtp_host: process.env.SMTP_HOST || '',
        smtp_port: process.env.SMTP_PORT || '587',
        smtp_secure: process.env.SMTP_SECURE || 'false',
        smtp_user: process.env.SMTP_USER || '',
        smtp_pass: process.env.SMTP_PASS || '',
        smtp_from: process.env.SMTP_FROM || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
        global_alert_emails: process.env.GLOBAL_ALERT_EMAILS || '',
      };
    }

    const recipients = resolveRecipients(settings.global_alert_emails, process.env.GLOBAL_ALERT_EMAILS);
    if (recipients.length === 0) return null;

    const transport = buildTransport(settings);
    if (!transport) return null;

    const subject = `[SYSTEM ERROR] ${component}: ${errorType}`;
    const text = `Component: ${component}\nError Type: ${errorType}\nDetails: ${message}\nTime (UTC): ${new Date().toISOString()}`;
    const html = `
      <div style="font-family:Inter,Arial,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:24px;border-radius:10px;border:1px solid #334155;">
        <div style="display:inline-block;background:#ef4444;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:999px;">SYSTEM ERROR</div>
        <h2 style="margin:14px 0 6px;color:#f8fafc;">${escapeHtml(component)} — ${escapeHtml(errorType)}</h2>
        <p style="margin:0;color:#fca5a5;font-size:14px;">${escapeHtml(message)}</p>
      </div>
    `;

    try {
      await transport.sendMail({
        from: settings.smtp_from || 'Uptime Sentinel <alerts@uptime-sentinel.local>',
        to: recipients.join(', '),
        subject,
        text,
        html,
      });
      return { delivery_status: 'sent', recipients };
    } catch (err) {
      console.error('[mailer] sendSystemErrorAlert failed:', err);
      return { delivery_status: 'failed', recipients, error_message: err?.message || String(err) };
    }
  }

  return {
    sendDownAlert,
    sendRecoveryAlert,
    sendTestEmail,
    sendSystemErrorAlert,
    resolveRecipients,
    formatDuration,
  };
}

module.exports = { createMailer, resolveRecipients, formatDuration };
