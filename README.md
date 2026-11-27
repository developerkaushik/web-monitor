# Uptime Sentinel

A production-ready Website Uptime Monitoring & Incident Alerting web application built with Node.js, Express, SQLite (`node:sqlite`), Nodemailer, and Server-Sent Events (SSE).

## Features

- **Admin Authentication Gate**: Dashboard and all API/SSE endpoints are locked behind `scrypt`-hashed admin login with `HttpOnly` SQLite-backed sessions; the main dashboard is hidden until authenticated.
- **Continuous HTTP/HTTPS Monitoring**: Configurable check intervals, timeouts, HTTP methods (`GET`, `HEAD`, `POST`), expected status codes, and optional response body keyword assertions.
- **Incident Capture & Lifecycle**: Automatically opens incidents when consecutive failures reach the configured threshold (`HTTP_STATUS`, `KEYWORD_MISMATCH`, `TIMEOUT`, `NETWORK_ERROR`), tracks downtime duration, and auto-resolves on recovery. Supports manual acknowledgment and resolution.
- **Multi-Recipient Email Alerts**: Sends HTML & plain-text incident and recovery emails via SMTP (`nodemailer`) to both per-monitor email lists and global default recipients (deduplicated).
- **Alert Delivery Audit Log**: Records every `sent`, `simulated`, `skipped`, or `failed` email dispatch in SQLite.
- **Live Observability Dashboard**: Real-time SSE updates, 30-check heartbeat strips, 24h uptime & latency KPIs, and an in-app SMTP & Test Email configuration panel.

## Quick Start

```bash
npm install
npm start
```

Open `http://localhost:3000` in your browser and sign in with your admin credentials (defaults to `admin` / `admin123` unless `ADMIN_USERNAME` and `ADMIN_PASSWORD` are set in the environment; you can change the password anytime in **SMTP & Settings**).

## Configuration

Configure SMTP either in the **SMTP & Settings** tab in the UI or via environment variables (see `.env.example`).

## Running Tests

```bash
npm test
```

## Deploying to Hostinger Web Apps

1. In **Hostinger hPanel → Websites → Node.js Web App** (or Git deployment):
   - Set **Node.js version** to **22.x** or **24.x** (`engines.node >= 22.13.0` is configured in `package.json`).
   - Set **Entry file** to `server.js` (or start command `npm start`).
   - Hostinger automatically provides `PORT` and terminates HTTPS via reverse proxy (`trust proxy` is enabled in `server.js`).
2. Add your **Environment Variables** in Hostinger hPanel (or `.env` on the server):
   - `ADMIN_USERNAME` and a strong `ADMIN_PASSWORD`
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
   - `GLOBAL_ALERT_EMAILS` (comma-separated)
3. Deploy and open your domain — sign in with your configured admin credentials.

