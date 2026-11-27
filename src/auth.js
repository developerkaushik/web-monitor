const crypto = require('node:crypto');

const SESSION_COOKIE = 'us_session';
const SESSION_TTL_HOURS = 24;
const revokedTokens = new Set();

function getSessionSecret() {
  const base =
    process.env.SESSION_SECRET ||
    `us:${process.env.ADMIN_USERNAME || 'admin'}:${process.env.ADMIN_PASSWORD || 'admin123'}:session-key`;
  return crypto.createHash('sha256').update(base).digest();
}

/**
 * Creates a stateless HMAC-SHA256 signed session token (works across serverless instances).
 * @param {{ id: number, username: string, role: string }} user
 * @param {number} [ttlHours]
 * @returns {string}
 */
function signSessionToken(user, ttlHours = SESSION_TTL_HOURS) {
  const payloadObj = {
    uid: user.id,
    u: user.username,
    r: user.role || 'admin',
    jti: crypto.randomBytes(8).toString('hex'),
    exp: Date.now() + Math.max(1, Number(ttlHours)) * 3600 * 1000,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/**
 * Verifies a stateless signed session token.
 * @param {string} token
 * @returns {{ user_id: number, username: string, role: string } | null}
 */
function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  if (revokedTokens.has(token)) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(payload)
    .digest('base64url');

  const sigBuf = Buffer.from(sig, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.exp !== 'number' || data.exp <= Date.now()) {
      return null;
    }
    return {
      user_id: data.uid,
      username: data.u,
      role: data.r || 'admin',
    };
  } catch {
    return null;
  }
}

function revokeSessionToken(token) {
  if (token) {
    revokedTokens.add(token);
  }
}

/**
 * Hashes a plaintext password with a random 16-byte salt using scrypt.
 * @param {string} password
 * @returns {string}
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

/**
 * Verifies a plaintext password against a stored `salt:hash` string.
 * @param {string} password
 * @param {string} storedHash
 * @returns {boolean}
 */
function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, expectedHex] = storedHash.split(':');
  if (!salt || !expectedHex) return false;
  const derived = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

/**
 * Parses cookies from an incoming HTTP request header.
 * @param {import('express').Request} req
 * @returns {Record<string, string>}
 */
function parseCookies(req) {
  const header = req.headers?.cookie;
  const cookies = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

/**
 * Extracts session token from cookie or Bearer header.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractToken(req) {
  const cookies = parseCookies(req);
  if (cookies[SESSION_COOKIE]) return cookies[SESSION_COOKIE];
  const auth = req.headers?.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  return null;
}

/**
 * Express middleware enforcing an authenticated admin session.
 * @param {ReturnType<import('./db').createDatabase>} store
 */
function requireAuth(store) {
  return (req, res, next) => {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const session = verifySessionToken(token) || store.getSession(token);
    if (!session) {
      return res.status(401).json({ error: 'Session expired or invalid' });
    }
    req.user = {
      id: session.user_id,
      username: session.username,
      role: session.role,
    };
    req.sessionToken = token;
    next();
  };
}

/**
 * Formats the Set-Cookie header value for the session token.
 * @param {string} token
 * @param {import('express').Request} req
 * @param {number} [maxAgeSeconds]
 */
function buildSessionCookie(token, req, maxAgeSeconds = SESSION_TTL_HOURS * 3600) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    parts.push('Secure');
  }
  return parts.join('; ');
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_HOURS,
  hashPassword,
  verifyPassword,
  signSessionToken,
  verifySessionToken,
  revokeSessionToken,
  parseCookies,
  extractToken,
  requireAuth,
  buildSessionCookie,
};
