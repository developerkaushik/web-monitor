const crypto = require('node:crypto');

const SESSION_COOKIE = 'us_session';
const SESSION_TTL_HOURS = 24;

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
    const session = store.getSession(token);
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
  parseCookies,
  extractToken,
  requireAuth,
  buildSessionCookie,
};
