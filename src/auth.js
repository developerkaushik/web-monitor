const crypto = require('node:crypto');

const SESSION_COOKIE = 'us_session';
const SESSION_TTL_HOURS = 24;
const revokedTokens = new Set();
const ephemeralFallbackSecret = crypto.randomBytes(32);
let cachedDbSecret = null;

function getSessionSecret(secretOverride) {
  if (secretOverride) {
    return crypto.createHash('sha256').update(String(secretOverride)).digest();
  }
  if (process.env.SESSION_SECRET) {
    return crypto.createHash('sha256').update(process.env.SESSION_SECRET).digest();
  }
  if (cachedDbSecret) {
    return cachedDbSecret;
  }
  return ephemeralFallbackSecret;
}

/**
 * Loads or generates a persistent random 256-bit signing secret in the store's settings
 * when SESSION_SECRET env var is not explicitly configured.
 * @param {ReturnType<import('./db').createDatabase>} store
 */
async function ensureSessionSecret(store) {
  if (process.env.SESSION_SECRET) {
    return getSessionSecret();
  }
  if (cachedDbSecret) return cachedDbSecret;
  try {
    const settings = await store.getSettings();
    let hex = settings.session_secret;
    if (!hex || hex.length < 32) {
      hex = crypto.randomBytes(32).toString('hex');
      await store.updateSettings({ session_secret: hex });
    }
    cachedDbSecret = crypto.createHash('sha256').update(hex).digest();
    return cachedDbSecret;
  } catch {
    return ephemeralFallbackSecret;
  }
}

/**
 * Encrypts a sensitive string (e.g. SMTP password) using AES-256-GCM.
 * @param {string} plaintext
 * @param {Buffer} [key]
 * @returns {string}
 */
function encryptSecret(plaintext, key) {
  if (!plaintext) return '';
  if (String(plaintext).startsWith('enc:v1:')) return String(plaintext);
  const encKey = key || getSessionSecret();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

/**
 * Decrypts an AES-256-GCM secret; returns plaintext as-is for legacy unencrypted values.
 * @param {string} value
 * @param {Buffer} [key]
 * @returns {string}
 */
function decryptSecret(value, key) {
  if (!value) return '';
  const str = String(value);
  if (!str.startsWith('enc:v1:')) return str;
  const parts = str.split(':');
  if (parts.length !== 5) return '';
  try {
    const iv = Buffer.from(parts[2], 'base64url');
    const tag = Buffer.from(parts[3], 'base64url');
    const data = Buffer.from(parts[4], 'base64url');
    const encKey = key || getSessionSecret();
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

/**
 * Creates a stateless HMAC-SHA256 signed session token (works across serverless instances).
 * @param {{ id: number, username: string, role: string }} user
 * @param {number} [ttlHours]
 * @returns {string}
 */
function signSessionToken(user, ttlHours = SESSION_TTL_HOURS) {
  const now = Date.now();
  const payloadObj = {
    uid: user.id,
    u: user.username,
    r: user.role || 'admin',
    jti: crypto.randomBytes(8).toString('hex'),
    iat: now,
    exp: now + Math.max(1, Number(ttlHours)) * 3600 * 1000,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/**
 * Verifies a stateless signed session token.
 * @param {string} token
 * @param {number} [minIat]
 * @returns {{ user_id: number, username: string, role: string, iat?: number } | null}
 */
function verifySessionToken(token, minIat = 0) {
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
    if (minIat > 0 && (!data.iat || data.iat < minIat)) {
      return null;
    }
    return {
      user_id: data.uid,
      username: data.u,
      role: data.r || 'admin',
      iat: data.iat,
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
  return async (req, res, next) => {
    try {
      await ensureSessionSecret(store);
      const token = extractToken(req);
      if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      const settings = await store.getSettings();
      const minIat = Number(settings.min_token_iat || 0);
      const session = verifySessionToken(token, minIat) || (await store.getSession(token));
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
    } catch (err) {
      next(err);
    }
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
  ensureSessionSecret,
  encryptSecret,
  decryptSecret,
  signSessionToken,
  verifySessionToken,
  revokeSessionToken,
  parseCookies,
  extractToken,
  requireAuth,
  buildSessionCookie,
};
