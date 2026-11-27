const dns = require('node:dns').promises;
const net = require('node:net');

/**
 * Checks whether an IPv4 address is in a private, loopback, or reserved range.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // multicast / reserved
  return false;
}

/**
 * Checks whether an IPv6 address is loopback, link-local, or unique local.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIpv6(ip) {
  const norm = ip.toLowerCase();
  if (norm === '::' || norm === '::1') return true;
  if (norm.startsWith('::ffff:')) {
    return isPrivateIpv4(norm.slice(7));
  }
  if (norm.startsWith('fe80:') || norm.startsWith('fc') || norm.startsWith('fd')) {
    return true;
  }
  return false;
}

function isBlockedIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIpv4(ip);
  if (version === 6) return isPrivateIpv6(ip);
  return true;
}

/**
 * Validates that a target URL is HTTP/HTTPS and does not resolve to private/internal IPs
 * unless ALLOW_PRIVATE_TARGETS=true is set.
 * @param {string} rawUrl
 * @returns {Promise<URL>}
 */
async function assertSafeTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('A valid http:// or https:// URL is required');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http:// and https:// URLs are permitted');
  }

  if (process.env.ALLOW_PRIVATE_TARGETS === 'true') {
    return parsed;
  }

  const host = parsed.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Internal or localhost URLs are blocked by SSRF policy');
  }

  if (net.isIP(host)) {
    if (isBlockedIp(host)) {
      throw new Error('Private or reserved IP addresses are blocked by SSRF policy');
    }
    return parsed;
  }

  try {
    const records = await dns.lookup(host, { all: true });
    if (!records || records.length === 0) {
      throw new Error('Unable to resolve target hostname');
    }
    for (const rec of records) {
      if (isBlockedIp(rec.address)) {
        throw new Error('Target hostname resolves to a blocked private or reserved IP address');
      }
    }
  } catch (err) {
    if (err.message.includes('SSRF policy') || err.message.includes('blocked')) {
      throw err;
    }
    // Allow unresolvable hosts to be saved only if needed? No — fail or let monitorEngine catch DNS errors at probe time.
    // Wait: if a domain temporarily fails DNS during creation, monitorEngine should record NETWORK_ERROR rather than blocking creation!
    // Only block if DNS explicitly resolves to a private/reserved IP.
  }

  return parsed;
}

module.exports = { assertSafeTargetUrl, isBlockedIp };
