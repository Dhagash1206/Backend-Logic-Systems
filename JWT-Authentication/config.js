'use strict';
const isProd = process.env.NODE_ENV === 'production';

function fail(msg) { throw new Error(`[jwt-config] ${msg}`); }

function posInt(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) fail(`${name} must be a positive integer`);
  return n;
}

function readKey(secretVar, kidVar, defaultKid, required) {
  const secret = process.env[secretVar];
  if (!secret) {
    if (required) fail(`${secretVar} is required (generate with: openssl rand -hex 64)`);
    return null;
  }
  if (secret.length < 32) fail(`${secretVar} must be at least 32 characters`);
  const kid = process.env[kidVar] || defaultKid;
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(kid)) fail(`${kidVar} must match [A-Za-z0-9_.-]{1,32}`);
  return { kid, secret };
}

function keyring(prefix) {
  const current = readKey(`${prefix}_SECRET`, `${prefix}_KID`, 'k1', true);
  const previous = readKey(`${prefix}_SECRET_PREVIOUS`, `${prefix}_KID_PREVIOUS`, 'k0', false);
  const keys = previous ? [current, previous] : [current];
  if (new Set(keys.map((k) => k.kid)).size !== keys.length) fail(`${prefix}: current and previous kid must differ`);
  return { current, keys, byKid: new Map(keys.map((k) => [k.kid, k.secret])) };
}

const access = keyring('JWT_ACCESS');
const refresh = keyring('JWT_REFRESH');

const allSecrets = [...access.keys, ...refresh.keys].map((k) => k.secret);
if (new Set(allSecrets).size !== allSecrets.length) fail('All access/refresh secrets must be different');

const transport = process.env.JWT_REFRESH_TRANSPORT || 'cookie';
if (!['cookie', 'body'].includes(transport)) fail('JWT_REFRESH_TRANSPORT must be "cookie" or "body"');

const bcryptRounds = posInt('BCRYPT_ROUNDS', 12);
if (bcryptRounds < 10 || bcryptRounds > 14) fail('BCRYPT_ROUNDS must be between 10 and 14');

module.exports = Object.freeze({
  isProd,
  issuer: process.env.JWT_ISSUER || 'auth-service',
  audience: process.env.JWT_AUDIENCE || 'api',
  clockToleranceSec: 5,
  bcryptRounds,
  access: Object.freeze({ ...access, ttl: posInt('JWT_ACCESS_TTL_SECONDS', 15 * 60) }),
  refresh: Object.freeze({
    ...refresh,
    ttl: posInt('JWT_REFRESH_TTL_SECONDS', 5 * 24 * 3600),
    sessionMax: posInt('JWT_SESSION_MAX_SECONDS', 30 * 24 * 3600),
    transport,
    cookie: Object.freeze({
      name: process.env.JWT_REFRESH_COOKIE_NAME || 'refresh_token',
      path: process.env.JWT_REFRESH_COOKIE_PATH || '/auth',
      domain: process.env.JWT_REFRESH_COOKIE_DOMAIN || undefined,
      secure: isProd ? true : process.env.COOKIE_SECURE === 'true',
      sameSite: 'strict',
    }),
  }),
});