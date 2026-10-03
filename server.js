const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');
const { createServer } = require('node:http');
const { mkdirSync, readFileSync } = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { promisify } = require('node:util');

const SESSION_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const SESSION_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const MAX_RATE_LIMIT_BUCKETS = 10_000;
const PASSWORD_KEY_LENGTH = 64;
const PASSWORD_SALT_BYTES = 16;
const MAX_BODY_BYTES = 16 * 1024;
const INDEX_HTML = path.join(__dirname, 'index.html');
const derivePassword = promisify(require('node:crypto').scrypt);

function createApp(databasePath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'users.sqlite'), options = {}) {
  const rateLimits = {
    login: options.rateLimits?.login ?? 10,
    register: options.rateLimits?.register ?? 5,
    windowMs: options.rateLimits?.windowMs ?? 15 * 60 * 1000
  };
  const bitcoinNetwork = options.bitcoinNetwork || process.env.BTC_NETWORK || 'testnet';
  if (!['mainnet', 'testnet'].includes(bitcoinNetwork)) {
    throw new Error('BTC_NETWORK must be either mainnet or testnet.');
  }
  const peerConfig = getPeerConfig(options.peer);
  const attempts = new Map();
  mkdirSync(path.dirname(databasePath), { recursive: true });
  const database = new DatabaseSync(databasePath);
  database.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      bitcoin_address TEXT,
      password_salt BLOB NOT NULL,
      password_hash BLOB NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
  `);
  const userColumns = database.prepare('PRAGMA table_info(users)').all();
  if (!userColumns.some((column) => column.name === 'bitcoin_address')) {
    database.exec('ALTER TABLE users ADD COLUMN bitcoin_address TEXT');
  }
  database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    for (const [key, attempt] of attempts) {
      if (attempt.resetAt <= now) attempts.delete(key);
    }
  }, SESSION_CLEANUP_INTERVAL_MS);
  cleanupInterval.unref();

  const server = createServer(async (request, response) => {
    setSecurityHeaders(response, request);
    const requestUrl = new URL(request.url, 'http://localhost');

    try {
      if (request.method === 'GET' && requestUrl.pathname === '/healthz') {
        database.prepare('SELECT 1').get();
        sendJson(response, 200, { status: 'ok' });
        return;
      }

      if (request.method === 'GET' && requestUrl.pathname === '/api/config') {
        sendJson(response, 200, { peer: peerConfig });
        return;
      }

      if (request.method === 'GET' && requestUrl.pathname === '/vendor/peerjs.min.js') {
        response.writeHead(200, {
          'Content-Type': 'text/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=3600'
        });
        response.end(readFileSync(path.join(__dirname, 'node_modules', 'peerjs', 'dist', 'peerjs.min.js')));
        return;
      }

      if (requestUrl.pathname.startsWith('/api/') &&
          ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) &&
          !isRequestOriginTrusted(request)) {
        sendJson(response, 403, { error: 'Cross-origin request rejected.' });
        return;
      }

      if (requestUrl.pathname.startsWith('/api/')) {
        await handleApi(request, response, requestUrl.pathname, database, attempts, rateLimits,
          bitcoinNetwork);
        return;
      }

      if ((request.method === 'GET' || request.method === 'HEAD') &&
          (requestUrl.pathname === '/' || requestUrl.pathname === '/index.html')) {
        const nonce = randomBytes(18).toString('base64');
        const page = readFileSync(INDEX_HTML, 'utf8').replaceAll('__CSP_NONCE__', nonce);
            const peerOrigin = peerConfig.host
              ? `${peerConfig.secure ? 'https' : 'http'}://${peerConfig.host}${peerConfig.port === (peerConfig.secure ? 443 : 80) ? '' : `:${peerConfig.port}`} ` +
                `${peerConfig.secure ? 'wss' : 'ws'}://${peerConfig.host}${peerConfig.port === (peerConfig.secure ? 443 : 80) ? '' : `:${peerConfig.port}`}`
          : 'https://*.peerjs.com wss://*.peerjs.com';
        response.setHeader('Content-Security-Policy',
          `default-src 'self'; script-src 'self' 'nonce-${nonce}'; ` +
          `style-src 'self' 'nonce-${nonce}'; connect-src 'self' ${peerOrigin}; ` +
          `img-src 'self' data:; font-src 'self' data:; form-action 'self'; base-uri 'self'; ` +
          `frame-ancestors 'none'; object-src 'none'`);
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        response.end(request.method === 'HEAD' ? undefined : page);
        return;
      }

      sendJson(response, 404, { error: 'Not found.' });
    } catch (error) {
      if (!response.headersSent) {
        sendJson(response, error.statusCode || 500, {
          error: error.statusCode ? error.message : 'An unexpected server error occurred.'
        });
      }
      if (!error.statusCode) console.error(error);
    }
  });

  server.on('close', () => {
    clearInterval(cleanupInterval);
    database.close();
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 1_000;
  return server;
}

async function handleApi(request, response, route, database, attempts, rateLimits,
  bitcoinNetwork) {
  if (request.method === 'POST' &&
      (route === '/api/auth/register' || route === '/api/auth/login')) {
    const action = route.endsWith('/register') ? 'register' : 'login';
    const retryAfter = consumeRateLimit(attempts, `${action}:${getClientAddress(request)}`,
      rateLimits[action], rateLimits.windowMs);
    if (retryAfter > 0) {
      response.setHeader('Retry-After', String(retryAfter));
      sendJson(response, 429, { error: 'Too many attempts. Please wait before trying again.' });
      return;
    }

    const body = await readJson(request);
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      sendJson(response, 400, { error: 'Enter a valid email address.' });
      return;
    }
    if (password.length < 10 || Buffer.byteLength(password, 'utf8') > 128) {
      sendJson(response, 400, { error: 'Password must be at least 10 characters and no more than 128 bytes.' });
      return;
    }

    let user;
    if (route === '/api/auth/register') {
      const salt = randomBytes(PASSWORD_SALT_BYTES);
      const passwordHash = await derivePassword(password, salt, PASSWORD_KEY_LENGTH);
      try {
        const result = database.prepare(
          'INSERT INTO users (email, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)'
        ).run(email, salt, passwordHash, Date.now());
        user = { id: result.lastInsertRowid, email };
      } catch (error) {
        if (error.code === 'ERR_SQLITE_ERROR' && error.message === 'UNIQUE constraint failed: users.email') {
          sendJson(response, 409, { error: 'An account with that email already exists.' });
          return;
        }
        throw error;
      }
    } else {
      user = database.prepare(
        'SELECT id, email, password_salt, password_hash FROM users WHERE email = ?'
      ).get(email);
      const salt = user?.password_salt || Buffer.alloc(PASSWORD_SALT_BYTES);
      const expectedHash = user?.password_hash || Buffer.alloc(PASSWORD_KEY_LENGTH);
      const actualHash = await derivePassword(password, salt, PASSWORD_KEY_LENGTH);

      if (!user || !timingSafeEqual(actualHash, expectedHash)) {
        sendJson(response, 401, { error: 'Email or password is incorrect.' });
        return;
      }
    }

    const sessionToken = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + SESSION_LIFETIME_SECONDS * 1000;
    database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
      .run(hashToken(sessionToken), user.id, expiresAt);
    setSessionCookie(response, sessionToken);
    sendJson(response, route.endsWith('/register') ? 201 : 200, {
      user: { email: user.email }
    });
    return;
  }

  if (request.method === 'GET' && route === '/api/auth/me') {
    const user = getSessionUser(request, database);
    if (!user) {
      sendJson(response, 401, { error: 'Sign in to continue.' });
      return;
    }
    sendJson(response, 200, { user: { email: user.email } });
    return;
  }

  if (route.startsWith('/api/wallet')) {
    const user = getSessionUser(request, database);
    if (!user) {
      sendJson(response, 401, { error: 'Sign in to continue.' });
      return;
    }

    if (request.method === 'GET' && route === '/api/wallet') {
      const profile = database.prepare('SELECT bitcoin_address FROM users WHERE id = ?').get(user.id);
      sendJson(response, 200, {
        network: bitcoinNetwork,
        bitcoinAddress: profile.bitcoin_address
      });
      return;
    }

    if (request.method === 'PUT' && route === '/api/wallet') {
      const body = await readJson(request);
      const address = typeof body.bitcoinAddress === 'string' ? body.bitcoinAddress.trim() : '';
      if (address && !isBitcoinAddress(address, bitcoinNetwork)) {
        sendJson(response, 400, { error: `Enter a valid ${bitcoinNetwork} Bitcoin address.` });
        return;
      }
      database.prepare('UPDATE users SET bitcoin_address = ? WHERE id = ?')
        .run(address || null, user.id);
      sendJson(response, 200, { network: bitcoinNetwork, bitcoinAddress: address || null });
      return;
    }

    sendJson(response, 404, { error: 'Not found.' });
    return;
  }

  if (request.method === 'POST' && route === '/api/auth/logout') {
    const token = readSessionToken(request);
    if (token) database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    clearSessionCookie(response);
    sendJson(response, 200, { ok: true });
    return;
  }

  sendJson(response, 404, { error: 'Not found.' });
}

function isBitcoinAddress(address, network) {
  const pattern = network === 'mainnet'
    ? /^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/
    : /^(tb1[a-z0-9]{25,62}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
  return pattern.test(address);
}

function getPeerConfig(overrides = {}) {
  const host = overrides.host ?? process.env.PEER_HOST ?? '';
  const port = Number(overrides.port ?? process.env.PEER_PORT ?? 443);
  const pathValue = overrides.path ?? process.env.PEER_PATH ?? '/peerjs';
  const secureValue = overrides.secure ?? process.env.PEER_SECURE;
  if (host && !/^[a-zA-Z0-9.-]+$/.test(host)) {
    throw new Error('PEER_HOST must be a hostname without a scheme or path.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PEER_PORT must be an integer between 1 and 65535.');
  }
  if (typeof pathValue !== 'string' || !/^\/[a-zA-Z0-9/_-]*$/.test(pathValue)) {
    throw new Error('PEER_PATH must be an absolute URL path containing only letters, numbers, /, _ or -.');
  }
  return {
    host,
    port,
    path: pathValue,
    secure: secureValue === undefined ? true : secureValue === true || secureValue === 'true'
  };
}

function isRequestOriginTrusted(request) {
  if (request.headers['sec-fetch-site'] === 'cross-site') return false;
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const originUrl = new URL(origin);
    const forwardedHost = process.env.TRUST_PROXY === 'true'
      ? request.headers['x-forwarded-host']?.split(',')[0].trim()
      : '';
    const requestHost = forwardedHost || request.headers.host;
    return ['http:', 'https:'].includes(originUrl.protocol) &&
      Boolean(requestHost) && originUrl.host.toLowerCase() === requestHost.toLowerCase();
  } catch {
    return false;
  }
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const contentType = request.headers['content-type']?.split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json') {
      request.resume();
      const error = new Error('Content-Type must be application/json.');
      error.statusCode = 415;
      reject(error);
      return;
    }

    let body = '';
    let rejected = false;
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      if (rejected) return;
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
        const error = new Error('Request body is too large.');
        error.statusCode = 413;
        rejected = true;
        reject(error);
      }
    });
    request.on('end', () => {
      if (rejected) return;
      try {
        resolve(JSON.parse(body));
      } catch {
        const error = new Error('Request body must be valid JSON.');
        error.statusCode = 400;
        reject(error);
      }
    });
    request.on('error', (error) => {
      if (!rejected) reject(error);
    });
  });
}

function readSessionToken(request) {
  const cookie = request.headers.cookie?.split(';').map((part) => part.trim())
    .find((part) => part.startsWith('session='));
  return cookie?.slice('session='.length) || '';
}

function getSessionUser(request, database) {
  const token = readSessionToken(request);
  if (!token) return null;
  return database.prepare(`
    SELECT users.id, users.email
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(hashToken(token), Date.now()) || null;
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function consumeRateLimit(attempts, key, limit, windowMs) {
  const now = Date.now();
  let attempt = attempts.get(key);
  if (!attempt || attempt.resetAt <= now) {
    if (attempts.size >= MAX_RATE_LIMIT_BUCKETS) {
      for (const [existingKey, existingAttempt] of attempts) {
        if (existingAttempt.resetAt <= now) attempts.delete(existingKey);
      }
      if (attempts.size >= MAX_RATE_LIMIT_BUCKETS) {
        attempts.delete(attempts.keys().next().value);
      }
    }
    attempt = { count: 0, resetAt: now + windowMs };
    attempts.set(key, attempt);
  }
  if (attempt.count >= limit) return Math.max(1, Math.ceil((attempt.resetAt - now) / 1000));
  attempt.count += 1;
  return 0;
}

function getClientAddress(request) {
  if (process.env.TRUST_PROXY === 'true') {
    const forwardedFor = request.headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string' && forwardedFor.length > 0) {
      return forwardedFor.split(',')[0].trim().slice(0, 64);
    }
  }
  return request.socket.remoteAddress || 'unknown';
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  response.setHeader('Set-Cookie',
    `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME_SECONDS}${secure}`);
}

function clearSessionCookie(response) {
  response.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}

function setSecurityHeaders(response, request) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  response.setHeader('Cache-Control', 'no-store');
  if (process.env.NODE_ENV === 'production' && process.env.TRUST_PROXY === 'true') {
    const forwardedProto = requestProtocolFromProxy(request);
    if (forwardedProto === 'https') {
      response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
  }
}

function requestProtocolFromProxy(request) {
  return request.headers['x-forwarded-proto']?.split(',')[0].trim().toLowerCase() || '';
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

if (require.main === module) {
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  const server = createApp();
  server.listen(port, host, () => console.log(`Messenger available at http://${host}:${port}`));
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received; closing server.`);
    const forceClose = setTimeout(() => server.closeAllConnections(), 10_000);
    forceClose.unref();
    server.close((error) => {
      clearTimeout(forceClose);
      if (error) {
        console.error('Server shutdown failed:', error);
        process.exitCode = 1;
      }
    });
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
}

module.exports = { createApp };