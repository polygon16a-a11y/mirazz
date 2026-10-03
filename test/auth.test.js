const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { DatabaseSync } = require('node:sqlite');
const { createApp } = require('../server');

test('accounts persist hashed passwords and issue revocable sessions', async (context) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'relay-auth-'));
  const databasePath = path.join(directory, 'accounts.sqlite');
  const server = createApp(databasePath, {
    rateLimits: { login: 2, register: 5, windowMs: 60_000 }
  });
  server.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const email = 'reader@example.test';
  const password = 'correct-horse-battery-staple';

  context.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  });

  const registerResponse = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  assert.equal(registerResponse.status, 201);
  const registrationCookie = registerResponse.headers.getSetCookie()[0];
  assert.match(registrationCookie, /HttpOnly/);
  assert.match(registrationCookie, /SameSite=Strict/);
  const registrationToken = registrationCookie.split(';')[0];

  const database = new DatabaseSync(databasePath);
  const account = database.prepare('SELECT email, password_hash FROM users').get();
  assert.equal(account.email, email);
  assert.equal(account.password_hash.length, 64);
  assert.notEqual(account.password_hash.toString(), password);
  database.close();

  let response = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: registrationToken }
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { user: { email } });

  response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  assert.equal(response.status, 409);

  response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.getSetCookie()[0], /HttpOnly/);

  response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'not-the-password' })
  });
  assert.equal(response.status, 401);

  response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'not-the-password' })
  });
  assert.equal(response.status, 429);
  assert.ok(Number(response.headers.get('retry-after')) > 0);

  response = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Cookie: registrationToken }
  });
  assert.equal(response.status, 200);
  response = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: registrationToken }
  });
  assert.equal(response.status, 401);
});

test('Bitcoin receive addresses are validated and stored per account', async (context) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'relay-bitcoin-'));
  const databasePath = path.join(directory, 'accounts.sqlite');
  const address = `tb1${'q'.repeat(30)}`;
  const server = createApp(databasePath, { bitcoinNetwork: 'testnet' });
  server.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  context.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  });

  async function register(email) {
    const response = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'correct-horse-battery-staple' })
    });
    assert.equal(response.status, 201);
    return response.headers.getSetCookie()[0].split(';')[0];
  }

  const firstCookie = await register('first@example.test');
  let response = await fetch(`${baseUrl}/api/wallet`, { headers: { Cookie: firstCookie } });
  assert.deepEqual(await response.json(), { network: 'testnet', bitcoinAddress: null });

  response = await fetch(`${baseUrl}/api/wallet`, {
    method: 'PUT',
    headers: { Cookie: firstCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ bitcoinAddress: '1BoatSLRHtKNngkdXEeobR76b53LETtpyT' })
  });
  assert.equal(response.status, 400, 'mainnet address is rejected when server uses testnet');

  response = await fetch(`${baseUrl}/api/wallet`, {
    method: 'PUT',
    headers: { Cookie: firstCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ bitcoinAddress: address })
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).bitcoinAddress, address);

  const secondCookie = await register('second@example.test');
  response = await fetch(`${baseUrl}/api/wallet`, { headers: { Cookie: secondCookie } });
  assert.deepEqual(await response.json(), { network: 'testnet', bitcoinAddress: null });

  response = await fetch(`${baseUrl}/api/wallet`);
  assert.equal(response.status, 401, 'wallet addresses require authentication');
});

test('health, CSP nonces, and mutation request guards work', async (context) => {
  const previousNodeEnv = process.env.NODE_ENV;
  const previousTrustProxy = process.env.TRUST_PROXY;
  process.env.NODE_ENV = 'production';
  process.env.TRUST_PROXY = 'true';
  const directory = mkdtempSync(path.join(tmpdir(), 'relay-security-'));
  const server = createApp(path.join(directory, 'accounts.sqlite'), {
    peer: { host: 'signal.example.test', port: 9443, path: '/signal', secure: true }
  });
  server.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  context.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
    if (previousTrustProxy === undefined) delete process.env.TRUST_PROXY;
    else process.env.TRUST_PROXY = previousTrustProxy;
  });

  let response = await fetch(`${baseUrl}/healthz`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });

  response = await fetch(`${baseUrl}/api/config`);
  assert.deepEqual(await response.json(), {
    peer: { host: 'signal.example.test', port: 9443, path: '/signal', secure: true }
  });

  response = await fetch(baseUrl);
  const page = await response.text();
  const contentSecurityPolicy = response.headers.get('content-security-policy');
  const nonce = page.match(/<script nonce="([^"]+)"/)[1];
  assert.ok(contentSecurityPolicy.includes(`'nonce-${nonce}'`));
  assert.ok(page.includes(`nonce="${nonce}"`));
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(contentSecurityPolicy, /wss:\/\/signal\.example\.test:9443/);
  assert.doesNotMatch(contentSecurityPolicy, /\*\.peerjs\.com/);
  assert.doesNotMatch(contentSecurityPolicy, /unpkg\.com/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');

  response = await fetch(`${baseUrl}/vendor/peerjs.min.js`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /javascript/);
  assert.match(await response.text(), /PeerJS/);

  response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { Origin: 'https://attacker.example', 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'guard@example.test', password: 'correct-horse-battery-staple' })
  });
  assert.equal(response.status, 403);

  response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ email: 'guard@example.test', password: 'correct-horse-battery-staple' })
  });
  assert.equal(response.status, 415);

  response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: {
      Origin: baseUrl,
      'X-Forwarded-Proto': 'https',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email: 'guard@example.test', password: 'correct-horse-battery-staple' })
  });
  assert.equal(response.status, 201);
  assert.match(response.headers.getSetCookie()[0], /Secure/);
  assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
});