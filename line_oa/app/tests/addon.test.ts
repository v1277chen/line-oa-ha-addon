import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, writeFile, stat, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AddressInfo } from 'node:net';
import http, { type IncomingMessage } from 'node:http';
import { AuthManager } from '../src/auth.js';
import { PairingManager, BOOTSTRAP_TTL_MS } from '../src/pairing.js';
import { DiscoveryPublisher, supervisorRequest, type SupervisorRequest } from '../src/discovery.js';
import { createGateway, type GatewayOptions } from '../src/server.js';
import { trustedIngress } from '../src/ingress.js';
import { atomicWriteJson } from '../src/storage.js';
import type { RequestFn } from '../src/line-client.js';
import type { BusinessQrLogin } from '../src/qr-login.js';

const secret = () => randomBytes(32).toString('base64url');
const temp = () => mkdtemp(join(tmpdir(), 'line-oa-addon-'));
const payload = (pairing: PairingManager) => ({ instance_id: pairing.instanceId,
  bootstrap_token: pairing.discovery().bootstrap_token, request_id: randomUUID(), client: 'homeassistant-line_oa' });

test('pairing rejects wrong secrets, instance, expiry, replay and concurrent exchange', async () => {
  const dir = await temp();
  try {
    const auth = new AuthManager(dir, false); await auth.load();
    let now = Date.now();
    const pairing = new PairingManager(auth, randomUUID(), () => now);
    const first = payload(pairing);
    await assert.rejects(pairing.exchange({ ...first, bootstrap_token: secret() }), /PAIRING_REJECTED/);
    await assert.rejects(pairing.exchange({ ...first, instance_id: randomUUID() }), /PAIRING_REJECTED/);
    now += BOOTSTRAP_TTL_MS + 1;
    await assert.rejects(pairing.exchange(first), /PAIRING_REJECTED/);
    const next = payload(pairing);
    assert.notEqual(next.bootstrap_token, first.bootstrap_token);
    const results = await Promise.allSettled([pairing.exchange(next), pairing.exchange(next)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    const success = results.find(r => r.status === 'fulfilled') as PromiseFulfilledResult<Record<string, unknown>>;
    const key = String(success.value.api_key);
    assert.equal(auth.validApiKey(`Bearer ${key}`), true);
    await assert.rejects(pairing.exchange(next), /PAIRING_REJECTED/);
    assert.equal(pairing.discovery().bootstrap_token, undefined);
    assert.doesNotMatch(JSON.stringify(pairing.status()), new RegExp(key));
    const stored = await readFile(join(dir, 'secrets/api-key.json'), 'utf8');
    assert.equal(stored.includes(key), false);
    if (process.platform !== 'win32') assert.equal((await stat(join(dir, 'secrets/api-key.json'))).mode & 0o777, 0o600);
    const restarted = new AuthManager(dir, false); await restarted.load();
    assert.equal(restarted.validApiKey(`Bearer ${key}`), true);
    const again = new PairingManager(restarted, pairing.instanceId);
    assert.equal(again.discovery().bootstrap_token, undefined);
    await again.revoke();
    assert.equal(restarted.validApiKey(`Bearer ${key}`), false);
    const rotated = await again.exchange(payload(again));
    assert.notEqual(rotated.api_key, key);
    assert.equal(restarted.validApiKey(`Bearer ${key}`), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('pairing enforces global attempt budget, malformed bodies and corruption fail closed', async () => {
  const dir = await temp();
  try {
    const auth = new AuthManager(dir, false); await auth.load();
    let now = Date.now();
    const pairing = new PairingManager(auth, randomUUID(), () => now);
    for (let i = 0; i < 5; i++) await assert.rejects(pairing.exchange({}), /INVALID_PAIRING_REQUEST/);
    await assert.rejects(pairing.exchange(payload(pairing)), /PAIRING_RATE_LIMITED/);
    now += 60_001;
    await pairing.exchange(payload(pairing));
    await writeFile(join(dir, 'secrets/api-key.json'), 'invalid');
    await assert.rejects(new AuthManager(dir, false).load(), /API_CREDENTIAL_CORRUPT/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('discovery uses actual Supervisor hostname, retries, upserts and refreshes expired tokens', async () => {
  const dir = await temp();
  try {
    const auth = new AuthManager(dir, false); await auth.load();
    let now = Date.now(); let offline = true;
    const pairing = new PairingManager(auth, randomUUID(), () => now);
    const records = new Map<string, unknown>();
    const request: SupervisorRequest = async (path, _method, body) => {
      if (offline) throw new Error('offline');
      if (path === '/addons/self/info') return { hostname: 'a1b2c3d4-line-oa' };
      const message = body as { service: string; config: Record<string, unknown> };
      records.set(message.service, message.config); return { uuid: randomUUID() };
    };
    const publisher = new DiscoveryPublisher(pairing, request);
    await publisher.publish(); assert.equal(publisher.status, 'retrying');
    offline = false; await publisher.publish();
    const first = structuredClone(records.get('line_oa')) as Record<string, unknown>;
    assert.equal(first.host, 'a1b2c3d4-line-oa'); assert.equal(first.port, 8787);
    await publisher.publish(); assert.equal(records.size, 1); assert.deepEqual(records.get('line_oa'), first);
    now += BOOTSTRAP_TTL_MS + 1; await publisher.publish();
    assert.notEqual((records.get('line_oa') as Record<string, unknown>).bootstrap_token, first.bootstrap_token);
    await pairing.exchange(payload(pairing)); await publisher.publish();
    assert.equal((records.get('line_oa') as Record<string, unknown>).bootstrap_token, undefined);
    // Restarting the publisher without resetting data republishes the same identity.
    await new DiscoveryPublisher(pairing, request).publish(); assert.equal(records.size, 1);
    assert.equal((records.get('line_oa') as Record<string, unknown>).instance_id, pairing.instanceId);
    publisher.stop();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

function port(server: http.Server): number { return (server.address() as AddressInfo).port; }
async function running(options: GatewayOptions = {}) {
  const dir = options.dataDir ?? await temp();
  const gateway = await createGateway({ ...options, dataDir: dir });
  await gateway.start(0, 0, '127.0.0.1');
  const api = `http://127.0.0.1:${port(gateway.apiServer)}`;
  const ui = `http://127.0.0.1:${port(gateway.uiServer)}`;
  return { dir, gateway, api, ui, async close() { await gateway.stop(); await rm(dir, { recursive: true, force: true }); } };
}
const ingressHeaders = { 'X-Ingress-Path': '/api/hassio_ingress/mockprefix' };
async function browserSession(ui: string) {
  const response = await fetch(`${ui}/api/auth/session`, { headers: ingressHeaders });
  const state = await response.json() as { csrfToken: string };
  const cookie = response.headers.get('set-cookie')!;
  assert.match(cookie, /Path=\/api\/hassio_ingress\/mockprefix\//);
  return { ...ingressHeaders, Cookie: cookie.split(';')[0]!, 'X-CSRF-Token': state.csrfToken };
}

test('actual socket, not forwarded user headers, protects Ingress; API port excludes management', async () => {
  const h = await running();
  try {
    assert.equal(trustedIngress({ socket: { remoteAddress: '172.30.32.2' } } as IncomingMessage), true);
    assert.equal((await fetch(h.ui, { headers: { ...ingressHeaders, 'X-Remote-User-Id': 'admin', 'X-Forwarded-For': '172.30.32.2' } })).status, 403);
    for (const path of ['/api/pairing/status', '/api/api-key', '/api/session/qr/start', '/']) {
      assert.equal((await fetch(h.api + path)).status, 404);
    }
    const health = await (await fetch(h.api + '/api/v1/health')).json();
    assert.deepEqual(health, { status: 'ok', version: '0.1.9', api_version: 1 });
    for (const path of ['/api/v1/status', '/api/v1/aliases']) assert.equal((await fetch(h.api + path)).status, 401);
    const b = payload(h.gateway.pairing);
    assert.equal((await fetch(h.api + '/api/v1/pairing/exchange', { method: 'POST', headers: { Origin: 'http://attacker', 'Content-Type': 'application/json' }, body: JSON.stringify(b) })).status, 403);
  } finally { await h.close(); }
});

test('Ingress relative assets, CSRF, QR routes, logout, reset and internal credentials remain separate', async () => {
  let qrOwner = ''; let selection = '';
  const qr = { close() {}, cancel(owner: string) { qrOwner = ''; },
    async start(owner: string) { qrOwner = owner; return { status: 'selecting', hasQr: true, choices: [{ id: 'mockchoice123456', label: 'Mock OA' }] }; },
    state(owner: string) { return { status: qrOwner === owner ? 'selecting' : 'idle', hasQr: !!qrOwner }; },
    image() { return Buffer.from([137,80,78,71,13,10,26,10]); },
    async select(owner: string, choice: string) { assert.equal(owner, qrOwner); selection = choice; return { status: 'ok', hasQr: false }; }
  } as unknown as BusinessQrLogin;
  const h = await running({ ingressTrust: () => true, qrLogin: qr });
  try {
    const headers = await browserSession(h.ui);
    for (const path of ['/', '/index.html', '/app.js', '/style.css']) {
      const res = await fetch(h.ui + path, { headers }); assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
      const body = await res.text();
      assert.doesNotMatch(body, /(?:href|src)="\//);
      if (path === '/app.js') assert.doesNotMatch(body, /(?:fetch|api)\(['"`]\//);
    }
    assert.equal((await fetch(h.ui + '/api/pairing/reset', { method: 'POST', headers: ingressHeaders })).status, 401);
    assert.equal((await fetch(h.ui + '/api/pairing/reset', { method: 'POST', headers: { ...headers, 'X-CSRF-Token': '' } })).status, 403);
    assert.equal((await fetch(h.ui + '/api/pairing/reset', { method: 'POST', headers: { ...headers, Origin: 'http://evil.example' } })).status, 403);
    for (const path of ['/api/session/qr/start', '/api/session/qr/select']) {
      const res = await fetch(h.ui + path, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ choiceId: 'mockchoice123456' }) }); assert.equal(res.status, 200);
    }
    assert.equal(selection, 'mockchoice123456');
    assert.equal((await fetch(h.ui + '/api/session/qr/image', { headers })).status, 200);
    assert.equal((await fetch(h.ui + '/api/session/qr/status', { headers })).status, 200);
    const exchange = await fetch(h.api + '/api/v1/pairing/exchange', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload(h.gateway.pairing)) });
    assert.equal(exchange.status, 201);
    const key = String((await exchange.json() as Record<string, unknown>).api_key);
    for (const path of ['/api/status', '/api/pairing/status', '/api/logs']) {
      const body = await (await fetch(h.ui + path, { headers })).text(); assert.equal(body.includes(key), false); assert.equal(body.includes('bootstrap_token'), false);
    }
    const publicStatus = await (await fetch(h.api + '/api/v1/status', { headers: { Authorization: `Bearer ${key}` } })).json() as Record<string, unknown>;
    assert.equal(publicStatus.line_logged_in, false); assert.equal(publicStatus.session_status, 'auth_required');
    assert.equal(publicStatus.login_required_reason, 'not_logged_in');
    assert.equal((await fetch(h.ui + '/api/v1/status', { headers })).status, 404);
    assert.equal((await fetch(h.ui + '/api/pairing/reset', { method: 'POST', headers })).status, 200);
    assert.equal((await fetch(h.api + '/api/v1/status', { headers: { Authorization: `Bearer ${key}` } })).status, 401);
    assert.equal((await fetch(h.ui + '/api/auth/logout', { method: 'POST', headers })).status, 200);
    assert.equal((await fetch(h.ui + '/api/status', { headers })).status, 401);
  } finally { await h.close(); }
});

test('real API text/image contract, UNKNOWN deduplication, alias validation and temp cleanup with Mock LINE', async () => {
  let textPosts = 0; let imagePosts = 0; let unknown = false;
  const chatId = 'U' + randomBytes(16).toString('hex');
  const request: RequestFn = async (method, path) => {
    if (path === '/api/v1/csrfToken') return { status: 200, contentType: 'application/json', body: { token: secret() } };
    if (path.includes('/contacts?')) return { status: 200, contentType: 'application/json', body: { list: [{ contactId: chatId, profile: { name: 'Mock friend' }, friend: true }] } };
    if (method === 'POST' && path.endsWith('/messages/send')) { textPosts++; if (unknown) throw new Error('timeout'); }
    else if (path.endsWith('/uploadFile')) return { status: 200, contentType: 'application/json', body: { contentMessageToken: secret() } };
    else if (path.endsWith('/bulkSendFiles')) imagePosts++;
    else throw new Error('Unexpected Mock LINE call');
    return { status: 200, contentType: 'application/json', body: {} };
  };
  const dir = await temp();
  await atomicWriteJson(join(dir, 'secrets/line-session.json'), { version: 1, botId: 'U' + randomBytes(16).toString('hex'), importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses', value: secret() }] });
  const h = await running({ dataDir: dir, lineRequest: request, ingressTrust: () => true });
  try {
    await h.gateway.contacts.search('', true); await h.gateway.contacts.setAlias('simon', chatId);
    const paired = await h.gateway.pairing.exchange(payload(h.gateway.pairing));
    const headers = { Authorization: `Bearer ${paired.api_key}`, 'Content-Type': 'application/json' };
    const postText = async (body: unknown) => fetch(h.api + '/api/v1/messages/text', { method: 'POST', headers, body: JSON.stringify(body) });
    assert.equal((await postText({ who: 'absent', message: 'x' })).status, 404);
    const id = randomUUID(); unknown = true;
    for (let i = 0; i < 2; i++) { const res = await postText({ who: 'simon', message: 'mock unknown', request_id: id }); assert.equal(res.status, 202); assert.equal((await res.json() as Record<string, unknown>).status, 'unknown'); }
    assert.equal(textPosts, 1);
    unknown = false; assert.equal((await postText({ who: 'simon', message: 'mock success' })).status, 202); assert.equal(textPosts, 2);
    const form = new FormData(); form.set('who', 'simon'); form.set('request_id', randomUUID()); form.set('image', new Blob([Buffer.from([137,80,78,71,13,10,26,10,1])], { type: 'image/png' }), 'test.png');
    const res = await fetch(h.api + '/api/v1/messages/image', { method: 'POST', headers: { Authorization: headers.Authorization }, body: form });
    assert.equal(res.status, 202); assert.equal(imagePosts, 1);
    assert.deepEqual(await readdir(join(dir, 'tmp')), []);
    const uiHeaders = await browserSession(h.ui);
    // The original UI uploads raw PNG bytes rather than multipart.
    assert.equal((await fetch(h.ui + '/api/messages/image?target=simon', { method: 'POST', headers: { ...uiHeaders, 'Content-Type': 'image/png' }, body: Buffer.from([137,80,78,71,13,10,26,10,2]) })).status, 202);
    assert.equal(imagePosts, 2);
    assert.deepEqual(await readdir(join(dir, 'tmp')), []);
    h.gateway.sessions.mark('EXPIRED', 'mock expiry');
    assert.equal((await postText({ who: 'simon', message: 'expired' })).status, 409);
    assert.equal(textPosts, 2);
    await assert.rejects(readFile(join(dir, 'contacts.json')), { code: 'ENOENT' });
  } finally { await h.close(); }
});

test('restart retains stable identity, session, aliases, and credential; corrupt identity fails closed', async () => {
  const dir = await temp();
  const session = { version: 1, botId: 'U' + randomBytes(16).toString('hex'), importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses', value: secret() }] };
  await atomicWriteJson(join(dir, 'secrets/line-session.json'), session);
  await atomicWriteJson(join(dir, 'aliases.json'), { simon: { chatId: 'U' + randomBytes(16).toString('hex'), name: 'Mock' } });
  const one = await createGateway({ dataDir: dir });
  const paired = await one.pairing.exchange(payload(one.pairing));
  await one.stop();
  const two = await createGateway({ dataDir: dir });
  try {
    assert.equal(two.pairing.instanceId, paired.instance_id);
    assert.equal(two.auth.validApiKey(`Bearer ${paired.api_key}`), true);
    assert.deepEqual(two.sessions.getCredentials(), session);
    assert.ok(two.contacts.resolve('simon'));
    if (process.platform !== 'win32') {
      for (const path of ['secrets', 'tmp']) assert.equal((await stat(join(dir, path))).mode & 0o777, 0o700);
      assert.equal((await stat(join(dir, 'secrets/line-session.json'))).mode & 0o777, 0o600);
    }
    await writeFile(join(dir, 'config.json'), '{bad');
    await assert.rejects(createGateway({ dataDir: dir }), /CONFIG_CORRUPT/);
  } finally { await two.stop(); await rm(dir, { recursive: true, force: true }); }
});

test('Supervisor HTTP client authenticates with header only and rejects redirects', async () => {
  const supervisorToken = secret(); let seen = false;
  const server = http.createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${supervisorToken}`);
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/secret' }); res.end(); return; }
    assert.equal(req.url, '/addons/self/info'); seen = true;
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ result: 'ok', data: { hostname: 'local-line-oa' } }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const request = supervisorRequest(supervisorToken, `http://127.0.0.1:${port(server)}`);
    assert.deepEqual(await request('/addons/self/info'), { hostname: 'local-line-oa' }); assert.equal(seen, true);
    await assert.rejects(request('/redirect'));
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('LINE logout requires CSRF, retains pairing and aliases, and clears only LINE state', async () => {
  const h = await running({ ingressTrust: () => true, lineRequest: async () => ({ status: 200, contentType: 'application/json', body: { list: [] } }) });
  try {
    const headers = await browserSession(h.ui);
    await h.gateway.sessions.importCredentials({ version: 1, botId: 'U' + 'a'.repeat(32), importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses', value: secret() }] });
    const pair = await h.gateway.pairing.exchange(payload(h.gateway.pairing));
    const key = String(pair.api_key);
    const before = await readFile(join(h.dir, 'aliases.json'), 'utf8');
    for (const [token, name] of [['', 'WEB_UI_CSRF_TOKEN_MISSING'], ['invalid', 'WEB_UI_CSRF_TOKEN_MISMATCH']]) {
      const response = await fetch(h.ui + '/api/session/logout', { method: 'POST', headers: { ...headers, 'X-CSRF-Token': token! } });
      assert.equal(response.status, 403); assert.equal((await response.json() as { error_name: string }).error_name, name);
      assert.ok(h.gateway.sessions.getCredentials());
    }
    const response = await fetch(h.ui + '/api/session/logout', { method: 'POST', headers });
    assert.equal(response.status, 200);
    assert.equal(h.gateway.sessions.getCredentials(), undefined);
    assert.equal(h.gateway.sessions.getStatus().state, 'AUTH_REQUIRED');
    assert.equal(h.gateway.auth.validApiKey(`Bearer ${key}`), true);
    assert.equal(await readFile(join(h.dir, 'aliases.json'), 'utf8'), before);
    assert.equal((await fetch(h.ui + '/api/status', { headers })).status, 200);
  } finally { await h.close(); }
});

test('logout refuses while a submitted send is still waiting for the upstream response', async () => {
  let unblock!: () => void;
  let started!: () => void;
  const waiting = new Promise<void>(resolve => { started = resolve; });
  const pending = new Promise<void>(resolve => { unblock = resolve; });
  const chatId = 'U' + 'b'.repeat(32);
  const h = await running({ ingressTrust: () => true, lineRequest: async (_method, path) => {
    if (path === '/api/v1/csrfToken') return { status: 200, contentType: 'application/json', body: { token: secret() } };
    if (path.includes('/contacts?')) return { status: 200, contentType: 'application/json', body: { list: [{ contactId: chatId, profile: { name: 'Mock' } }] } };
    started(); await pending; return { status: 200, contentType: 'application/json', body: {} };
  } });
  let sending: Promise<Response> | undefined;
  try {
    const headers = { ...await browserSession(h.ui), 'Content-Type': 'application/json' };
    await h.gateway.sessions.importCredentials({ version: 1, botId: 'U' + 'a'.repeat(32), importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses', value: secret() }] });
    await h.gateway.contacts.search('', true); await h.gateway.contacts.setAlias('mock', chatId);
    sending = fetch(h.ui + '/api/messages/send', { method: 'POST', headers, body: JSON.stringify({ target: 'mock', message: 'synthetic only' }) });
    await waiting;
    const logout = await fetch(h.ui + '/api/session/logout', { method: 'POST', headers });
    assert.equal(logout.status, 409); assert.equal((await logout.json() as { error: string }).error, 'SEND_BUSY');
    assert.ok(h.gateway.sessions.getCredentials());
    unblock(); assert.equal((await sending).status, 202);
  } finally { unblock(); await sending; await h.close(); }
});

test('revoking __proto__ through the UI blocks text and image API sends with the same valid key', async () => {
  let posts = 0;
  const chatId = `U${'b'.repeat(32)}`;
  const h = await running({ ingressTrust: () => true, lineRequest: async (method, path) => {
    if (method === 'POST') posts++;
    return { status: 200, contentType: 'application/json', body: path.includes('csrfToken') ? { token: secret() }
      : path.includes('/contacts?') ? { list: [{ contactId: chatId, profile: { name: 'Synthetic friend' } }] } : {} };
  } });
  try {
    await h.gateway.sessions.importCredentials({ version: 1, botId: `U${'a'.repeat(32)}`, importedAt: new Date().toISOString(),
      cookies: [{ name: '__Host-chat-ses', value: secret() }] });
    const uiHeaders = { ...await browserSession(h.ui), 'Content-Type': 'application/json' };
    assert.equal((await fetch(h.ui + '/api/contacts/refresh', { method: 'POST', headers: uiHeaders, body: '{}' })).status, 200);
    const added = await fetch(h.ui + '/api/aliases', { method: 'PUT', headers: uiHeaders, body: JSON.stringify({ alias: '__proto__', chatId }) });
    assert.equal(added.status, 200);
    const paired = await h.gateway.pairing.exchange(payload(h.gateway.pairing));
    const auth = { Authorization: `Bearer ${paired.api_key}` };
    const send = (message: string) => fetch(h.api + '/api/v1/messages/text', { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ who: '__proto__', message, request_id: randomUUID() }) });
    assert.equal((await send('before revocation')).status, 202); assert.equal(posts, 1);
    assert.equal((await fetch(h.ui + '/api/aliases/__proto__', { method: 'DELETE', headers: uiHeaders })).status, 200);
    assert.equal(h.gateway.auth.validApiKey(auth.Authorization), true);
    const denied = await send('after revocation');
    assert.equal(denied.status, 404);
    assert.equal((await denied.json() as { error: { code: string } }).error.code, 'ALIAS_NOT_FOUND');
    const form = new FormData(); form.set('who', '__proto__'); form.set('request_id', randomUUID());
    form.set('image', new Blob([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 1])], { type: 'image/png' }), 'synthetic.png');
    const image = await fetch(h.api + '/api/v1/messages/image', { method: 'POST', headers: auth, body: form });
    assert.equal(image.status, 404); assert.equal(posts, 1);
    assert.deepEqual(await readdir(join(h.dir, 'tmp')), []);
  } finally { await h.close(); }
});

test('idle LINE expiry reaches the authenticated status API; explicit logout has its own reason', async () => {
  let upstream = 200;
  const h = await running({ sessionCheckDelayMs: () => 10, lineRequest: async (method, path) => {
    assert.equal(method, 'GET');
    return { status: upstream, body: path.includes('csrfToken') ? { token: secret() } : { list: [] }, contentType: 'application/json' };
  } });
  try {
    const paired = await h.gateway.pairing.exchange(payload(h.gateway.pairing));
    const headers = { Authorization: `Bearer ${paired.api_key}` };
    const status = async () => (await (await fetch(h.api + '/api/v1/status', { headers })).json()) as Record<string, unknown>;
    const waitFor = async (expected: string) => {
      for (let i = 0; i < 100; i++) {
        const value = await status();
        if (value.session_status === expected) return value;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.fail(`Session did not become ${expected}`);
    };
    await h.gateway.sessions.importCredentials({ version: 1, botId: `U${'a'.repeat(32)}`, importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses', value: secret() }] });
    assert.equal((await waitFor('ready')).line_logged_in, true);
    upstream = 401;
    const expired = await waitFor('expired');
    assert.equal(expired.line_logged_in, false); assert.equal(expired.login_required_reason, 'expired');
    assert.equal(h.gateway.auth.validApiKey(headers.Authorization), true);
    await h.gateway.sessions.logout();
    const loggedOut = await status();
    assert.equal(loggedOut.session_status, 'auth_required'); assert.equal(loggedOut.login_required_reason, 'logged_out');
  } finally { await h.close(); }
});
