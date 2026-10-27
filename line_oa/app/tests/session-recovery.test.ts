import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SessionManager, validSession } from '../src/session.js';
import { MemoryCookieJar } from '../src/cookie-jar.js';
import { BusinessQrLogin, extractRememberedLogin, extractLoginMetaRedirect } from '../src/qr-login.js';
import { LineClient, type RequestFn } from '../src/line-client.js';
import { SessionMonitor } from '../src/session-monitor.js';
import { MemoryLogger } from '../src/logger.js';
import { MessageSender } from '../src/sender.js';
import type { ContactService } from '../src/contacts.js';
import type { SessionCredentials } from '../src/types.js';
import { diagnosticText } from '../src/diagnostics.js';

const botId = `U${'a'.repeat(32)}`, chatId = `U${'b'.repeat(32)}`;
const query = new URLSearchParams({ loginChannelId: '1576775644', returnUri: '/oauth2/v2.1/authorize/consent?client_id=1576775644' });
const accessUrl = new URL(`https://access.line.me/oauth2/v2.1/login?${query}`);
function confirmation(target = `/oauth2/v2.1/ssoLogin?${query}`) {
  const data = JSON.stringify({ props: { username: '測試', 'login-url': target }, slots: { field: [{ name: '__csrf', value: 'never-log-me' }] } });
  return `<app app-data="${data.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"></app>`;
}
const creds = (): SessionCredentials => ({ version: 1, botId, accountName: '原本官方帳號', importedAt: '2026-10-17T05:00:00Z',
  cookies: [{ name: 'ses', value: 'business-session' }, { name: '__Host-chat-ses', value: 'old-chat' }],
  loginCookies: [{ name: '__Host-SID', value: 'remembered-user', domain: 'access.line.me', path: '/', secure: true, hostOnly: true, expiresAt: Date.now() + 86400_000 }] });
function response(body: string, status = 200, location?: string, cookie?: string) {
  return new Response(body || null, { status, headers: { 'content-type': body.startsWith('{') ? 'application/json' : 'text/html',
    ...(location ? { location } : {}), ...(cookie ? { 'set-cookie': cookie } : {}) } });
}
async function fixture(options: { human?: boolean; network?: boolean; sendAuth?: string; meta?: boolean } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-recovery-'));
  const sessions = new SessionManager(dir); await sessions.importCredentials(creds());
  const original = globalThis.fetch, routes: string[] = [], posts: Array<{ path: string; body?: string | Buffer; cookie: string }> = [];
  let recoveries = 0;
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input)), path = url.pathname, headers = init?.headers as Record<string, string>;
    routes.push(`${init?.method ?? 'GET'} ${url.hostname}${path}`);
    assert.ok(!path.includes('/qrlogin/'), 'automatic recovery never requests QR/PIN');
    if (options.network) throw new TypeError('offline');
    if (url.hostname === 'chat.line.biz') {
      if (path === '/') return headers.Cookie?.includes('__Host-chat-ses=fresh-chat') ? response('<html>chat</html>') : response('', 302, 'https://account.line.biz/login');
      if (path === '/oauth2/linebiz/callback') return response('', 302, '/', '__Host-chat-ses=fresh-chat; Path=/; Secure; HttpOnly');
      if (path === '/api/v1/csrfToken') return response('{"token":"fresh-csrf"}');
      if (path.startsWith('/api/v2/bots/')) { assert.ok(path.includes(botId)); return response('{"list":[]}'); }
    }
    if (url.hostname === 'account.line.biz') {
      assert.doesNotMatch(headers.Cookie ?? '', /__Host-chat-ses|__Host-SID/);
      if (path === '/login') return response('<form method="POST" action="/login/line"><input type="hidden" name="_csrf" value="business-csrf"></form>');
      if (path === '/login/line') { assert.equal(init?.method, 'POST'); return response('', 302, accessUrl.toString()); }
      if (path === '/login/line-callback') return response('<form method="POST" action="/oauth2/callback"><input type="hidden" name="code" value="one-use-code"></form>');
      if (path === '/oauth2/callback') return response('', 302, 'https://chat.line.biz/oauth2/linebiz/callback', '__Host-ses-account=account-renewed; Path=/; Secure; HttpOnly');
    }
    if (url.hostname === 'access.line.me') {
      assert.doesNotMatch(headers.Cookie ?? '', /business-session|old-chat/);
      if (path === '/oauth2/v2.1/login') return response(options.human ? '<html>Scan QR</html>' : confirmation());
      if (path === '/oauth2/v2.1/ssoLogin') {
        assert.match(headers.Cookie ?? '', /__Host-SID=remembered-user/); recoveries++;
        return options.meta ? response('<html><head><meta http-equiv="refresh" content="0; url=https://account.line.biz/login/line-callback"></head><body></body></html>') : response('', 302, 'https://account.line.biz/login/line-callback');
      }
    }
    throw new Error(`Unexpected synthetic route ${url.origin}${path}`);
  };
  let rejected = false;
  const request: RequestFn = async (method, path, headers, body) => {
    if (method === 'POST') {
      posts.push({ path, body, cookie: headers.Cookie! });
      if (options.sendAuth && path.endsWith(options.sendAuth) && !rejected) { rejected = true; return { status: 401, body: { code: 'not_login' }, contentType: 'application/json' }; }
      return { status: 200, body: path.endsWith('/uploadFile') ? { contentMessageToken: 'image-token' } : {}, contentType: 'application/json' };
    }
    const ok = path.includes('csrfToken') || !!options.sendAuth || !!headers.Cookie?.includes('fresh-chat');
    return { status: ok ? 200 : 401, body: path.includes('csrfToken') ? { token: 'csrf' } : ok ? { list: [] } : { code: 'not_login' }, contentType: 'application/json' };
  };
  const logger = new MemoryLogger(), login = new BusinessQrLogin(sessions);
  const client = new LineClient(sessions, 1000, request, undefined, c => login.recover(c));
  const sender = new MessageSender(client, sessions, { resolve: () => ({ chatId, name: 'test' }) } as unknown as ContactService, logger, 1000, 10);
  const monitor = new SessionMonitor(sessions, client, logger, () => sender.isBusy());
  return { dir, sessions, login, client, sender, monitor, routes, posts, recoveries: () => recoveries,
    async close() { login.close(); monitor.stop(); globalThis.fetch = original; await rm(dir, { recursive: true, force: true }); } };
}

test('remembered-user parser accepts official app-data, rejects changed context, and redacts embedded secrets', () => {
  assert.equal(extractRememberedLogin(confirmation(), accessUrl)?.pathname, '/oauth2/v2.1/ssoLogin');
  for (const target of ['https://evil.example/oauth2/v2.1/ssoLogin', '/oauth2/v2.1/ssoLogin?loginChannelId=999999&returnUri=other']) assert.throws(() => extractRememberedLogin(confirmation(target), accessUrl), /LOGIN_REDIRECT_REJECTED/);
  assert.equal(extractRememberedLogin('<html>QR required</html>', accessUrl), undefined);
  assert.doesNotMatch(diagnosticText({ response: confirmation() }), /never-log-me/);
});

test('cookie persistence retains scoped authentication, drops intermediates, and obeys deletion', () => {
  const jar = new MemoryCookieJar(), url = new URL('https://access.line.me/');
  for (const name of ['__Host-SID', 'cert', 'qrPinCert', 'X-SCGW-CSRF-Token', 'qrSes', '_uts_cid']) jar.set(url, `${name}=secret; Path=/; Secure; Max-Age=3600`);
  jar.set(url, 'bad=bad; Domain=me; Secure');
  assert.deepEqual(jar.snapshot().map(c => c.name).sort(), ['__Host-SID', 'cert', 'qrPinCert'].sort());
  const restored = new MemoryCookieJar(); restored.restore(jar.snapshot());
  assert.match(restored.header(url), /__Host-SID=secret/); assert.equal(restored.header(new URL('https://chat.line.biz/')), '');
  restored.set(url, '__Host-SID=gone; Secure; Path=/; Max-Age=0; Expires=Wed, 01 Jan 2040 00:00:00 GMT');
  assert.doesNotMatch(restored.header(url), /__Host-SID/);
  assert.equal(validSession({ ...creds(), loginCookies: [{ ...creds().loginCookies![0], domain: 'evil.example' }] }), false);
});

test('background 401 recovers the same OA, persists privately, and survives restart', async () => {
  const h = await fixture();
  try {
    const original = h.sessions.getCredentials(); await h.monitor.check();
    assert.equal(h.sessions.getStatus().state, 'CONNECTED'); assert.equal(h.sessions.getStatus().loginRequiredReason, undefined);
    assert.equal(h.sessions.getCredentials(), original); assert.equal(original?.botId, botId); assert.equal(original?.importedAt, creds().importedAt);
    assert.equal(h.recoveries(), 1);
    if (process.platform !== 'win32') assert.equal((await stat(join(h.dir, 'secrets/line-session.json'))).mode & 0o777, 0o600);
    const restarted = new SessionManager(h.dir); await restarted.load();
    assert.equal(restarted.getCredentials()?.cookies.find(c => c.name === '__Host-chat-ses')?.value, 'fresh-chat');
    assert.ok(restarted.getCredentials()?.loginCookies?.some(c => c.name === '__Host-SID'));
    assert.ok(h.routes.every(r => !r.includes('send')));
  } finally { await h.close(); }
});

test('concurrent foreground/background validation shares one recovery', async () => {
  const h = await fixture();
  try { await Promise.all([h.client.validate(), h.client.validate(), h.monitor.check()]); assert.equal(h.recoveries(), 1); assert.equal(h.sessions.getStatus().state, 'CONNECTED'); }
  finally { await h.close(); }
});

test('text/image preflight recovers before submitting a message', async () => {
  for (const image of [false, true]) {
    const h = await fixture();
    try {
      const result = image ? await h.sender.sendImage('home', Buffer.from('image'), 'image/png') : await h.sender.send('home', 'test');
      assert.equal(result.result, 'SUBMITTED'); assert.equal(h.recoveries(), 1); assert.equal(h.posts.length, image ? 2 : 1);
      assert.ok(h.posts.every(p => p.cookie.includes('fresh-chat')));
    } finally { await h.close(); }
  }
});

test('explicit not_login on text/upload/image submission retries the rejected operation once with the same payload', async () => {
  for (const suffix of ['/send', '/uploadFile', '/bulkSendFiles']) {
    const h = await fixture({ sendAuth: suffix });
    try {
      const result = suffix === '/send' ? await h.sender.send('home', 'test') : await h.sender.sendImage('home', Buffer.from('image'), 'image/png');
      assert.equal(result.result, 'SUBMITTED'); assert.equal(h.recoveries(), 1);
      const retried = h.posts.filter(p => p.path.endsWith(suffix));
      assert.equal(retried.length, 2); assert.deepEqual(retried[0]!.body, retried[1]!.body); assert.match(retried[1]!.cookie, /fresh-chat/);
      if (suffix === '/bulkSendFiles') assert.equal(h.posts.filter(p => p.path.endsWith('/uploadFile')).length, 1);
    } finally { await h.close(); }
  }
});

test('human-only login expires once; recovery network failure remains retryable', async () => {
  for (const network of [false, true]) {
    const h = await fixture(network ? { network: true } : { human: true });
    try {
      await h.monitor.check(); assert.equal(h.sessions.getStatus().state, network ? 'DISCONNECTED' : 'EXPIRED');
      const calls = h.routes.length; await h.monitor.check(); if (!network) assert.equal(h.routes.length, calls);
      assert.equal(h.posts.length, 0); assert.equal(h.sessions.getCredentials()?.cookies.find(c => c.name === '__Host-chat-ses')?.value, 'old-chat');
    } finally { await h.close(); }
  }
});

test('successful API Set-Cookie rotation persists and is used by the next request', async () => {
  const h = await fixture();
  try {
    const client = new LineClient(h.sessions, 1000, async (_m, path, headers) => {
      if (path.includes('csrfToken')) return { status: 200, body: { token: 'new-csrf' }, contentType: 'application/json', headers: { 'set-cookie': ['__Host-chat-ses=rotated; Path=/; Secure; HttpOnly'] } };
      assert.match(headers.Cookie!, /__Host-chat-ses=rotated/); return { status: 200, body: { list: [] }, contentType: 'application/json' };
    });
    await client.validate(); const saved = JSON.parse(await readFile(join(h.dir, 'secrets/line-session.json'), 'utf8'));
    assert.equal(saved.cookies.find((c: { name: string }) => c.name === '__Host-chat-ses').value, 'rotated');
  } finally { await h.close(); }
});

test('logout/new login beats pending recovery', async () => {
  for (const mode of ['logout', 'login'] as const) {
    const h = await fixture(), fetch = globalThis.fetch;
    let release!: () => void, started!: () => void;
    const pending = new Promise<void>(r => { release = r; }), entered = new Promise<void>(r => { started = r; });
    globalThis.fetch = async (...args) => { started(); await pending; return fetch(...args); };
    try {
      const recovery = h.login.recover(h.sessions.getCredentials()!), rejected = assert.rejects(recovery); await entered;
      if (mode === 'logout') await h.sessions.logout(); else await h.sessions.importCredentials({ ...creds(), botId: `U${'c'.repeat(32)}` });
      release(); await rejected; const saved = JSON.parse(await readFile(join(h.dir, 'secrets/line-session.json'), 'utf8'));
      assert.equal(saved?.botId, mode === 'logout' ? undefined : `U${'c'.repeat(32)}`);
    } finally { release(); await h.close(); }
  }
});

test('unknown sends/other failures never retry; repeated not_login only retries once', async () => {
  const h = await fixture();
  try {
    for (const status of [0, 403, 429, 500, 401]) {
      let calls = 0, repairs = 0;
      const client = new LineClient(h.sessions, 1000, async () => { calls++; if (!status) throw new Error('timeout'); return { status, body: {}, contentType: 'application/json' }; }, undefined, async () => { repairs++; });
      const result = await client.sendText(chatId, 'test'); assert.equal(calls, 1); assert.equal(repairs, 0); assert.equal(result.result, status ? 'FAILED' : 'UNKNOWN');
    }
    let calls = 0, repairs = 0;
    const client = new LineClient(h.sessions, 1000, async () => { calls++; return { status: 401, body: { code: 'not_login' }, contentType: 'application/json' }; }, undefined, async () => { repairs++; });
    assert.equal((await client.sendText(chatId, 'test')).result, 'FAILED'); assert.equal(calls, 2); assert.equal(repairs, 1);
    const broken = new LineClient(h.sessions, 1000, async () => ({ status: 401, body: { code: 'not_login' }, contentType: 'application/json' }), undefined, async () => { throw new Error('LOGIN_NETWORK_ERROR'); });
    const result = await broken.sendText(chatId, 'test'); assert.equal(result.result, 'FAILED'); assert.equal(result.error, 'NETWORK');
  } finally { await h.close(); }
});

test('late successful Cookie responses cannot overwrite a newer session or defeat logout', async () => {
  const h = await fixture();
  try {
    const expected = h.sessions.getCredentials()!;
    const cookie = expected.cookies.map(c => `${c.name}=${c.value}`).join('; ');
    await Promise.all([
      h.sessions.updateCookies(['__Host-chat-ses=newest; Path=/; Secure'], expected, cookie),
      h.sessions.updateCookies(['__Host-chat-ses=late; Path=/; Secure'], expected, cookie)
    ]);
    assert.equal(expected.cookies.find(c => c.name === '__Host-chat-ses')?.value, 'newest');
    const renewal = h.sessions.renewCredentials({ ...expected, csrfToken: 'late' }, expected);
    const rejected = assert.rejects(renewal, /SESSION_CHANGED/);
    await h.sessions.logout(); await rejected;
    assert.equal(JSON.parse(await readFile(join(h.dir, 'secrets/line-session.json'), 'utf8')), null);
  } finally { await h.close(); }
});

test('send-time recovery network failure reports disconnected rather than requiring human login', async () => {
  const h = await fixture({ network: true, sendAuth: '/send' });
  try {
    const result = await h.sender.send('home', 'synthetic');
    assert.equal(result.result, 'FAILED'); assert.equal(result.error, 'NETWORK');
    assert.equal(h.sessions.getStatus().state, 'DISCONNECTED'); assert.equal(h.sessions.getStatus().loginRequiredReason, undefined);
    assert.equal(h.posts.length, 1);
  } finally { await h.close(); }
});


test('official SSO meta refresh continues to the same OA; external refresh targets fail closed', async () => {
  const h = await fixture({ meta: true });
  try { await h.monitor.check(); assert.equal(h.sessions.getStatus().state, 'CONNECTED'); assert.equal(h.recoveries(), 1); }
  finally { await h.close(); }
  const html = '<meta content="0; url=https://account.line.biz/login/line-callback?code=synthetic&amp;state=synthetic" http-equiv="Refresh">';
  assert.equal(extractLoginMetaRedirect(html, accessUrl)?.hostname, 'account.line.biz');
  for (const target of ['https://evil.example/login', 'http://access.line.me/login', 'https://user:password@access.line.me/login']) {
    assert.throws(() => extractLoginMetaRedirect(`<meta http-equiv="refresh" content="0;url=${target}">`, accessUrl), /LOGIN_REDIRECT_REJECTED/);
  }
});
