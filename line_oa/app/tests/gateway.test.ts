import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { atomicWriteJson, readJsonSafe } from '../src/storage.js';
import { validSession, SessionManager } from '../src/session.js';
import { LineClient, type RequestFn } from '../src/line-client.js';
import { ImageSender } from '../src/images.js';
import { AuthManager } from '../src/auth.js';
import { MessageSender } from '../src/sender.js';
import type { ContactService } from '../src/contacts.js';
import { MemoryLogger } from '../src/logger.js';
import { MemoryCookieJar, extractLineLoginForm, extractQrOptions } from '../src/qr-login.js';
import { randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';

const credentials = { version: 1 as const, botId: `U${'a'.repeat(32)}`, accountName: '測試帳號', csrfToken: 'csrf', clientVersion: '1', importedAt: new Date().toISOString(), cookies: [{ name: '__Host-chat-ses' as const, value: 'secret' }] };
function fakeSession(): SessionManager {
  return { getCredentials: () => credentials, updateCsrf: async (token: string) => { credentials.csrfToken = token; }, mark: () => undefined } as unknown as SessionManager;
}

test('Session schema rejects missing session cookie', () => {
  assert.equal(validSession(credentials), true);
  assert.equal(validSession({ ...credentials, cookies: [] }), false);
});

test('QR login cookie jar enforces host, path and Secure scope', () => {
  const jar = new MemoryCookieJar();
  jar.set(new URL('https://chat.line.biz/login'), '__Host-chat-ses=abc; Path=/; Secure; HttpOnly');
  jar.set(new URL('https://access.line.me/qrlogin/v1/session'), 'qrSes=xyz; Path=/; Secure; HttpOnly');
  jar.set(new URL('https://access.line.me/'), 'bad=value; Domain=attacker.example; Path=/');
  assert.match(jar.header(new URL('https://chat.line.biz/api')), /__Host-chat-ses=abc/);
  assert.doesNotMatch(jar.header(new URL('https://access.line.me/api')), /__Host-chat-ses/);
  assert.match(jar.header(new URL('https://access.line.me/api')), /qrSes=xyz/);
  assert.equal(jar.header(new URL('http://access.line.me/api')), '');
});

test('QR login page parsers accept only the expected official flow shapes', () => {
  const form = extractLineLoginForm('<form method="POST" action="/login/line?disableLineAutoLogin=false&amp;type=login"><input value="csrf-value" name="_csrf" type="hidden"></form>', new URL('https://account.line.biz/login'));
  assert.equal(form.action.hostname, 'account.line.biz'); assert.equal(form.csrf, 'csrf-value');
  const options = extractQrOptions('<script>const x=["/qrlogin/v1/qr/token_1","/qrlogin/v1/pin/token_2","/qrlogin/oauth2/v2.1/token_3"]</script>', new URL('https://access.line.me/oauth2/v2.1/login?loginChannelId=1576775644'));
  assert.deepEqual(options, { channelId: '1576775644', returnUri: '/qrlogin/oauth2/v2.1/token_3', waitQrPath: '/qrlogin/v1/qr/token_1', waitPinPath: '/qrlogin/v1/pin/token_2' });
  assert.throws(() => extractQrOptions('<script></script>', new URL('https://access.line.me/oauth2/v2.1/login?loginChannelId=bad')), /LOGIN_QR_OPTIONS_CHANGED/);
});

test('JSON storage writes atomically and validates', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'loagw-test-'));
  try {
    const path = join(dir, 'value.json'); await atomicWriteJson(path, { ok: true });
    const loaded = await readJsonSafe(path, { ok: false }, (v): v is { ok: boolean } => !!v && typeof v === 'object' && typeof (v as { ok?: unknown }).ok === 'boolean');
    assert.deepEqual(loaded.value, { ok: true }); assert.match(await readFile(path, 'utf8'), /"ok": true/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('QR completion imports credentials atomically into SessionManager', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'loagw-session-'));
  try {
    const manager = new SessionManager(dir); await manager.load(); await manager.importCredentials(credentials);
    assert.equal(manager.getStatus().state, 'VALIDATING');
    assert.equal(manager.getCredentials()?.botId, credentials.botId);
    if (process.platform !== 'win32') assert.equal((await stat(join(dir, 'secrets', 'line-session.json'))).mode & 0o777, 0o600);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('LINE client queries contacts with verified parameters', async () => {
  let seenPath = '';
  const request: RequestFn = async (_method, path) => { seenPath = path; return { status: 200, contentType: 'application/json', body: { list: [{ contactId: `U${'b'.repeat(32)}`, profile: { name: '王小明', userId: `U${'b'.repeat(32)}` }, friend: true, chatAvailable: true }] } }; };
  const client = new LineClient(fakeSession(), 100, request);
  const result = await client.getContacts('王', 20);
  assert.equal(result.list[0]?.name, '王小明'); assert.match(seenPath, /sortKey=DISPLAY_NAME/); assert.match(seenPath, /query=%E7%8E%8B/);
});

test('text send uses one exact textV2 POST and reports SUBMITTED', async () => {
  let attempts = 0; let sentBody = '';
  const request: RequestFn = async (method, _path, _headers, body) => { assert.equal(method, 'POST'); attempts++; sentBody = body?.toString() ?? ''; return { status: 200, body: {}, contentType: 'application/json' }; };
  const result = await new LineClient(fakeSession(), 100, request).sendText(`U${'b'.repeat(32)}`, '中文\nUnicode ✓');
  assert.equal(result.result, 'SUBMITTED'); assert.equal(attempts, 1); assert.equal(JSON.parse(sentBody).type, 'textV2');
});

test('send timeout is UNKNOWN and never retried', async () => {
  let attempts = 0;
  const request: RequestFn = async () => { attempts++; throw new Error('timeout'); };
  const result = await new LineClient(fakeSession(), 100, request).sendText(`U${'b'.repeat(32)}`, 'test');
  assert.equal(result.result, 'UNKNOWN'); assert.equal(attempts, 1);
});

test('explicit LINE rejection is FAILED', async () => {
  const request: RequestFn = async () => ({ status: 403, body: {}, contentType: 'application/json' });
  const result = await new LineClient(fakeSession(), 100, request).sendText(`U${'b'.repeat(32)}`, 'test');
  assert.deepEqual({ result: result.result, error: result.error }, { result: 'FAILED', error: 'CSRF' });
});

test('image validation enforces format, capacity and cleanup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'loagw-image-'));
  const images = new ImageSender(dir, 16, 20); await images.init();
  const png = Buffer.from([137,80,78,71,13,10,26,10,1,2]);
  const path = await images.stage(png, 'image/png'); assert.equal(await images.totalBytes(), 10);
  assert.throws(() => images.validate(Buffer.alloc(21), 'image/png'), /IMAGE_SIZE_LIMIT/);
  assert.throws(() => images.validate(Buffer.alloc(10), 'image\/gif'), /IMAGE_TYPE_NOT_ALLOWED/);
  await images.remove(path); assert.equal(await images.totalBytes(), 0); await rm(dir, { recursive: true, force: true });
});

test('admin authentication hashes password and checks CSRF', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'loagw-auth-')); const secrets = join(dir, 'secrets');
  const salt = randomBytes(16); const hash = await promisify(scryptCallback)('very-strong-password', salt, 32) as Buffer;
  await atomicWriteJson(join(secrets, 'admin-password.json'), { version: 1, salt: salt.toString('hex'), hash: hash.toString('hex') });
  const auth = new AuthManager(dir, false); await auth.load(); const login = await auth.login('very-strong-password', 'local');
  const session = auth.browserSession(login.cookie); assert.ok(session); assert.equal(auth.validCsrf(session!, login.csrf), true);
  await assert.rejects(() => auth.login('wrong-password', 'other'), /INVALID_CREDENTIALS/); await rm(dir, { recursive: true, force: true });
});

test('passwordless UI still uses an anonymous HttpOnly session and CSRF', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'loagw-anon-'));
  const auth = new AuthManager(dir, false); await auth.load(); const login = auth.anonymousSession();
  assert.match(login.cookie, /HttpOnly; SameSite=Strict/);
  const session = auth.browserSession(login.cookie); assert.ok(session); assert.equal(auth.validCsrf(session!, login.csrf), true);
  await rm(dir, { recursive: true, force: true });
});

test('sender rejects non-allowlisted recipient and blocks duplicate requests', async () => {
  const fakeContacts = { resolve: (alias: string) => alias === 'home' ? { chatId: `U${'b'.repeat(32)}`, name: '家' } : undefined } as ContactService;
  const fakeClient = { validate: async () => undefined, sendText: async () => ({ result: 'SUBMITTED' as const, sendId: 'x', status: 200 }) } as unknown as LineClient;
  const sender = new MessageSender(fakeClient, fakeSession(), fakeContacts, new MemoryLogger(), 60_000, 5);
  await assert.rejects(() => sender.send('stranger', 'test'), /TARGET_NOT_ALLOWED/);
  assert.equal((await sender.send('home', 'test')).result, 'SUBMITTED');
  await assert.rejects(() => sender.send('home', 'test'), /DUPLICATE_BLOCKED/);
});
