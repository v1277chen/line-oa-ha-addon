import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, readdir, symlink, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ContactService } from '../src/contacts.js';
import { ImageSender } from '../src/images.js';
import { BusinessQrLogin } from '../src/qr-login.js';
import { SessionManager } from '../src/session.js';
import type { LineClient } from '../src/line-client.js';

const MiB = 1024 * 1024;
const chatId = `U${'b'.repeat(32)}`;
const contactClient = () => ({ getContacts: async () => ({ list: [{ chatId, name: 'Synthetic contact',
  kind: 'user', friend: true, chatAvailable: true }] }) }) as unknown as LineClient;

test('reserved-looking aliases are own entries and revocation survives restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-alias-security-'));
  try {
    const contacts = new ContactService(contactClient(), dir, 60_000); await contacts.load();
    assert.equal(contacts.resolve('constructor'), undefined);
    assert.equal(contacts.resolve('toString'), undefined);
    await contacts.search('', true);
    for (const alias of ['__proto__', 'constructor', 'prototype', 'home']) await contacts.setAlias(alias, chatId);
    for (const alias of ['__proto__', 'constructor', 'prototype', 'home']) {
      assert.equal(contacts.resolve(alias)?.chatId, chatId);
      assert.equal(Object.hasOwn(contacts.getAliases(), alias), true);
    }
    const saved = JSON.parse(await readFile(join(dir, 'aliases.json'), 'utf8'));
    assert.equal(Object.hasOwn(saved, '__proto__'), true);
    const restored = new ContactService(contactClient(), dir, 60_000); await restored.load();
    assert.equal(restored.resolve('__proto__')?.chatId, chatId);
    for (const alias of ['__proto__', 'constructor', 'prototype']) {
      await restored.deleteAlias(alias);
      assert.equal(restored.resolve(alias), undefined);
    }
    assert.deepEqual(restored.listAliases().map(value => value.alias), ['home']);
    const restarted = new ContactService(contactClient(), dir, 60_000); await restarted.load();
    assert.equal(restarted.resolve('__proto__'), undefined);
    assert.equal(restarted.resolve('constructor'), undefined);
    assert.equal(restarted.resolve('home')?.chatId, chatId);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('legacy alias migration preserves literal keys and current values without inherited targets', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-alias-migration-'));
  try {
    await writeFile(join(dir, 'contacts.json'), JSON.stringify(Object.fromEntries([
      ['__proto__', { chatId, name: 'Legacy reserved alias' }], ['home', { chatId, name: 'Legacy name' }]
    ])));
    await writeFile(join(dir, 'aliases.json'), JSON.stringify({ home: { chatId, name: 'Current name' } }));
    const contacts = new ContactService(contactClient(), dir, 60_000); await contacts.load();
    assert.equal(contacts.resolve('__proto__')?.chatId, chatId);
    assert.equal(contacts.resolve('home')?.name, 'Current name');
    await contacts.deleteAlias('__proto__');
    assert.equal(contacts.resolve('__proto__'), undefined);
    assert.equal(contacts.resolve('constructor'), undefined);
    assert.equal(Object.hasOwn(JSON.parse(await readFile(join(dir, 'aliases.json'), 'utf8')), '__proto__'), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('four concurrent 8 MiB images cannot exceed the aggregate 20 MiB limit', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-capacity-security-'));
  const images = new ImageSender(dir, 10 * MiB, 20 * MiB);
  const png = Buffer.alloc(8 * MiB); Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(png);
  try {
    await images.init();
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => images.stage(png, 'image/png')));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 2);
    assert.equal(results.filter(result => result.status === 'rejected' && result.reason.message === 'TEMP_CAPACITY_LIMIT').length, 2);
    assert.equal(await images.totalBytes(), 16 * MiB);
    assert.equal((await readdir(dir)).length, 2);
    const staged = results.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<string>;
    await images.remove(staged.value);
    await images.stage(png, 'image/png');
    assert.equal(await images.totalBytes(), 16 * MiB);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('the exact aggregate capacity is allowed and rejected writes do not poison the queue', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-capacity-boundary-'));
  const images = new ImageSender(dir, 16, 20);
  const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 1, 2]);
  try {
    await images.init();
    const paths = await Promise.all([images.stage(png, 'image/png'), images.stage(png, 'image/png')]);
    assert.equal(await images.totalBytes(), 20);
    await assert.rejects(images.stage(png, 'image/png'), /TEMP_CAPACITY_LIMIT/);
    await images.remove(paths[0]!);
    await images.stage(png, 'image/png'); assert.equal(await images.totalBytes(), 20);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('unknown filesystem capacity refuses a write and the next request can recover', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'line-oa-capacity-io-'));
  const images = new ImageSender(dir, 16, 20);
  const png = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 1, 2]);
  try {
    await images.init();
    try {
      await symlink('loop', join(dir, 'loop'));
    } catch (err: unknown) {
      if (process.platform === 'win32' && (err as NodeJS.ErrnoException).code === 'EPERM') return;
      throw err;
    }
    await assert.rejects(images.stage(png, 'image/png'), { code: 'ELOOP' });
    assert.deepEqual(await readdir(dir), ['loop']);
    await unlink(join(dir, 'loop')); await images.stage(png, 'image/png');
    assert.equal(await images.totalBytes(), 10);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('QR responses are stopped while streaming when the decoded body exceeds 2 MiB', async t => {
  for (const contentLength of [undefined, '1']) {
    await t.test(contentLength ? 'misleading Content-Length' : 'missing Content-Length', async () => {
      let pulledBytes = 0; let cancelled = false; let signal: AbortSignal | null | undefined;
      const chunk = new Uint8Array(64 * 1024);
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (pulledBytes === 4 * MiB) { controller.close(); return; }
          pulledBytes += chunk.byteLength; controller.enqueue(chunk);
        },
        cancel() { cancelled = true; }
      }, { highWaterMark: 0 });
      const original = globalThis.fetch;
      const login = new BusinessQrLogin({} as SessionManager);
      globalThis.fetch = async (_input, init) => {
        signal = init?.signal;
        return new Response(body, { headers: { 'content-type': 'text/html', ...(contentLength ? { 'content-length': contentLength } : {}) } });
      };
      try {
        const state = await login.start('synthetic-owner');
        assert.equal(state.error_name, 'LOGIN_RESPONSE_TOO_LARGE');
        assert.ok(pulledBytes <= 2 * MiB + chunk.byteLength, `Read ${pulledBytes} bytes before refusing`);
        assert.equal(cancelled, true);
        assert.equal(signal?.aborted, true);
        assert.equal(body.locked, false);
        assert.equal(state.hasQr, false);
      } finally { login.close(); globalThis.fetch = original; }
    });
  }
});

test('oversized declared QR responses are cancelled before consuming their body', async () => {
  let reads = 0; let cancelled = false;
  const body = new ReadableStream<Uint8Array>({ pull(controller) { reads++; controller.enqueue(new Uint8Array(16)); },
    cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const original = globalThis.fetch;
  const login = new BusinessQrLogin({} as SessionManager);
  globalThis.fetch = async () => new Response(body, { headers: { 'content-length': String(4 * MiB) } });
  try {
    assert.equal((await login.start('synthetic-owner')).error_name, 'LOGIN_RESPONSE_TOO_LARGE');
    assert.equal(reads, 0); assert.equal(cancelled, true); assert.equal(body.locked, false);
  } finally { login.close(); globalThis.fetch = original; }
});

test('QR streaming limit accepts exactly 2 MiB and rejects the next byte', async () => {
  const original = globalThis.fetch;
  try {
    for (const size of [2 * MiB, 2 * MiB + 1]) {
      const login = new BusinessQrLogin({} as SessionManager);
      globalThis.fetch = async () => new Response(new Uint8Array(size));
      try {
        const state = await login.start('synthetic-owner');
        // The exact-limit response reaches normal URL validation after reading.
        assert.equal(state.error_name, size === 2 * MiB ? 'LOGIN_UPSTREAM_REJECTED' : 'LOGIN_RESPONSE_TOO_LARGE');
      } finally { login.close(); }
    }
  } finally { globalThis.fetch = original; }
});
