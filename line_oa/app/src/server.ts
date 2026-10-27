/**
 * ============================================================================
 * 模組名稱：server.ts
 * 模組用途：LINE OA Add-on 核心 HTTP 伺服器 (Gateway Server)
 * 
 * 路由與服務架構：
 * 1. 對外提供 Home Assistant 整合的 HTTP API v1：
 *    - GET  /api/v1/health             ：健康檢查端點
 *    - GET  /api/v1/status             ：會話狀態端點 (Bearer API Key)
 *    - GET  /api/v1/aliases            ：收件者別名清單端點 (Bearer API Key)
 *    - POST /api/v1/messages/text      ：發送純文字訊息
 *    - POST /api/v1/messages/image     ：發送圖片訊息 (multipart/form-data)
 *    - POST /api/v1/pairing/exchange   ：一次性 Token 配對換鑰
 * 2. 靜態資源與 Ingress Web UI 管理後台：
 *    - GET  /                          ：管理後台 HTML 首頁
 *    - GET  /style.css, /app.js        ：前端樣式與互動腳本
 *    - REST /api/ui/*                  ：後台內部管理 API (登入狀態、日誌、聯絡人、QR 碼登入控制)
 * ============================================================================
 */

import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PairingManager, PairingError } from './pairing.js';
import { DiscoveryPublisher, supervisorRequest, type SupervisorRequest } from './discovery.js';
import { trustedIngress, ingressPath, ingressMutationAllowed } from './ingress.js';
import { DATA_DIR, loadConfig } from './config.js';
import { MemoryLogger } from './logger.js';
import { SessionManager } from './session.js';
import { SessionMonitor } from './session-monitor.js';
import { LineClient, LineError, type RequestFn } from './line-client.js';
import { ContactService } from './contacts.js';
import { MessageSender } from './sender.js';
import { ImageSender } from './images.js';
import { AuthManager } from './auth.js';
import { BusinessQrLogin } from './qr-login.js';
import { healthResponse, parseRequestId, RequestDeduplicator, requestFingerprint, sendResponse, statusResponse, type ApiSendResponse } from './api-v1.js';
import { parseImageMultipart } from './multipart.js';

/**
 * 閘道伺服器啟動選項介面
 */
export interface GatewayOptions {
  dataDir?: string;                          // 自訂資料目錄
  lineRequest?: RequestFn;                   // 自訂 LINE HTTP 請求器 (供測試 Mock)
  qrLogin?: BusinessQrLogin;                 // 自訂 QR 登入實例
  supervisor?: SupervisorRequest;            // 自訂 Supervisor 通訊器
  ingressTrust?: typeof trustedIngress;      // 自訂 Ingress 信任校驗函式
  sessionCheckDelayMs?: () => number;        // 自訂會話檢查延遲函式
}


export async function createGateway(options: GatewayOptions = {}) {
const dataDir = options.dataDir ?? DATA_DIR;
const version = '0.1.9';
const startedAt = Date.now();
const webDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'web');
const { config, warning: configWarning } = await loadConfig(dataDir);
const logger = new MemoryLogger();
if (configWarning) logger.add('CONFIG', 'WARNING', undefined, configWarning);
const sessions = new SessionManager(dataDir);
await sessions.load();
const qrLogin = options.qrLogin ?? new BusinessQrLogin(sessions, (operation, result, target, error, details) => logger.add(operation, result, target, error, details));
const client = new LineClient(sessions, config.requestTimeoutMs, options.lineRequest, (code, details) => logger.add('LINE_UPSTREAM', 'FAILED', undefined, code, details), credentials => qrLogin.recover(credentials));
const contacts = new ContactService(client, dataDir, config.contactsCacheTtlMs);
await contacts.load();
if (contacts.warning) logger.add('CONTACTS_CONFIG', 'WARNING', undefined, contacts.warning);
const sessionMonitor = new SessionMonitor(sessions, client, logger, () => sender.isBusy(), options.sessionCheckDelayMs);
const sender = new MessageSender(client, sessions, contacts, logger, config.duplicateWindowMs, config.rateLimitPerMinute, () => sessionMonitor.messageSent());
const images = new ImageSender(join(dataDir, 'tmp'), config.maxImageBytes, config.maxTempBytes);
await images.init();
const auth = new AuthManager(dataDir, config.secureCookies);
await auth.load();
const pairing = new PairingManager(auth, config.instanceId);
const supervisorToken = process.env.SUPERVISOR_TOKEN;
const discovery = options.supervisor || supervisorToken
  ? new DiscoveryPublisher(pairing, options.supervisor ?? supervisorRequest(supervisorToken!), state => logger.add('DISCOVERY', state))
  : undefined;
type ApiHttpResult = { status: number; body: ApiSendResponse };
const apiRequests = new RequestDeduplicator<ApiHttpResult>(config.duplicateWindowMs, 256);
const staticFiles: Record<string, { file: string; type: string }> = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/icon.png': { file: 'icon.png', type: 'image/png' },
  '/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' }
};

function securityHeaders(res: ServerResponse): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'");
}
function json(res: ServerResponse, status: number, value: unknown): void {
  securityHeaders(res); res.statusCode = status; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(value));
}
function imageResponse(res: ServerResponse, value: Buffer): void {
  securityHeaders(res); res.statusCode = 200; res.setHeader('Content-Type', 'image/png'); res.setHeader('Content-Length', String(value.length));
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin'); res.end(value);
}
function v1Error(res: ServerResponse, status: number, code: string, message: string): void {
  json(res, status, { error: { code, message } });
}
async function bodyJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > 64 * 1024) throw new Error('BODY_TOO_LARGE'); chunks.push(chunk); }
  try { const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value as Record<string, unknown>; }
  catch { throw new Error('INVALID_JSON'); }
}
async function bodyBuffer(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const declared = Number(req.headers['content-length'] ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error('IMAGE_SIZE_LIMIT');
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of req) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += value.length;
    if (size > maxBytes) throw new Error('IMAGE_SIZE_LIMIT');
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}
function errorStatus(code: string): number {
  if (['INVALID_INPUT', 'INVALID_JSON', 'INVALID_ALIAS', 'INVALID_MESSAGE', 'INVALID_TARGET'].includes(code)) return 400;
  if (['IMAGE_TYPE_NOT_ALLOWED', 'IMAGE_SIGNATURE_INVALID'].includes(code)) return 400;
  if (code === 'IMAGE_SIZE_LIMIT') return 413;
  if (code === 'TEMP_CAPACITY_LIMIT') return 507;
  if (['LOGIN_SELECTION_INVALID'].includes(code)) return 400;
  if (['INVALID_CREDENTIALS'].includes(code)) return 401;
  if (['TARGET_NOT_ALLOWED', 'CONTACT_NOT_IN_CACHE'].includes(code)) return 403;
  if (['DUPLICATE_BLOCKED', 'SEND_BUSY'].includes(code)) return 409;
  if (['LOGIN_BUSY'].includes(code)) return 409;
  if (['LOGIN_SELECTION_NOT_AVAILABLE'].includes(code)) return 409;
  if (['RATE_LIMITED', 'LOGIN_RATE_LIMITED'].includes(code)) return 429;
  if (code.startsWith('LOGIN_')) return 502;
  if (code.startsWith('SESSION_')) return 503;
  return 500;
}

function apiResultStatus(result: ApiSendResponse, lineError?: string): number {
  if (result.status === 'confirmed') return 200;
  if (result.status === 'submitted' || result.status === 'unknown') return 202;
  return lineError === 'RATE_LIMIT' ? 429 : 502;
}

function handleV1Error(res: ServerResponse, error: unknown): void {
  const code = error instanceof Error ? error.message : 'INTERNAL_ERROR';
  if (code === 'INVALID_JSON' || code === 'INVALID_REQUEST_ID' || code === 'INVALID_MULTIPART' || code === 'INVALID_TARGET' || code === 'INVALID_MESSAGE') {
    return v1Error(res, 400, 'INVALID_REQUEST', '請求格式或欄位內容無效');
  }
  if (code === 'IMAGE_MESSAGE_NOT_SUPPORTED') return v1Error(res, 400, 'INVALID_REQUEST', '圖片無法原子附加文字，請另行呼叫文字發送 API');
  if (code === 'TARGET_NOT_ALLOWED') return v1Error(res, 404, 'ALIAS_NOT_FOUND', '找不到指定的收件者別名');
  if (code === 'AUTH_REQUIRED') return v1Error(res, 409, 'AUTH_REQUIRED', 'LINE 尚未登入');
  if (code === 'SESSION_EXPIRED' || code === 'SESSION_AUTH') return v1Error(res, 409, 'SESSION_EXPIRED', 'LINE Session 已失效，請重新登入');
  if (code === 'IMAGE_SIZE_LIMIT' || code === 'BODY_TOO_LARGE') return v1Error(res, 413, 'IMAGE_TOO_LARGE', '圖片超過允許大小');
  if (code === 'IMAGE_TYPE_NOT_ALLOWED' || code === 'IMAGE_SIGNATURE_INVALID') return v1Error(res, 400, 'UNSUPPORTED_IMAGE', '只接受內容有效的 JPEG 或 PNG 圖片');
  if (code === 'RATE_LIMITED') return v1Error(res, 429, 'RATE_LIMITED', '發送頻率超過限制');
  if (code === 'REQUEST_ID_CONFLICT') return v1Error(res, 409, 'INVALID_REQUEST', 'request_id 已用於不同內容');
  if (code === 'DUPLICATE_BLOCKED') return v1Error(res, 409, 'DUPLICATE_REQUEST', '短時間內已提交相同內容');
  if (code === 'SEND_BUSY') return v1Error(res, 409, 'SEND_FAILED', '另一筆發送正在處理中');
  if (code.startsWith('SESSION_')) return v1Error(res, 409, 'AUTH_REQUIRED', 'LINE Session 尚未準備完成');
  if (code === 'TEMP_CAPACITY_LIMIT') return v1Error(res, 503, 'INTERNAL_ERROR', '圖片暫存空間目前不可用');
  logger.add('API_V1', 'FAILED', undefined, code);
  return v1Error(res, 500, 'INTERNAL_ERROR', 'Gateway 內部錯誤');
}

function assertV1Session(): void {
  const state = sessions.getStatus().state;
  if (state === 'AUTH_REQUIRED') throw new Error('AUTH_REQUIRED');
  if (state === 'EXPIRED') throw new Error('SESSION_EXPIRED');
}

async function handleApiV1(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
  if (!auth.validApiKey(req.headers.authorization)) return v1Error(res, 401, 'UNAUTHORIZED', 'API Key 無效或未提供');
  pairing.authenticated();
  if (req.method === 'GET' && path === '/api/v1/status') {
    const session = sessions.getStatus();
    return json(res, 200, statusResponse({ instanceId: config.instanceId, version, state: session.state, accountName: session.accountName, lastError: logger.lastError(), loginRequiredReason: session.loginRequiredReason }));
  }
  if (req.method === 'GET' && path === '/api/v1/aliases') return json(res, 200, { aliases: contacts.listAliases() });
  if (req.method === 'POST' && path === '/api/v1/messages/text') {
    if (!String(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) throw new Error('INVALID_JSON');
    const body = await bodyJson(req);
    if (typeof body.who !== 'string' || typeof body.message !== 'string' ||
      (body.request_id !== undefined && typeof body.request_id !== 'string')) throw new Error('INVALID_JSON');
    const who = body.who;
    if (!/^[a-z0-9_-]{1,32}$/.test(who)) throw new Error('INVALID_TARGET');
    if (!body.message.trim() || body.message.length > 5000 || /\u0000/.test(body.message)) throw new Error('INVALID_MESSAGE');
    if (!contacts.resolve(who)) throw new Error('TARGET_NOT_ALLOWED');
    assertV1Session();
    const requestId = parseRequestId(body.request_id);
    const fingerprint = requestFingerprint(['text', who, body.message]);
    const result = await apiRequests.run(requestId, fingerprint, async () => {
      const sent = await sender.send(who, body.message as string);
      const response = sendResponse(requestId, sent);
      return { status: apiResultStatus(response, sent.error), body: response };
    });
    if (result.duplicate) logger.add('API_REQUEST_DUPLICATE', 'CACHED', who);
    return json(res, result.value.status, result.value.body);
  }
  if (req.method === 'POST' && path === '/api/v1/messages/image') {
    const contentType = String(req.headers['content-type'] ?? '');
    const raw = await bodyBuffer(req, config.maxImageBytes + 64 * 1024);
    const form = parseImageMultipart(raw, contentType);
    if (!/^[a-z0-9_-]{1,32}$/.test(form.who)) throw new Error('INVALID_TARGET');
    if (!contacts.resolve(form.who)) throw new Error('TARGET_NOT_ALLOWED');
    if (form.message?.trim()) throw new Error('IMAGE_MESSAGE_NOT_SUPPORTED');
    const requestId = parseRequestId(form.requestId);
    const mime = form.imageType;
    if (mime !== 'image/jpeg' && mime !== 'image/png') throw new Error('IMAGE_TYPE_NOT_ALLOWED');
    images.validate(form.image, mime);
    assertV1Session();
    const fingerprint = requestFingerprint(['image', form.who, mime, form.image]);
    const result = await apiRequests.run(requestId, fingerprint, async () => {
      const staged = await images.stage(form.image, mime);
      try {
        const sent = await sender.sendImage(form.who, form.image, mime);
        const response = sendResponse(requestId, sent);
        return { status: apiResultStatus(response, sent.error), body: response };
      } finally { await images.remove(staged); }
    });
    if (result.duplicate) logger.add('API_REQUEST_DUPLICATE', 'CACHED', form.who);
    return json(res, result.value.status, result.value.body);
  }
  return v1Error(res, 404, 'INVALID_REQUEST', '找不到指定的 API 路徑');
}

const handleUi = async (req: IncomingMessage, res: ServerResponse) => {
  try {
    if (!(options.ingressTrust ?? trustedIngress)(req) || !ingressPath(req)) return json(res, 403, { error: 'INGRESS_REQUIRED' });
    if (!ingressMutationAllowed(req)) return json(res, 403, { error: 'ORIGIN_REJECTED' });
    const requestUrl = new URL(req.url ?? '/', 'http://localhost');
    const path = requestUrl.pathname;
    if (path.startsWith('/api/v1/')) return json(res, 404, { error: 'NOT_FOUND' });
    const staticItem = req.method === 'GET' ? staticFiles[path] : undefined;
    if (staticItem) {
      const value = await readFile(join(webDir, staticItem.file));
      securityHeaders(res); res.statusCode = 200; res.setHeader('Content-Type', staticItem.type); res.end(value); return;
    }
    if (req.method === 'GET' && path === '/api/health') return json(res, 200, { ok: true, version });
    if (req.method === 'GET' && path === '/api/auth/session') {
      let browser = auth.browserSession(req.headers.cookie);
      if (!config.uiAuthEnabled && !browser) {
        const created = auth.anonymousSession();
        res.setHeader('Set-Cookie', scopedCookie(created.cookie, req));
        browser = { token: '', csrf: created.csrf };
      }
      return json(res, 200, { authenticated: !!browser, setupRequired: config.uiAuthEnabled && auth.setupRequired(), authRequired: config.uiAuthEnabled, ...(browser ? { csrfToken: browser.csrf } : {}) });
    }
    const browser = auth.browserSession(req.headers.cookie);
    if (!browser) return json(res, 401, { error: 'AUTH_REQUIRED' });
    if (req.method !== 'GET' && !auth.validCsrf(browser, String(req.headers['x-csrf-token'] ?? ''))) {
      const code = req.headers['x-csrf-token'] ? 'WEB_UI_CSRF_TOKEN_MISMATCH' : 'WEB_UI_CSRF_TOKEN_MISSING';
      const message = '網頁操作驗證失敗；請重新整理 Add-on 頁面後再操作。本次操作尚未執行。';
      logger.add('WEB_UI_CSRF', 'FAILED', undefined, code, { method: req.method, endpoint: path, httpStatus: 403, message });
      return json(res, 403, { error: code, error_name: code, message, http_status: 403 });
    }
    if (req.method === 'POST' && path === '/api/auth/logout' && browser) {
      qrLogin.cancel(browser.token);
      auth.logout(browser.token); res.setHeader('Set-Cookie', scopedCookie(auth.clearCookie(), req)); return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && path === '/api/session/logout') {
      if (sender.isBusy()) throw new Error('SEND_BUSY');
      qrLogin.close();
      contacts.clearCache();
      await sessions.logout();
      logger.add('LINE_LOGOUT', 'SUCCESS');
      return json(res, 200, sessions.getStatus());
    }
    if (req.method === 'GET' && path === '/api/pairing/status') return json(res, 200, {
      ...pairing.status(), discovery_status: discovery?.status ?? 'unavailable'
    });
    if (req.method === 'POST' && path === '/api/pairing/reset') {
      await pairing.revoke();
      await discovery?.publish();
      logger.add('PAIRING_RESET', 'SUCCESS');
      return json(res, 200, pairing.status());
    }
    if (req.method === 'POST' && path === '/api/session/qr/start' && browser) {
      const state = await qrLogin.start(browser.token);
      logger.add('QR_LOGIN_START', state.status === 'error' ? 'FAILED' : 'SUCCESS', undefined, state.status === 'error' ? state.message : undefined);
      return json(res, 200, state);
    }
    if (req.method === 'GET' && path === '/api/session/qr/status' && browser) return json(res, 200, qrLogin.state(browser.token));
    if (req.method === 'GET' && path === '/api/session/qr/image' && browser) {
      const value = qrLogin.image(browser.token);
      if (!value) return json(res, 404, { error: 'LOGIN_QR_NOT_AVAILABLE' });
      return imageResponse(res, value);
    }
    if (req.method === 'POST' && path === '/api/session/qr/select' && browser) {
      const body = await bodyJson(req);
      const choiceId = typeof body.choiceId === 'string' && /^[A-Za-z0-9_-]{16}$/.test(body.choiceId) ? body.choiceId : '';
      if (!choiceId) return json(res, 400, { error: 'LOGIN_SELECTION_INVALID' });
      const state = await qrLogin.select(browser.token, choiceId);
      logger.add('QR_LOGIN_SELECT', state.status === 'error' ? 'FAILED' : 'SUCCESS', undefined, state.status === 'error' ? state.message : undefined);
      return json(res, 200, state);
    }
    if (req.method === 'POST' && path === '/api/session/qr/cancel' && browser) {
      qrLogin.cancel(browser.token); logger.add('QR_LOGIN_CANCEL', 'SUCCESS'); return json(res, 200, { status: 'idle', hasQr: false });
    }
    if (req.method === 'GET' && path === '/api/status') {
      const mem = process.memoryUsage();
      return json(res, 200, { version, session: sessions.getStatus(), cacheCount: contacts.count(), submittedCount: sender.submittedCount,
        lastSubmittedAt: sender.lastSubmittedAt, latestError: logger.lastError(), uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
        timezone: logger.timezone, resources: { rssBytes: mem.rss, heapUsedBytes: mem.heapUsed, cpu: process.cpuUsage() },
        settings: { host: config.listenHost, port: config.port, cacheTtlMs: config.contactsCacheTtlMs, uiAuthEnabled: config.uiAuthEnabled,
          apiEnabled: auth.apiKeyConfigured(), imageSendingEnabled: true } });
    }
    if (req.method === 'POST' && path === '/api/session/validate') {
      try { await client.validate(); sessions.mark('CONNECTED', 'Session 驗證成功'); logger.add('SESSION_VALIDATE', 'SUCCESS'); return json(res, 200, sessions.getStatus()); }
      catch (error) { const kind = error instanceof LineError ? error.kind : 'NETWORK'; sessions.mark(kind === 'AUTH' ? 'EXPIRED' : kind === 'NETWORK' ? 'DISCONNECTED' : 'ERROR', `驗證失敗：${error instanceof LineError ? error.code : kind}`); const code = error instanceof LineError ? error.code : 'SESSION_VALIDATION_FAILED'; logger.add('SESSION_VALIDATE', 'FAILED', undefined, code); return json(res, 503, { ...sessions.getStatus(), error: code, error_name: code, ...(error instanceof LineError ? { upstream_status: error.status, details: error.details } : {}) }); }
    }
    if (req.method === 'GET' && path === '/api/contacts') {
      const query = requestUrl.searchParams.get('query') ?? '';
      const next = requestUrl.searchParams.get('next') ?? undefined;
      const result = await contacts.search(query, false, next); return json(res, 200, { ...result, aliases: contacts.getAliases() });
    }
    if (req.method === 'POST' && path === '/api/contacts/refresh') {
      const body = await bodyJson(req); const query = typeof body.query === 'string' ? body.query : '';
      const result = await contacts.search(query, true); logger.add('CONTACTS_REFRESH', 'SUCCESS'); return json(res, 200, { ...result, aliases: contacts.getAliases() });
    }
    if (req.method === 'GET' && path === '/api/aliases') return json(res, 200, { aliases: contacts.getAliases() });
    if (req.method === 'PUT' && path === '/api/aliases') {
      const body = await bodyJson(req);
      const alias = String(body.alias ?? '').trim().toLowerCase();
      await contacts.setAlias(alias, String(body.chatId ?? ''));
      logger.add('ALIAS_SET', 'SUCCESS', alias); return json(res, 200, { aliases: contacts.getAliases() });
    }
    if (req.method === 'DELETE' && path.startsWith('/api/aliases/')) {
      const alias = decodeURIComponent(path.slice('/api/aliases/'.length)); await contacts.deleteAlias(alias); logger.add('ALIAS_DELETE', 'SUCCESS', alias); return json(res, 200, { aliases: contacts.getAliases() });
    }
    if (req.method === 'POST' && path === '/api/messages/send') {
      const body = await bodyJson(req); const target = typeof body.target === 'string' ? body.target : ''; const message = typeof body.message === 'string' ? body.message : '';
      const result = await sender.send(target, message); return json(res, result.result === 'SUBMITTED' ? 202 : result.result === 'UNKNOWN' ? 202 : 502, result);
    }
    if (req.method === 'POST' && path === '/api/messages/image') {
      const target = requestUrl.searchParams.get('target') ?? '';
      const type = String(req.headers['content-type'] ?? '').split(';', 1)[0]!.trim().toLowerCase();
      if (type !== 'image/jpeg' && type !== 'image/png') throw new Error('IMAGE_TYPE_NOT_ALLOWED');
      const buffer = await bodyBuffer(req, config.maxImageBytes);
      const staged = await images.stage(buffer, type);
      try {
        const result = await sender.sendImage(target, buffer, type);
        return json(res, result.result === 'SUBMITTED' || result.result === 'UNKNOWN' ? 202 : 502, result);
      } finally { await images.remove(staged); }
    }
    if (req.method === 'GET' && path === '/api/logs') return json(res, 200, { logs: logger.list() });
    return json(res, 404, { error: 'NOT_FOUND' });
  } catch (error) {
    const code = error instanceof LineError ? error.code : error instanceof Error && /^[A-Z][A-Z0-9_]{1,80}$/.test(error.message) ? error.message : 'INTERNAL_ERROR';
    logger.add('HTTP_REQUEST', 'FAILED', undefined, code);
    return json(res, error instanceof PairingError ? error.status : error instanceof LineError ? 502 : errorStatus(code), { error: code, error_name: code, ...(error instanceof LineError ? { upstream_status: error.status, details: error.details } : {}) });
  }
};

function scopedCookie(cookie: string, req: IncomingMessage): string {
  const secure = req.headers['x-forwarded-proto'] === 'https' || req.headers.origin?.startsWith('https://');
  return cookie.replace('Path=/;', `Path=${ingressPath(req)}/;`) + (secure ? '; Secure' : '');
}
const uiServer = http.createServer(handleUi);
const apiServer = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (req.method === 'GET' && path === '/api/v1/health') return json(res, 200, healthResponse(version));
    if (req.method === 'POST' && path === '/api/v1/pairing/exchange') {
      if (req.headers.origin || req.headers.cookie || req.headers['sec-fetch-site']) return v1Error(res, 403, 'PAIRING_REJECTED', 'Pairing requires an internal API client');
      if (!String(req.headers['content-type']).startsWith('application/json')) return v1Error(res, 400, 'INVALID_PAIRING_REQUEST', 'JSON required');
      const result = await pairing.exchange(await bodyJson(req));
      // Removing the secret from discovery may retry in the background. The token
      // is already invalid in RAM once the credential is durably stored.
      void discovery?.publish();
      logger.add('PAIRING', 'SUCCESS');
      return json(res, 201, result);
    }
    if (!path.startsWith('/api/v1/')) return json(res, 404, { error: 'NOT_FOUND' });
    await handleApiV1(req, res, path);
  } catch (error) {
    if (error instanceof PairingError) return v1Error(res, error.status, error.message, 'Pairing was rejected; refresh discovery or reauthorize in Ingress');
    handleV1Error(res, error);
  }
});
for (const server of [uiServer, apiServer]) { server.requestTimeout = 20_000; server.headersTimeout = 10_000; }
let stopping: Promise<void> | undefined;
return {
  pairing, discovery, sessions, contacts, auth, uiServer, apiServer,
  async start(apiPort = 8787, uiPort = 8099, host = '0.0.0.0') {
    const listen = (server: http.Server, port: number) => new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => { server.off('error', reject); resolve(); });
    });
    try { await listen(apiServer, apiPort); await listen(uiServer, uiPort); }
    catch (error) { await this.stop(); throw error; }
    logger.add('SERVER_START', 'SUCCESS');
    discovery?.start();
    sessionMonitor.start();
    // Resolve restored credentials once at startup; HA polls only the cached result.
    // Keep listeners responsive while validation (and any recovery) is in progress.
    if (sessions.getStatus().state === 'VALIDATING') void sessionMonitor.check();
  },
  stop(): Promise<void> {
    if (stopping) return stopping;
    discovery?.stop();
    sessionMonitor.stop();
    qrLogin.close();
    stopping = (async () => {
      const close = (server: http.Server) => new Promise<void>(resolve => {
        server.close(() => resolve()); server.closeIdleConnections();
      });
      const deadline = setTimeout(() => { apiServer.closeAllConnections(); uiServer.closeAllConnections(); }, 20_000);
      deadline.unref();
      try { await Promise.all([close(apiServer), close(uiServer)]); await images.cleanup(); }
      finally { clearTimeout(deadline); }
    })();
    return stopping;
  }
};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.umask(0o077);
  try {
    const gateway = await createGateway();
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => {
      void gateway.stop().then(() => process.exit(0), () => process.exit(1));
    });
    await gateway.start();
  } catch {
    // Never include raw errors, request bodies, paths or credentials in startup logs.
    process.stderr.write('LINE OA startup failed; check private data and listener availability.\n');
    process.exitCode = 1;
  }
}
