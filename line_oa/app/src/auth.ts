/**
 * ============================================================================
 * 模組名稱：auth.ts
 * 模組用途：管理 Add-on Web UI 管理員登入密碼驗證、CSRF 防護與外部 API Key 生成與驗證
 * 
 * 資安設計特色：
 * 1. 密碼雜湊採用 Node.js 原生 scrypt 演算法並搭配隨機 Salt。
 * 2. API Key 採用 SHA-256 單向雜湊持久化儲存，記憶體中絕不以明文留存。
 * 3. 憑證與金鑰比對全程採用固定時間演算法 (`timingSafeEqual`)，杜絕時序旁路攻擊 (Timing Attack)。
 * 4. 登入失敗率限制：單一 IP 於 15 分鐘內失敗超過 5 次即啟動鎖定。
 * ============================================================================
 */

import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { unlink, open } from 'node:fs/promises';
import { atomicWriteJson, ensurePrivateDir, readJsonSafe } from './storage.js';

const scrypt = promisify(scryptCallback);

/** 管理員密碼儲存結構 */
type PasswordRecord = { version: 1; salt: string; hash: string };
/** API Key 儲存結構 (儲存 SHA-256 雜湊，不存明文) */
type ApiRecord = { version: 1; hash: string } | { version: 2; hash: string; createdAt: string };

/** 驗證密碼記錄結構完整性 */
function validPassword(value: unknown): value is PasswordRecord {
  const v = value as Partial<PasswordRecord> | null;
  return !!v && v.version === 1 && /^[a-f0-9]{32}$/.test(v.salt ?? '') && /^[a-f0-9]{64}$/.test(v.hash ?? '');
}

/** 驗證 API Key 記錄結構完整性 */
function validApi(value: unknown): value is ApiRecord {
  const v = value as Partial<ApiRecord> | null;
  return !!v && (v.version === 1 || (v.version === 2 && typeof v.createdAt === 'string' && Number.isFinite(Date.parse(v.createdAt)))) &&
    /^[a-f0-9]{64}$/.test(v.hash ?? '');
}

/**
 * 認證與授權管理核心類別
 */
export class AuthManager {
  private password?: PasswordRecord;
  private api?: ApiRecord;
  private sessions = new Map<string, { csrf: string; expires: number }>();
  private failures = new Map<string, number[]>();

  /**
   * @param dataDir - 資料儲存根目錄
   * @param secureCookies - 是否強制 Cookie 啟用 Secure 標籤
   * @param cookiePath - Cookie 的有效路徑，預設為 '/'
   */
  constructor(private readonly dataDir: string, private readonly secureCookies: boolean, private readonly cookiePath = '/') {}

  /**
   * 從磁碟安全載入管理員密碼與 API Key 憑證
   */
  async load(): Promise<void> {
    this.password = (await readJsonSafe<PasswordRecord | null>(
      join(this.dataDir, 'secrets', 'admin-password.json'),
      null,
      (v): v is PasswordRecord | null => v === null || validPassword(v)
    )).value ?? undefined;

    const loaded = await readJsonSafe<ApiRecord | null>(
      join(this.dataDir, 'secrets', 'api-key.json'),
      null,
      (v): v is ApiRecord | null => v === null || validApi(v)
    );
    if (loaded.warning) throw new Error('API_CREDENTIAL_CORRUPT_RESTORE_BACKUP');
    this.api = loaded.value ?? undefined;
  }

  /** 是否需要進行初次管理員密碼設定 */
  setupRequired(): boolean { return !this.password; }

  /** 是否已配置 API Key (已與 HA 或外部配對) */
  apiKeyConfigured(): boolean { return !!this.api; }

  /** 取得當前 API Key 的配置狀態與建立時間 */
  apiKeyInfo(): { configured: boolean; createdAt?: string } {
    return { configured: !!this.api, ...(this.api?.version === 2 ? { createdAt: this.api.createdAt } : {}) };
  }

  /**
   * 生成一組全新的專屬 API Key，並以 SHA-256 雜湊儲存至 secrets/api-key.json (0o600 權限)
   * 
   * @returns 包含明文 apiKey (僅此處回傳一次) 與建立時間
   */
  async generateApiKey(): Promise<{ apiKey: string; createdAt: string }> {
    const apiKey = `loagw_${randomBytes(32).toString('base64url')}`;
    const createdAt = new Date().toISOString();
    const record: ApiRecord = { version: 2, hash: createHash('sha256').update(apiKey).digest('hex'), createdAt };
    await atomicWriteJson(join(this.dataDir, 'secrets', 'api-key.json'), record, 0o600);
    this.api = record;
    return { apiKey, createdAt };
  }

  /**
   * 撤銷當前 API Key (刪除金鑰檔並同步磁碟)
   */
  async revokeApiKey(): Promise<void> {
    await unlink(join(this.dataDir, 'secrets', 'api-key.json')).catch(error => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    });
    await ensurePrivateDir(join(this.dataDir, 'secrets'));
    if (process.platform !== 'win32') {
      const directory = await open(join(this.dataDir, 'secrets'), 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    }
    this.api = undefined;
  }

  /**
   * 產生瀏覽器匿名會話 (例如 Ingress 免登入模式下使用)
   * 
   * @returns 包含 Set-Cookie 標頭值與對應的 csrf 權杖
   */
  anonymousSession(): { cookie: string; csrf: string } {
    this.prune();
    const token = randomBytes(32).toString('base64url');
    const csrf = randomBytes(24).toString('base64url');
    this.sessions.set(token, { csrf, expires: Date.now() + 8 * 60 * 60_000 });
    const secure = this.secureCookies ? '; Secure' : '';
    return { cookie: `loagw_session=${token}; Path=${this.cookiePath}; HttpOnly; SameSite=Strict; Max-Age=28800${secure}`, csrf };
  }

  /** 清除已過期的記憶體會話 */
  private prune(): void {
    const now = Date.now();
    for (const [token, session] of this.sessions) if (session.expires < now) this.sessions.delete(token);
  }

  /**
   * 處理管理員密碼登入 (含 IP 限流防暴力破解)
   * 
   * @param password - 使用者輸入的明文密碼
   * @param address - 發起請求的客戶端 IP
   * @returns 建立成功之會話 Cookie 與 CSRF Token
   * @throws Error('LOGIN_RATE_LIMITED') 若短時間內失敗次數過多
   * @throws Error('INVALID_CREDENTIALS') 密碼錯誤
   */
  async login(password: string, address: string): Promise<{ cookie: string; csrf: string }> {
    if (!this.password) throw new Error('SETUP_REQUIRED');
    const now = Date.now();
    const failures = (this.failures.get(address) ?? []).filter(at => now - at < 15 * 60_000);
    if (failures.length >= 5) throw new Error('LOGIN_RATE_LIMITED');
    const actual = await scrypt(password, Buffer.from(this.password.salt, 'hex'), 32) as Buffer;
    const expected = Buffer.from(this.password.hash, 'hex');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      failures.push(now);
      this.failures.set(address, failures);
      throw new Error('INVALID_CREDENTIALS');
    }
    this.failures.delete(address);
    this.prune();
    return this.anonymousSession();
  }

  /**
   * 從 Cookie 標頭解析並驗證當前瀏覽器會話
   */
  browserSession(cookieHeader?: string): { token: string; csrf: string } | undefined {
    this.prune();
    const prefix = 'loagw_session=';
    const token = cookieHeader?.split(';').map(v => v.trim()).find(v => v.startsWith(prefix))?.slice(prefix.length);
    if (!token) return undefined;
    const session = this.sessions.get(token);
    return session ? { token, csrf: session.csrf } : undefined;
  }

  /** 註銷瀏覽器會話 */
  logout(token: string): void { this.sessions.delete(token); }

  /** 產生清除 Session Cookie 的 Set-Cookie 標頭 */
  clearCookie(): string {
    return `loagw_session=; Path=${this.cookiePath}; HttpOnly; SameSite=Strict; Max-Age=0${this.secureCookies ? '; Secure' : ''}`;
  }

  /** 驗證前端傳入之 CSRF Token 是否與 Session 匹配 (時序安全比對) */
  validCsrf(session: { csrf: string }, header?: string): boolean {
    return !!header && Buffer.byteLength(header) === Buffer.byteLength(session.csrf) && timingSafeEqual(Buffer.from(header), Buffer.from(session.csrf));
  }

  /**
   * 驗證外部傳入之 Bearer API Key 是否合法
   * 
   * @param authorization - HTTP Authorization 標頭字串
   * @returns 若金鑰正確則回傳 True，否則回傳 False
   */
  validApiKey(authorization?: string): boolean {
    if (!this.api || !authorization?.startsWith('Bearer ')) return false;
    const token = authorization.slice(7);
    if (token.length < 32 || token.length > 256) return false;
    // 計算傳入 token 的 SHA-256 雜湊，並與已儲存之雜湊進行固定時間比對
    const actual = createHash('sha256').update(token).digest();
    const expected = Buffer.from(this.api.hash, 'hex');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }
}
