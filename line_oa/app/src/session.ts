/**
 * ============================================================================
 * 模組名稱：session.ts
 * 模組用途：管理 LINE 官方帳號 Web Session 登入憑證的載入、狀態維護、Cookie 動態更新與持久化
 * 
 * 核心功能：
 * 1. 憑證結構嚴格校驗：確保 botId 符合 LINE 格式 (U 開頭 + 32 字元十六進位)，
 *    且包含關鍵的 `__Host-chat-ses` 安全 Cookie。
 * 2. 會話生命週期狀態機：管理 AUTH_REQUIRED -> VALIDATING -> CONNECTED -> EXPIRED 等狀態轉變。
 * 3. 序列化 Cookie 更新佇列：透過 `cookieUpdates` Promise 鏈，確保並行的 HTTP 回應
 *    在回寫 Set-Cookie 時順序正確且不發生覆蓋競爭。
 * 4. 登出墓碑標記 (Tombstone)：登出時立即寫入 null，防止被非同步競態覆寫還原。
 * ============================================================================
 */

import { join } from 'node:path';
import type { SessionCredentials, SessionState } from './types.js';
import { atomicWriteJson, readJsonSafe } from './storage.js';
import { MemoryCookieJar, validLoginCookies } from './cookie-jar.js';

/**
 * 嚴格校驗載入之 SessionCredentials 憑證結構是否符合安全性與正確性規範
 * 
 * @param value - 待校驗之物件
 * @returns 是否為合法的 SessionCredentials
 */
export function validSession(value: unknown): value is SessionCredentials {
  if (!value || typeof value !== 'object') return false;
  const v = value as Partial<SessionCredentials>;
  const allowed = new Set(['ses', '__Host-chat-ses', 'XSRF-TOKEN']);
  // 必須包含 __Host-chat-ses 且不得包含非法分號或換行
  const cookiesValid = Array.isArray(v.cookies) && v.cookies.some(c => c.name === '__Host-chat-ses') &&
    v.cookies.every(c => allowed.has(c.name) && typeof c.value === 'string' && !!c.value && !/[\r\n;]/.test(c.value)) &&
    new Set(v.cookies.map(c => c.name)).size === v.cookies.length;

  return v.version === 1 && /^U[0-9a-f]{32}$/.test(v.botId ?? '') && cookiesValid &&
    (v.loginCookies === undefined || validLoginCookies(v.loginCookies)) &&
    typeof v.importedAt === 'string' && Number.isFinite(Date.parse(v.importedAt)) &&
    (v.csrfToken === undefined || (typeof v.csrfToken === 'string' && !!v.csrfToken && !/[\r\n;]/.test(v.csrfToken))) &&
    (v.clientVersion === undefined || (typeof v.clientVersion === 'string' && v.clientVersion.length <= 100 && !/[\r\n]/.test(v.clientVersion)));
}

/**
 * LINE 會話憑證管理核心類別
 */
export class SessionManager {
  private credentials?: SessionCredentials;
  private generation = 0;
  private cookieUpdates: Promise<void> = Promise.resolve();
  private state: SessionState = 'AUTH_REQUIRED';
  private authRequiredReason: 'not_logged_in' | 'logged_out' = 'not_logged_in';
  private reason = '尚未登入 LINE，請先登入';
  private lastValidatedAt?: string;
  private readonly path: string;

  /**
   * @param dataDir - 資料儲存根目錄路徑
   */
  constructor(dataDir: string) {
    this.path = join(dataDir, 'secrets', 'line-session.json');
  }

  /**
   * 從 secrets/line-session.json 載入既有之登入憑證
   */
  async load(): Promise<void> {
    const loaded = await readJsonSafe<SessionCredentials | null>(
      this.path,
      null,
      (v): v is SessionCredentials | null => v === null || validSession(v)
    );
    if (loaded.value) {
      this.credentials = loaded.value;
      this.state = 'VALIDATING';
      this.reason = 'Session 已載入，正在確認 LINE 連線';
    } else if (loaded.warning) {
      this.state = 'ERROR';
      this.reason = 'Session 檔案格式無效，請重新登入';
    }
  }

  /** 取得當前持有的登入憑證物件 (若已登出則為 undefined) */
  getCredentials(): SessionCredentials | undefined { return this.credentials; }

  /**
   * 取得對外呈報之狀態摘要
   */
  getStatus(): {
    state: SessionState;
    reason: string;
    loginRequiredReason?: 'expired' | 'not_logged_in' | 'logged_out';
    lastValidatedAt?: string;
    lastLoginAt?: string;
    loginAgeDays?: number;
    accountName?: string;
    botIdConfigured: boolean;
  } {
    const lastLoginAt = this.credentials?.importedAt;
    const loginAgeDays = lastLoginAt ? Math.max(0, Math.floor((Date.now() - Date.parse(lastLoginAt)) / 86_400_000)) : undefined;
    const loginRequiredReason = this.state === 'EXPIRED' ? 'expired' : this.state === 'AUTH_REQUIRED' ? this.authRequiredReason : undefined;
    return {
      state: this.state,
      reason: this.reason,
      loginRequiredReason,
      lastValidatedAt: this.lastValidatedAt,
      lastLoginAt,
      loginAgeDays,
      accountName: this.credentials?.accountName,
      botIdConfigured: !!this.credentials
    };
  }

  /**
   * 標記當前會話狀態與描述文字
   * 
   * @param state - 目標 SessionState
   * @param reason - 變更原因摘要
   */
  mark(state: SessionState, reason: string): void {
    if (!this.credentials) return;
    this.state = state;
    this.reason = reason;
    if (state === 'CONNECTED') this.lastValidatedAt = new Date().toISOString();
  }

  /**
   * 執行登出作業，銷毀憑證並寫入 null 墓碑記錄
   */
  async logout(): Promise<void> {
    ++this.generation;
    this.credentials = undefined;
    this.state = 'AUTH_REQUIRED';
    this.authRequiredReason = 'logged_out';
    this.reason = '已登出 LINE，請重新登入';
    this.lastValidatedAt = undefined;
    // 將檔案原子化寫入 null，防止被非同步舊寫入還原
    await atomicWriteJson(this.path, null, 0o600);
  }

  /**
   * 更新 CSRF Token (XSRF-TOKEN Cookie) 並同步寫入磁碟
   */
  async updateCsrf(token: string, expected?: SessionCredentials): Promise<void> {
    if (!this.credentials || (expected && expected !== this.credentials)) throw new Error('SESSION_CHANGED');
    this.credentials.csrfToken = token;
    const cookie = this.credentials.cookies.find(c => c.name === 'XSRF-TOKEN');
    if (cookie) cookie.value = token;
    else this.credentials.cookies.push({ name: 'XSRF-TOKEN', value: token });
    await atomicWriteJson(this.path, this.credentials, 0o600);
  }

  /**
   * 續期或重整登入憑證 (以序列鎖執行 commitRenewal)
   */
  async renewCredentials(next: SessionCredentials, expected: SessionCredentials): Promise<void> {
    const generation = this.generation;
    const update = this.cookieUpdates.then(() => this.commitRenewal(next, expected, generation));
    this.cookieUpdates = update.catch(() => undefined);
    return update;
  }

  /** 提交憑證續期變更至磁碟 */
  private async commitRenewal(next: SessionCredentials, expected: SessionCredentials, generation: number): Promise<void> {
    if (this.credentials !== expected || next.botId !== expected.botId) throw new Error('SESSION_CHANGED');
    if (generation !== this.generation) throw new Error('SESSION_CHANGED');
    if (!validSession(next)) throw new Error('INVALID_SESSION');
    await atomicWriteJson(this.path, next, 0o600);
    if (generation !== this.generation || this.credentials !== expected) throw new Error('SESSION_CHANGED');
    Object.assign(expected, structuredClone(next));
    ++this.generation;
  }

  /**
   * 處理來自 LINE 伺服器 HTTP 回應中的 Set-Cookie 標頭，動態更新憑證
   * 
   * @param headers - HTTP 回應標頭中的 Set-Cookie 陣列
   * @param expected - 預期正在進行更新的憑證參照物件
   * @param sentCookie - 發送請求時所帶之 Cookie 字串，用於檢驗過期請求
   */
  async updateCookies(headers: string[], expected: SessionCredentials, sentCookie?: string): Promise<void> {
    const update = this.cookieUpdates.then(async () => {
      // 若無標頭或憑證已遭切換，或請求發送時的 Cookie 與當前不同，則忽略
      if (!headers.length || this.credentials !== expected || (sentCookie !== undefined &&
        sentCookie !== expected.cookies.map(c => `${c.name}=${c.value}`).join('; '))) return;

      const jar = this.cookieJar(expected);
      const url = new URL('https://chat.line.biz/');
      for (const header of headers) jar.set(url, header);

      const cookies = (['ses', '__Host-chat-ses', 'XSRF-TOKEN'] as const).flatMap(name => {
        const value = jar.value(name, url);
        return value ? [{ name, value }] : [];
      });

      // 清除回應絕對不可破壞最後可恢復的驗證狀態 (必須具備 __Host-chat-ses)
      if (!cookies.some(c => c.name === '__Host-chat-ses')) return;

      await this.commitRenewal({ ...expected, cookies, loginCookies: jar.snapshot() }, expected, this.generation);
    });

    this.cookieUpdates = update.catch(() => undefined);
    return update;
  }

  /**
   * 根據憑證資訊建立或還原 MemoryCookieJar 實例
   * 
   * @param credentials - 登入憑證
   * @returns 包含還原 Cookie 之 MemoryCookieJar 容器
   */
  cookieJar(credentials: SessionCredentials): MemoryCookieJar {
    const jar = new MemoryCookieJar();
    jar.restore(credentials.loginCookies ?? []);
    const url = new URL('https://chat.line.biz/');
    for (const c of credentials.cookies) {
      if (jar.value(c.name, url) !== c.value) {
        jar.set(url, `${c.name}=${c.value}; Path=/; Secure${c.name === 'ses' ? '; Domain=line.biz' : ''}`);
      }
    }
    return jar;
  }

  /**
   * 匯入外部產生的新登入憑證 (例如 QR Code 登入完成或外部遷移)
   * 
   * @param credentials - 待匯入之有效憑證
   * @throws INVALID_SESSION 當憑證結構無效時
   * @throws SESSION_CHANGED 當寫入過程發生世代並行衝突時
   */
  async importCredentials(credentials: SessionCredentials): Promise<void> {
    if (!validSession(credentials)) throw new Error('INVALID_SESSION');
    const generation = ++this.generation;
    // 原子性寫入檔案系統，限制存取權限為 0o600
    await atomicWriteJson(this.path, credentials, 0o600);
    if (generation !== this.generation) throw new Error('SESSION_CHANGED');
    this.credentials = structuredClone(credentials);
    this.state = 'VALIDATING';
    this.reason = 'QR 登入完成，正在驗證 Session';
    this.lastValidatedAt = undefined;
  }
}

