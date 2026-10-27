/**
 * ============================================================================
 * 模組名稱：cookie-jar.ts
 * 模組用途：實作安全、輕量且嚴格遵循 RFC 6265 規範的記憶體 Cookie Jar
 * 
 * 資安設計特色：
 * 1. 域名白名單限制：僅允許 LINE 相關網域 (chat.line.biz, account.line.biz 等)，
 *    拒絕任意網域注入，且強制驗證是否為 IP 位址。
 * 2. `__Host-` 安全字首強校驗：凡帶有 `__Host-` 字首的 Cookie，必須強制為 Secure、
 *    Host-Only 且 Path 必須為根目錄 '/'。
 * 3. 憑證快照 (Snapshot)：持久化保存時僅過濾儲存登入憑證關鍵 Cookie (`AUTH_COOKIES`)，
 *    排除臨時 CSRF 與分析追蹤 Cookie，降低外洩危害。
 * ============================================================================
 */

import { isIP } from 'node:net';

/**
 * 已儲存之 Cookie 物件型別定義
 */
export type StoredCookie = {
  name: string;        // Cookie 名稱
  value: string;       // Cookie 內容值
  domain: string;      // 所屬網域
  hostOnly: boolean;   // 是否限定單一主機 (未帶 Domain 屬性時為 True)
  path: string;        // 有效路徑
  secure: boolean;     // 是否僅限 HTTPS 傳輸
  expiresAt?: number;  // 到期時間戳記 (毫秒)
};

/** 允許接納 Cookie 的網域白名單 */
const COOKIE_DOMAINS = new Set(['chat.line.biz', 'account.line.biz', 'access.line.me', 'line.biz', 'line.me']);
/** 允許設置 Cookie 的主機白名單 */
const COOKIE_HOSTS = new Set(['chat.line.biz', 'account.line.biz', 'access.line.me']);
/** 關鍵身份驗證 Cookie 名稱清單 (僅這些 Cookie 會被納入長期持久化快照) */
const AUTH_COOKIES = new Set(['ses', '__Host-chat-ses', '__Host-ses-account', 'llm', 'cert', 'qrPinCert', '__is_login_sso', '__Host-SID']);

/**
 * 校驗載入之 Cookie 清單結構是否合法且無潛在注入攻擊
 * 
 * @param value - 待驗證之未知物件
 * @returns 是否為合法的 StoredCookie 陣列
 */
export function validLoginCookies(value: unknown): value is StoredCookie[] {
  return Array.isArray(value) && value.length <= 64 && JSON.stringify(value).length <= 64 * 1024 && value.every(c =>
    c && typeof c === 'object' && COOKIE_DOMAINS.has(c.domain) && typeof c.hostOnly === 'boolean' &&
    (!c.hostOnly || COOKIE_HOSTS.has(c.domain)) && c.secure === true &&
    typeof c.path === 'string' && c.path.startsWith('/') && c.path.length <= 2048 && !/[\r\n;]/.test(c.path) &&
    typeof c.name === 'string' && /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/.test(c.name) &&
    typeof c.value === 'string' && c.value.length <= 8192 && !/[\r\n;]/.test(c.value) &&
    (c.expiresAt === undefined || (typeof c.expiresAt === 'number' && Number.isFinite(c.expiresAt))) &&
    (!c.name.startsWith('__Host-') || (c.hostOnly && c.path === '/')));
}

/** 計算未指定 Path 屬性時之預設目錄路徑 */
function defaultCookiePath(pathname: string): string {
  if (!pathname.startsWith('/') || pathname === '/') return '/';
  const end = pathname.lastIndexOf('/');
  return end <= 0 ? '/' : pathname.slice(0, end);
}

/** 依據 RFC 6265 規範進行 Domain 比對 */
function domainMatches(host: string, domain: string, hostOnly: boolean): boolean {
  return hostOnly ? host === domain : host === domain || host.endsWith(`.${domain}`);
}

/**
 * 記憶體 Cookie 管理器 (Memory Cookie Jar)
 */
export class MemoryCookieJar {
  private cookies = new Map<string, StoredCookie>();

  /**
   * 從 Fetch / Node.js HTTP Headers 批量解析並存入 Set-Cookie 標頭
   * 
   * @param url - 發起請求之目標 URL
   * @param headers - HTTP 回應標頭
   */
  setFromHeaders(url: URL, headers: Headers): void {
    const values = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
    for (const value of values) this.set(url, value);
  }

  /**
   * 解析並儲存單條 Set-Cookie 標頭字串
   * 
   * @param url - 發起請求的來源 URL
   * @param header - Set-Cookie 單條字串內容
   */
  set(url: URL, header: string): void {
    // 嚴格限制：僅接受 HTTPS 且主機在白名單內
    if (url.protocol !== 'https:' || !COOKIE_HOSTS.has(url.hostname)) return;
    const parts = header.split(';').map(part => part.trim());
    const pair = parts.shift();
    if (!pair) return;
    const equals = pair.indexOf('=');
    if (equals <= 0) return;
    const name = pair.slice(0, equals);
    const value = pair.slice(equals + 1);
    // 驗證名稱與值長度，並杜絕換行符注入 (CRLF)
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/.test(name) || value.length > 8192 || /[\r\n;]/.test(value)) return;

    let domain = url.hostname.toLowerCase();
    let hostOnly = true;
    let path = defaultCookiePath(url.pathname);
    let secure = false;
    let expiresAt: number | undefined;
    let maxAge: number | undefined;

    // 解析各項 Cookie 屬性 (Domain, Path, Secure, Max-Age, Expires)
    for (const raw of parts) {
      const split = raw.indexOf('=');
      const key = (split < 0 ? raw : raw.slice(0, split)).trim().toLowerCase();
      const attr = split < 0 ? '' : raw.slice(split + 1).trim();
      if (key === 'domain') {
        const candidate = attr.replace(/^\./, '').toLowerCase();
        // 拒絕 IP 位址或不在白名單中的網域
        if (!COOKIE_DOMAINS.has(candidate) || isIP(candidate) || !domainMatches(url.hostname.toLowerCase(), candidate, false)) return;
        domain = candidate;
        hostOnly = false;
      } else if (key === 'path' && attr.startsWith('/')) {
        path = attr;
      } else if (key === 'secure') {
        secure = true;
      } else if (key === 'max-age' && /^-?\d+$/.test(attr)) {
        maxAge = Number(attr);
      } else if (key === 'expires') {
        const parsed = Date.parse(attr);
        if (Number.isFinite(parsed)) expiresAt = parsed;
      }
    }

    if (maxAge !== undefined && Number.isFinite(maxAge)) {
      expiresAt = Date.now() + Math.min(maxAge, 400 * 86_400) * 1000;
    }
    if (path.length > 2048 || /[\r\n;]/.test(path)) return;
    // __Host- 特殊字首安全性校驗
    if (name.startsWith('__Host-') && (!secure || !hostOnly || path !== '/')) return;

    const key = `${domain}\n${path}\n${name}`;
    if (expiresAt !== undefined && expiresAt <= Date.now()) {
      this.cookies.delete(key);
    } else {
      if (!this.cookies.has(key) && this.cookies.size >= 64) throw new Error('LOGIN_COOKIE_LIMIT');
      this.cookies.set(key, { name, value, domain, hostOnly, path, secure, expiresAt });
    }
  }

  /**
   * 依據目標 URL 比對並生成發送用的 HTTP `Cookie` 標頭字串
   * 
   * @param url - 即將請求的目標 URL
   * @returns 格式如 "name1=val1; name2=val2" 的字串
   */
  header(url: URL): string {
    const now = Date.now();
    const matches: StoredCookie[] = [];
    for (const [key, cookie] of this.cookies) {
      if (cookie.expiresAt !== undefined && cookie.expiresAt <= now) {
        this.cookies.delete(key);
        continue;
      }
      if (cookie.secure && url.protocol !== 'https:') continue;
      if (!domainMatches(url.hostname.toLowerCase(), cookie.domain, cookie.hostOnly)) continue;
      if (!(url.pathname === cookie.path || url.pathname.startsWith(cookie.path.endsWith('/') ? cookie.path : `${cookie.path}/`))) continue;
      matches.push(cookie);
    }
    // 依據 RFC 6265，路徑較長者優先排序
    matches.sort((a, b) => b.path.length - a.path.length);
    return matches.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
  }

  /** 取得指定名稱在特定 URL 下的 Cookie 內容值 */
  value(name: string, url: URL): string | undefined {
    const header = this.header(url);
    for (const pair of header.split('; ')) {
      if (pair.startsWith(`${name}=`)) return pair.slice(name.length + 1);
    }
    return undefined;
  }

  /**
   * 從已儲存之持久化陣列復原 Cookie
   * 
   * @param cookies - 儲存之 StoredCookie 陣列
   */
  restore(cookies: StoredCookie[]): void {
    if (!validLoginCookies(cookies)) throw new Error('LOGIN_COOKIES_INVALID');
    for (const c of cookies) {
      if (c.expiresAt !== undefined && c.expiresAt <= Date.now()) continue;
      this.cookies.set(`${c.domain}\n${c.path}\n${c.name}`, structuredClone(c));
    }
  }

  /**
   * 擷取身分認證核心 Cookie 快照，排除臨時性雜項
   * 
   * @returns 經過深度複製的認證 Cookie 清單
   */
  snapshot(): StoredCookie[] {
    this.header(new URL('https://chat.line.biz/'));
    const cookies = [...this.cookies.values()].filter(c => c.secure && AUTH_COOKIES.has(c.name));
    if (!validLoginCookies(cookies)) throw new Error('LOGIN_COOKIE_LIMIT');
    return structuredClone(cookies);
  }

  /** 清空所有 Cookie */
  clear(): void { this.cookies.clear(); }
}
