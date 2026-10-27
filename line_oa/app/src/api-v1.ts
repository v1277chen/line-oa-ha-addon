/**
 * ============================================================================
 * 模組名稱：api-v1.ts
 * 模組用途：實作 HTTP API v1 介面標準的回應格式化、請求防重複 (Deduplication)
 *           與 Request ID 驗證
 * ============================================================================
 */

import { createHash, randomUUID } from 'node:crypto';
import type { SendResult, SessionState } from './types.js';

/**
 * API 對外呈現的會話狀態字串型別
 */
export type ApiSessionStatus = 'ready' | 'auth_required' | 'expired' | 'disconnected' | 'error' | 'unknown';

/**
 * API 對外呈現的發送狀態字串型別
 */
export type ApiSendStatus = 'submitted' | 'confirmed' | 'failed' | 'unknown';

/**
 * 訊息發送端點之標準 JSON 回應結構
 */
export interface ApiSendResponse {
  request_id: string;                                // 請求追蹤識別碼 (UUID)
  status: ApiSendStatus;                             // 傳送狀態
  message_id: null;                                  // LINE Web 未回傳個別訊息 ID，固定為 null
  error?: { code: string; message: string };         // 失敗時之錯誤代碼與說明
}

/**
 * 產生 GET /api/v1/health 健康檢查端點回應
 * 
 * @param version - 目前 Add-on 軟體版本號 (如 '0.1.9')
 * @returns 包含狀態、版本與 API 主版本的物件
 */
export function healthResponse(version: string): { status: 'ok'; version: string; api_version: number } {
  return { status: 'ok', version, api_version: 1 };
}

/**
 * 將內部 SessionState 映射為 API 標準的 session_status 與 line_logged_in 布林值
 * 
 * @param state - 內部的 SessionState
 * @returns 映射後的狀態與登入布林值
 */
export function mapSessionState(state: SessionState): { sessionStatus: ApiSessionStatus; lineLoggedIn: boolean | null } {
  switch (state) {
    case 'CONNECTED': return { sessionStatus: 'ready', lineLoggedIn: true };
    case 'AUTH_REQUIRED': return { sessionStatus: 'auth_required', lineLoggedIn: false };
    case 'EXPIRED': return { sessionStatus: 'expired', lineLoggedIn: false };
    case 'DISCONNECTED': return { sessionStatus: 'disconnected', lineLoggedIn: null };
    case 'ERROR': return { sessionStatus: 'error', lineLoggedIn: null };
    default: return { sessionStatus: 'unknown', lineLoggedIn: null };
  }
}

/**
 * 產生 GET /api/v1/status 會話狀態端點之完整回應
 * 
 * @param input - 包含 instanceId, version, state, accountName, lastError 等輸入參數
 * @returns 序列化至 JSON 的完整閘道狀態字典
 */
export function statusResponse(input: {
  instanceId: string;
  version: string;
  state: SessionState;
  accountName?: string;
  lastError?: string;
  loginRequiredReason?: string;
  now?: Date;
}): Record<string, unknown> {
  const mapped = mapSessionState(input.state);
  // 安全清理最後錯誤字串：去除換行並截斷至 180 字元，避免日誌注入
  const safeError = input.lastError?.replace(/[\r\n]/g, ' ').slice(0, 180) ?? null;
  return {
    instance_id: input.instanceId,
    api_version: 1,
    version: input.version,
    gateway_status: 'online',
    line_logged_in: mapped.lineLoggedIn,
    session_status: mapped.sessionStatus,
    ...(input.loginRequiredReason ? { login_required_reason: input.loginRequiredReason } : {}),
    account_name: input.accountName ?? null,
    last_error: safeError,
    updated_at: (input.now ?? new Date()).toISOString()
  };
}

/**
 * 解析與驗證客戶端傳入之 Request ID (UUIDv4)
 * 
 * @param value - 客戶端傳入之 request_id 參數
 * @returns 合法的 UUID 字串 (若傳入空值則自動生成全新 UUIDv4)
 * @throws Error('INVALID_REQUEST_ID') 若格式不符合 UUID 規範
 */
export function parseRequestId(value: unknown): string {
  if (value === undefined || value === null || value === '') return randomUUID();
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error('INVALID_REQUEST_ID');
  }
  return value.toLowerCase();
}

/**
 * 計算訊息內容指紋 (SHA-256 Fingerprint)
 * 用於比對重複請求是否內容完全一致，防止 ID 衝突與參數混淆攻擊
 * 
 * @param parts - 組成內容的字串或 Buffer 清單
 * @returns SHA-256 十六進位字串
 */
export function requestFingerprint(parts: Array<string | Buffer>): string {
  const hash = createHash('sha256');
  for (const part of parts) {
    const value = Buffer.isBuffer(part) ? part : Buffer.from(part);
    // 使用長度加上空字元分界，防止長度擴展與碰撞攻擊
    hash.update(String(value.length));
    hash.update('\0');
    hash.update(value);
    hash.update('\0');
  }
  return hash.digest('hex');
}

/**
 * 將內部的 SendResult 轉換為標準 HTTP API 回應格式
 * 
 * @param requestId - 當前處理的 Request ID
 * @param result - 內部 MessageSender 發送結果
 * @returns ApiSendResponse 標準回傳物件
 */
export function sendResponse(requestId: string, result: SendResult): ApiSendResponse {
  if (result.result === 'SUBMITTED') return { request_id: requestId, status: 'submitted', message_id: null };
  if (result.result === 'CONFIRMED') return { request_id: requestId, status: 'confirmed', message_id: null };
  if (result.result === 'UNKNOWN') return {
    request_id: requestId,
    status: 'unknown',
    message_id: null,
    error: { code: 'SEND_UNKNOWN', message: '發送結果不明，為避免重複訊息不會自動重送' }
  };
  const restricted = result.error === 'RATE_LIMIT' || result.error === 'REJECTED';
  return {
    request_id: requestId,
    status: 'failed',
    message_id: null,
    error: restricted
      ? { code: 'LINE_RESTRICTED', message: 'LINE 拒絕或限制此次發送' }
      : { code: 'SEND_FAILED', message: 'LINE 明確回報發送失敗' }
  };
}

/**
 * 請求去重快取項目結構
 */
interface RequestEntry<T> {
  fingerprint: string;     // 內容 SHA-256 指紋
  expires: number;         // 過期時間戳記 (毫秒)
  promise: Promise<T>;     // 執行中的 Promise
}

/**
 * 請求去重器 (Request Deduplicator)
 * 確保在指定 TTL 時間視窗內，相同 Request ID 的請求僅會真正發送一次，
 * 後續重複請求直接共用並回傳同一個 Promise 執行結果。
 */
export class RequestDeduplicator<T> {
  private entries = new Map<string, RequestEntry<T>>();

  /**
   * @param ttlMs - 快取保留時間 (毫秒)
   * @param maxEntries - 最大記憶體條目數 (預設 256)
   */
  constructor(private readonly ttlMs: number, private readonly maxEntries = 256) {}

  /**
   * 執行去重防護邏輯
   * 
   * @param requestId - 請求唯一識別碼
   * @param fingerprint - 請求內容雜湊指紋
   * @param action - 真正執行發送的非同步函式
   * @returns 包含執行結果與 duplicate 標記的物件
   * @throws Error('REQUEST_ID_CONFLICT') 若同一 ID 卻送入不同內容
   */
  async run(requestId: string, fingerprint: string, action: () => Promise<T>): Promise<{ value: T; duplicate: boolean }> {
    this.prune();
    const existing = this.entries.get(requestId);
    if (existing) {
      if (existing.fingerprint !== fingerprint) throw new Error('REQUEST_ID_CONFLICT');
      return { value: await existing.promise, duplicate: true };
    }
    // 超出容量上限時，依序清除最舊項目 (FIFO)
    while (this.entries.size >= this.maxEntries) {
      this.entries.delete(this.entries.keys().next().value as string);
    }
    const promise = action();
    this.entries.set(requestId, { fingerprint, expires: Date.now() + this.ttlMs, promise });
    return { value: await promise, duplicate: false };
  }

  /**
   * 清除已過期的去重快取紀錄
   */
  private prune(): void {
    const now = Date.now();
    for (const [key, value] of this.entries) {
      if (value.expires <= now) this.entries.delete(key);
    }
  }
}
