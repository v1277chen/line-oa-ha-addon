/**
 * ============================================================================
 * 模組名稱：pairing.ts
 * 模組用途：管理 Home Assistant 與 Add-on 閘道之間的一次性配對交握機制
 * 
 * 資安設計特色：
 * 1. 一次性 Bootstrap Token 僅存在於記憶體 (RAM) 中，且僅透過 Supervisor 內部通道廣播。
 * 2. 嚴格時效性 (TTL 10 分鐘)，過期自動重新生成。
 * 3. 換鑰併發防禦 (Lock before await)：在進入非同步前即鎖定 busy 旗標，
 *    保證單一 Token 絕無法被並行併發請求換取多張憑證。
 * 4. 配對端點速率限制：60 秒內最多允許 5 次嘗試，防範暴力猜測。
 * ============================================================================
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { AuthManager } from './auth.js';

/** Bootstrap Token 存活時間上限 (10 分鐘) */
export const BOOTSTRAP_TTL_MS = 10 * 60_000;

/** UUID 格式驗證正規表示式 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** 配對錯誤例外類別 */
export class PairingError extends Error {
  constructor(public readonly status: number, code: string) { super(code); }
}

/**
 * 配對管理核心類別
 */
export class PairingManager {
  private bootstrap?: { token: string; expires: number };
  private busy = false;
  private attempts: number[] = [];
  private lastAuthenticatedAt?: number;

  /**
   * @param auth - 認證管理器實例
   * @param instanceId - 本閘道實體 UUID
   * @param now - 時間提供函式，預設為 Date.now
   */
  constructor(
    private readonly auth: AuthManager,
    public readonly instanceId: string,
    private readonly now: () => number = Date.now
  ) {}

  /**
   * 產出供 Supervisor Discovery 廣播之配對欄位
   * 若已配置 API Key 則告知不需配對；否則回傳記憶體中的 bootstrap_token 與過期時間
   */
  discovery(): Record<string, unknown> {
    if (this.auth.apiKeyConfigured()) return { pairing_required: false };
    if (!this.bootstrap || this.bootstrap.expires <= this.now()) {
      this.bootstrap = { token: randomBytes(32).toString('base64url'), expires: this.now() + BOOTSTRAP_TTL_MS };
    }
    return {
      pairing_required: true,
      bootstrap_token: this.bootstrap.token,
      bootstrap_expires_at: new Date(this.bootstrap.expires).toISOString()
    };
  }

  /**
   * 取得配對狀態摘要 (供 Web UI 介面呈現)
   */
  status(): Record<string, unknown> {
    return {
      paired: this.auth.apiKeyConfigured(),
      pairing_available: !this.auth.apiKeyConfigured(),
      hacs_connected: !!this.lastAuthenticatedAt && this.now() - this.lastAuthenticatedAt < 120_000,
      last_authenticated_at: this.lastAuthenticatedAt ? new Date(this.lastAuthenticatedAt).toISOString() : null
    };
  }

  /** 記錄最近一次成功通過 API Key 認證之時間戳記 */
  authenticated(): void { this.lastAuthenticatedAt = this.now(); }

  /**
   * 處理客戶端 POST /api/v1/pairing/exchange 換鑰請求
   * 
   * @param body - 客戶端傳入之 JSON Body
   * @returns 包含 instance_id 與全新生成的 api_key
   * @throws PairingError
   */
  async exchange(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    // 限流檢查：60 秒內最多 5 次嘗試
    this.attempts = this.attempts.filter(at => this.now() - at < 60_000);
    if (this.attempts.length >= 5) throw new PairingError(429, 'PAIRING_RATE_LIMITED');
    this.attempts.push(this.now());

    // 參數欄位與格式嚴格校驗
    if (
      typeof body.instance_id !== 'string' || !UUID.test(body.instance_id) ||
      typeof body.request_id !== 'string' || !UUID.test(body.request_id) ||
      body.client !== 'homeassistant-line_oa' || typeof body.bootstrap_token !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.bootstrap_token)
    ) {
      throw new PairingError(400, 'INVALID_PAIRING_REQUEST');
    }

    const bootstrap = this.bootstrap;
    // 檢查條件：未忙碌、尚未配置 API Key、Token 存在且未過期、實體 ID 符合、Token 比對一致
    if (
      this.busy || this.auth.apiKeyConfigured() || !bootstrap || bootstrap.expires <= this.now() ||
      body.instance_id !== this.instanceId ||
      !timingSafeEqual(Buffer.from(body.bootstrap_token), Buffer.from(bootstrap.token))
    ) {
      throw new PairingError(401, 'PAIRING_REJECTED');
    }

    // 關鍵資安鎖定：在進入非同步前立即將 busy 設為 true，杜絕競態條件 (Race Condition)
    this.busy = true;
    try {
      const generated = await this.auth.generateApiKey();
      // 成功生成 API Key 後立即銷毀 bootstrap_token，保證單次性
      this.bootstrap = undefined;
      return { instance_id: this.instanceId, api_key: generated.apiKey, api_version: 1 };
    } finally {
      this.busy = false;
    }
  }

  /**
   * 撤銷配對 (供 Web UI 手動重設配對狀態)
   */
  async revoke(): Promise<void> {
    if (this.busy) throw new PairingError(409, 'PAIRING_BUSY');
    this.busy = true;
    try {
      await this.auth.revokeApiKey();
      this.bootstrap = undefined;
      this.lastAuthenticatedAt = undefined;
    } finally {
      this.busy = false;
    }
  }
}
