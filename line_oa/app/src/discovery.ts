/**
 * ============================================================================
 * 模組名稱：discovery.ts
 * 模組用途：向 Home Assistant Supervisor Discovery 服務廣播 Add-on 連線與配對資訊
 * 
 * 運作機制：
 * 1. 透過環境變數 `SUPERVISOR_TOKEN` 向 Supervisor API 發起請求。
 * 2. 查詢 `/addons/self/info` 獲取由系統指派的內部容器 hostname。
 * 3. 定期 (每 30 秒) 向 `/discovery` 發送 POST 廣播，包含 `line_oa` 服務標籤、
 *    主機名稱、埠號 8787、API 版本 1 與短期配對 Token。
 * ============================================================================
 */

import { PairingManager } from './pairing.js';

/** Supervisor HTTP API 請求函式型別 */
export type SupervisorRequest = (path: string, method?: string, body?: unknown) => Promise<Record<string, unknown>>;

/**
 * 建立與 Supervisor 通訊的封裝函式
 * 
 * @param token - Supervisor Token (通常源自 process.env.SUPERVISOR_TOKEN)
 * @param base - Supervisor 內部 API 位址，預設為 'http://supervisor'
 */
export function supervisorRequest(token: string, base = 'http://supervisor'): SupervisorRequest {
  return async (path, method = 'GET', body) => {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000)
    });
    if (!response.ok) throw new Error('SUPERVISOR_UNAVAILABLE');
    const value = await response.json() as { result?: string; data?: Record<string, unknown> };
    if (value.result !== 'ok' || !value.data) throw new Error('SUPERVISOR_INVALID_RESPONSE');
    return value.data;
  };
}

/**
 * 自動探索廣播發布器類別
 */
export class DiscoveryPublisher {
  private timer?: NodeJS.Timeout;
  private active?: Promise<void>;
  private stopped = false;
  private host?: string;
  private published = false;

  /**
   * @param pairing - 配對管理器實例
   * @param request - Supervisor API 調用函式
   * @param report - 廣播狀態回報回呼函式
   */
  constructor(
    private readonly pairing: PairingManager,
    private readonly request: SupervisorRequest,
    private readonly report: (state: string) => void = () => undefined
  ) {}

  /** 取得目前發布狀態 ('published' 或 'retrying') */
  get status(): string { return this.published ? 'published' : 'retrying'; }

  /** 啟動定時廣播循環 (每 30 秒更新一次) */
  start(): void {
    void this.publish();
    this.timer = setInterval(() => { void this.publish(); }, 30_000);
    this.timer.unref();
  }

  /** 觸發一次非同步發布作業 */
  async publish(): Promise<void> {
    if (this.stopped) return;
    if (this.active) { await this.active; return this.publish(); }
    this.active = this.perform();
    try { await this.active; } finally { this.active = undefined; }
  }

  /** 執行真正的 Supervisor Discovery API 廣播 */
  private async perform(): Promise<void> {
    try {
      // 首次執行時向 Supervisor 查詢自身容器的分配 hostname
      if (!this.host) {
        const info = await this.request('/addons/self/info');
        if (typeof info.hostname !== 'string' || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(info.hostname)) {
          throw new Error('SUPERVISOR_HOST_INVALID');
        }
        this.host = info.hostname;
      }
      // 發送 Discovery 服務宣告
      await this.request('/discovery', 'POST', {
        service: 'line_oa',
        config: {
          host: this.host,
          port: 8787,
          instance_id: this.pairing.instanceId,
          api_version: 1,
          ...this.pairing.discovery()
        }
      });
      if (!this.published) this.report('PUBLISHED');
      this.published = true;
    } catch {
      if (this.published) this.report('RETRYING');
      this.published = false;
    }
  }

  /** 停止定時發布廣播 */
  stop(): void {
    this.stopped = true;
    clearInterval(this.timer);
  }
}
