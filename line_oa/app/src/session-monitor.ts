/**
 * ============================================================================
 * 模組名稱：session-monitor.ts
 * 模組用途：背景排程監控 LINE Web Session 存活性，自動進行低頻保活與失效探測
 * 
 * 設計特色：
 * 1. 隨機抖動延遲 (Jittered Idle Delay)：
 *    基礎間隔 30 分鐘，加上 0~30 分鐘的隨機抖動 (Jitter)，避免形成規律週期的固定請求特徵，
 *    大幅降低被 LINE 伺服器判定為自動化爬蟲的風險。
 * 2. 閒置計時重設：當有真實訊息發送時，自動延後下一次背景探針執行時機。
 * 3. 純唯讀探測：背景檢查僅呼叫輕量唯讀 API，絕不發起訊息，亦不在背景自動彈出 QR Code。
 * 4. 已失效靜默：若 Session 已確認過期 (EXPIRED)，停止持續騷擾 LINE 伺服器，靜候管理員掃碼。
 * ============================================================================
 */

import { randomInt } from 'node:crypto';
import { LineClient, LineError } from './line-client.js';
import { SessionManager } from './session.js';
import { MemoryLogger } from './logger.js';

/** 背景檢查基礎閒置間隔 (30 分鐘) */
export const SESSION_IDLE_DELAY_MS = 30 * 60_000;
/** 隨機抖動時間範圍上限 (30 分鐘) */
export const SESSION_IDLE_JITTER_MS = 30 * 60_000;

/**
 * 計算下一次背景檢查的延遲時間 (30 ~ 60 分鐘隨機值)
 * 
 * @returns 毫秒數
 */
export function sessionIdleDelayMs(): number {
  return SESSION_IDLE_DELAY_MS + randomInt(SESSION_IDLE_JITTER_MS + 1);
}

/**
 * 會話背景監控器類別
 */
export class SessionMonitor {
  private timer?: NodeJS.Timeout;
  private active?: Promise<void>;
  private stopped = false;
  private started = false;
  private generation = 0;

  /**
   * @param sessions - 會話憑證管理器
   * @param client - LINE API 用戶端
   * @param logger - 記憶體日誌記錄器
   * @param busy - 檢查發送端是否忙碌之回呼
   * @param nextDelayMs - 計算下次間隔函式，預設為 sessionIdleDelayMs
   */
  constructor(
    private readonly sessions: SessionManager,
    private readonly client: LineClient,
    private readonly logger: MemoryLogger,
    private readonly busy: () => boolean,
    private readonly nextDelayMs: () => number = sessionIdleDelayMs
  ) {}

  /** 啟動背景監控排程 */
  start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.schedule();
  }

  /**
   * 當成功發送或嘗試發送訊息時調用，重新計算閒置視窗
   */
  messageSent(): void {
    if (!this.started || this.stopped) return;
    ++this.generation;
    this.schedule();
  }

  /** 排定下一次計時器 */
  private schedule(): void {
    clearTimeout(this.timer);
    const generation = this.generation;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.cycle(generation);
    }, this.nextDelayMs());
    // unref 允許 Node.js 程序在無其他任務時自然退出
    this.timer.unref();
  }

  /** 週期循環執行器 */
  private async cycle(generation: number): Promise<void> {
    try {
      await this.check();
    } finally {
      if (!this.stopped && generation === this.generation) {
        this.schedule();
      }
    }
  }

  /**
   * 執行一次 LINE Session 存活性校驗
   */
  async check(): Promise<void> {
    if (this.stopped) return;
    if (this.active) return this.active;
    const credentials = this.sessions.getCredentials();
    // 若無憑證、已確認過期或發送端正忙碌，則跳過此輪
    if (!credentials || this.sessions.getStatus().state === 'EXPIRED' || this.busy()) return;

    this.active = (async () => {
      let state: 'CONNECTED' | 'EXPIRED' | 'DISCONNECTED' | 'ERROR' = 'CONNECTED';
      let code: string | undefined;
      try {
        await this.client.validate();
      } catch (error) {
        const kind = error instanceof LineError ? error.kind : 'NETWORK';
        state = kind === 'AUTH' ? 'EXPIRED' : kind === 'NETWORK' ? 'DISCONNECTED' : 'ERROR';
        code = error instanceof LineError ? error.code : 'SESSION_VALIDATION_FAILED';
      }

      // 檢查執行期間是否已被手動登出、重設或關閉
      if (this.stopped || this.sessions.getCredentials() !== credentials) return;
      const changed = this.sessions.getStatus().state !== state;
      this.sessions.mark(state, state === 'CONNECTED' ? '背景 Session 驗證成功' : `背景驗證失敗：${code}`);
      if (changed) {
        this.logger.add('SESSION_BACKGROUND_VALIDATE', state === 'CONNECTED' ? 'SUCCESS' : 'FAILED', undefined, code);
      }
    })();

    try {
      await this.active;
    } finally {
      this.active = undefined;
    }
  }

  /** 停止監控排程 */
  stop(): void {
    this.stopped = true;
    ++this.generation;
    clearTimeout(this.timer);
  }
}
