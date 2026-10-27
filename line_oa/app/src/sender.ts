/**
 * ============================================================================
 * 模組名稱：sender.ts
 * 模組用途：負責訊息發送前的別名解析、發送頻率限制 (Rate Limiting)、
 *           內容防重複 (Deduplication) 與執行文字及圖片的派送流程
 * 
 * 核心機制：
 * 1. 別名白名單驗證：所有 `who` 目標必須先在聯絡人快取中解析到相應的 `chatId`。
 * 2. 併發防護：發送期間鎖定 `this.active`，避免多個非同步發送交錯導致 Session 競爭。
 * 3. 幂等防重：利用內容 SHA-256 雜湊與時間視窗，防止短期內重複發送相同訊息。
 * 4. 狀態回寫：發送前後自動校驗 Session 存活性，若遇 AUTH/CSRF 失效立即標記狀態。
 * ============================================================================
 */

import { createHash } from 'node:crypto';
import type { SendResult } from './types.js';
import { ContactService } from './contacts.js';
import { LineClient, LineError } from './line-client.js';
import { SessionManager } from './session.js';
import { MemoryLogger } from './logger.js';

/**
 * 訊息發送器核心類別
 */
export class MessageSender {
  private recent = new Map<string, number>();  // 記錄最近發送內容的指紋與時間戳記
  private rate: number[] = [];                 // 最近一分鐘內發送的時間戳記陣列 (用於滑動視窗限流)
  private active = false;                      // 當前是否有發送作業執行中 (排他鎖)
  public submittedCount = 0;                   // 成功提交發送的訊息累計總數
  public lastSubmittedAt?: string;             // 最近一次成功提交發送的時間 ISO 字串

  /**
   * @param client - LINE 官方 Web API 用戶端
   * @param sessions - 會話憑證管理器
   * @param contacts - 聯絡人別名解析服務
   * @param logger - 記憶體操作日誌記錄器
   * @param duplicateWindowMs - 判定重複內容的時窗大小 (毫秒)
   * @param rateLimit - 每分鐘允許發送的最大次數上限
   * @param onMessageSent - 發送完成後之回呼 (用於通知 SessionMonitor 重設閒置計時)
   */
  constructor(
    private readonly client: LineClient,
    private readonly sessions: SessionManager,
    private readonly contacts: ContactService,
    private readonly logger: MemoryLogger,
    private readonly duplicateWindowMs: number,
    private readonly rateLimit: number,
    private readonly onMessageSent: () => void = () => {}
  ) {}

  /** 檢查發送端是否正處於發送忙碌狀態 */
  isBusy(): boolean { return this.active; }

  /**
   * 發送純文字訊息至指定的別名
   * 
   * @param alias - 收件者別名 (在 Add-on 後台設定)
   * @param message - 純文字訊息內容 (最長 5000 字元)
   * @returns SendResult 發送結果物件
   * 
   * @throws Error('INVALID_TARGET') 別名格式不合法
   * @throws Error('INVALID_MESSAGE') 訊息為空或超出長度
   * @throws Error('TARGET_NOT_ALLOWED') 別名未在白名單中
   * @throws Error('SEND_BUSY') 前一則發送尚未結束
   * @throws Error('RATE_LIMITED') 超過每分鐘發送頻率限制
   * @throws Error('DUPLICATE_BLOCKED') 短時間內重複發送相同內容
   * @throws Error('SESSION_*') Session 失效或異常
   */
  async send(alias: string, message: string): Promise<SendResult> {
    // 參數格式驗證
    if (!/^[a-z0-9_-]{1,32}$/.test(alias)) throw new Error('INVALID_TARGET');
    if (typeof message !== 'string' || !message.trim() || message.length > 5000 || /\u0000/.test(message)) {
      throw new Error('INVALID_MESSAGE');
    }

    // 別名解析
    const target = this.contacts.resolve(alias);
    if (!target) throw new Error('TARGET_NOT_ALLOWED');
    if (this.active) throw new Error('SEND_BUSY');

    // 速率限制檢查 (滑動視窗 60 秒)
    const now = Date.now();
    this.rate = this.rate.filter(value => now - value < 60_000);
    if (this.rate.length >= this.rateLimit) throw new Error('RATE_LIMITED');

    // 防重複發送檢查 (SHA-256 指紋比對)
    const fingerprint = createHash('sha256').update(`${alias}\0${message}`).digest('hex');
    const last = this.recent.get(fingerprint);
    if (last && now - last < this.duplicateWindowMs) throw new Error('DUPLICATE_BLOCKED');
    this.recent.set(fingerprint, now);
    for (const [key, at] of this.recent) if (now - at > this.duplicateWindowMs * 2) this.recent.delete(key);

    this.rate.push(now);
    this.active = true;
    try {
      // 發送前驗證 Session 是否存活
      try {
        await this.client.validate();
        this.sessions.mark('CONNECTED', 'Session 驗證成功');
      } catch (error) {
        const kind = error instanceof LineError ? error.kind : 'NETWORK';
        if (kind === 'AUTH') this.sessions.mark('EXPIRED', 'LINE Session 已失效，需要人工重新授權');
        else if (kind === 'CSRF') this.sessions.mark('ERROR', 'CSRF 驗證失敗，已停止發送');
        else this.sessions.mark('DISCONNECTED', `連線驗證失敗：${kind}`);
        this.logger.add('SEND_TEXT', 'FAILED', alias, kind);
        throw new Error(`SESSION_${kind}`);
      }

      // 調用客戶端發送文字
      const result = await this.client.sendText(target.chatId, message);
      if (result.result === 'SUBMITTED') {
        this.submittedCount += 1;
        this.lastSubmittedAt = new Date().toISOString();
      } else if (result.error === 'AUTH') this.sessions.mark('EXPIRED', 'LINE Session 已失效，需要人工重新授權');
      else if (result.error === 'CSRF') this.sessions.mark('ERROR', 'CSRF 驗證失敗，已停止發送');
      else if (result.error === 'RATE_LIMIT') this.sessions.mark('ERROR', 'LINE 回報速率限制，已停止發送');
      else if (result.error === 'NETWORK') this.sessions.mark('DISCONNECTED', 'LINE 連線恢復失敗，請稍後重試');
      else if (result.error === 'INVALID_RESPONSE') this.sessions.mark('ERROR', 'LINE 連線恢復回應異常，請查看日誌');

      this.logger.add('SEND_TEXT', result.result, alias, result.error);
      this.onMessageSent();
      return result;
    } finally {
      this.active = false;
    }
  }

  /**
   * 發送單張圖片 (JPEG / PNG) 至指定的別名
   * 
   * @param alias - 收件者別名
   * @param image - 圖片二進位 Buffer
   * @param mime - 圖片 MIME 類型 ('image/jpeg' 或 'image/png')
   * @returns SendResult 發送結果物件
   */
  async sendImage(alias: string, image: Buffer, mime: 'image/jpeg' | 'image/png'): Promise<SendResult> {
    if (!/^[a-z0-9_-]{1,32}$/.test(alias)) throw new Error('INVALID_TARGET');
    const target = this.contacts.resolve(alias);
    if (!target) throw new Error('TARGET_NOT_ALLOWED');
    if (this.active) throw new Error('SEND_BUSY');

    const now = Date.now();
    this.rate = this.rate.filter(value => now - value < 60_000);
    if (this.rate.length >= this.rateLimit) throw new Error('RATE_LIMITED');

    // 依據目標、格式與圖片內容計算雜湊指紋
    const fingerprint = createHash('sha256').update(alias).update('\0').update(mime).update('\0').update(image).digest('hex');
    const last = this.recent.get(fingerprint);
    if (last && now - last < this.duplicateWindowMs) throw new Error('DUPLICATE_BLOCKED');
    this.recent.set(fingerprint, now);
    for (const [key, at] of this.recent) if (now - at > this.duplicateWindowMs * 2) this.recent.delete(key);

    this.rate.push(now);
    this.active = true;
    try {
      try {
        await this.client.validate();
        this.sessions.mark('CONNECTED', 'Session 驗證成功');
      } catch (error) {
        const kind = error instanceof LineError ? error.kind : 'NETWORK';
        if (kind === 'AUTH') this.sessions.mark('EXPIRED', 'LINE Session 已失效，需要人工重新授權');
        else if (kind === 'CSRF') this.sessions.mark('ERROR', 'CSRF 驗證失敗，已停止發送');
        else this.sessions.mark('DISCONNECTED', `連線驗證失敗：${kind}`);
        this.logger.add('SEND_IMAGE', 'FAILED', alias, kind);
        throw new Error(`SESSION_${kind}`);
      }

      const result = await this.client.sendImage(target.chatId, image, mime);
      if (result.result === 'SUBMITTED') {
        this.submittedCount += 1;
        this.lastSubmittedAt = new Date().toISOString();
      } else if (result.error === 'AUTH') this.sessions.mark('EXPIRED', 'LINE Session 已失效，需要人工重新授權');
      else if (result.error === 'CSRF') this.sessions.mark('ERROR', 'CSRF 驗證失敗，已停止發送');
      else if (result.error === 'RATE_LIMIT') this.sessions.mark('ERROR', 'LINE 回報速率限制，已停止發送');
      else if (result.error === 'NETWORK') this.sessions.mark('DISCONNECTED', 'LINE 連線恢復失敗，請稍後重試');
      else if (result.error === 'INVALID_RESPONSE') this.sessions.mark('ERROR', 'LINE 連線恢復回應異常，請查看日誌');

      this.logger.add('SEND_IMAGE', result.result, alias, result.error);
      this.onMessageSent();
      return result;
    } finally {
      this.active = false;
    }
  }
}
