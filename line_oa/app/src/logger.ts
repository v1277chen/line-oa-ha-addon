/**
 * ============================================================================
 * 模組名稱：logger.ts
 * 模組用途：實作受限記憶體日誌記錄器 (Bounded Memory Logger) 與標準輸出排版
 * 
 * 設計特色：
 * 1. 當地時區支援：使用 Intl.DateTimeFormat 自動依據系統/HA 時區排版可讀時間。
 * 2. 嚴格邊界控制：記憶體僅保留最新 100 筆紀錄，且總 JSON 大小嚴格限制於 4 MiB 以內。
 * 3. 機敏過濾與注入防護：所有日誌文字均自動去除機密憑證並消除換行符 (防止 Log Injection)。
 * ============================================================================
 */

import type { OperationLog } from './types.js';
import { diagnosticText, redactText } from './diagnostics.js';

/**
 * 格式化輸出包含當地時區偏移量之時間戳記字串
 * 
 * @param date - 時間 Date 物件
 * @param timezone - 時區字串 (預設為系統當前時區)
 * @returns 格式如 "2026-10-20 17:30:00 GMT+08:00 [Asia/Taipei]"
 */
export function localTimestamp(date: Date, timezone = Intl.DateTimeFormat().resolvedOptions().timeZone): string {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'longOffset'
  }).formatToParts(date);
  const part = (name: string) => parts.find(p => p.type === name)?.value ?? '';
  return `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')}:${part('second')} ${part('timeZoneName')} [${timezone}]`;
}

/**
 * 記憶體受限日誌記錄器類別
 */
export class MemoryLogger {
  private entries: OperationLog[] = [];
  private latestError?: string;
  readonly timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  /**
   * 新增一筆操作日誌紀錄並輸出至標準輸出 (stdout)
   * 
   * @param operation - 操作名稱 (例如 'SEND_TEXT', 'QR_LOGIN')
   * @param result - 執行結果 (例如 'SUCCESS', 'FAILED')
   * @param target - 操作目標 (例如收件者別名)
   * @param error - 錯誤代碼或說明字串
   * @param details - 任意除錯物件或回應內容 (將自動進行機敏遮蔽)
   */
  add(operation: string, result: string, target?: string, error?: string, details?: unknown): void {
    // 遮蔽敏感字串並移除換行符，防範日誌偽造攻擊
    const safeError = error ? redactText(error).replace(/[\r\n]/g, ' ') : undefined;
    const now = new Date();
    const detail = details === undefined ? undefined : diagnosticText(details);
    const entry: OperationLog = {
      time: now.toISOString(),
      localTime: localTimestamp(now, this.timezone),
      timezone: this.timezone,
      operation: redactText(operation).replace(/[\r\n]/g, ' '),
      result: redactText(result).replace(/[\r\n]/g, ' '),
      ...(target ? { target: redactText(target).replace(/[\r\n]/g, ' ') } : {}),
      ...(safeError ? { error: safeError } : {}),
      ...(detail ? { details: detail } : {})
    };

    // 插入最前端 (最新紀錄排最前)
    this.entries.unshift(entry);
    this.entries.length = Math.min(this.entries.length, 100);

    // 限制整體記憶體佔用在 4 MiB 以內
    let bytes = 0;
    this.entries = this.entries.filter((item, index) => {
      bytes += Buffer.byteLength(JSON.stringify(item));
      return index === 0 || bytes <= 4 * 1024 * 1024;
    });

    if (safeError) this.latestError = safeError.slice(0, 180);

    // 組合單行標準輸出文字
    const line = [entry.localTime, entry.operation, entry.result, entry.target && `對象=${entry.target}`, entry.error].filter(Boolean).join(' | ');
    process.stdout.write(`${line}\n${detail ? detail.split('\n').map(line => `  ${line}`).join('\n') + '\n' : ''}`);
  }

  /** 列出所有記憶體中保留的日誌紀錄清單 (淺層複製) */
  list(): OperationLog[] { return this.entries.map(entry => ({ ...entry })); }

  /** 取得最近一次記錄的錯誤摘要字串 */
  lastError(): string | undefined { return this.latestError; }
}
