/**
 * ============================================================================
 * 模組名稱：types.ts
 * 模組用途：定義 LINE OA 閘道全域資料型別、介面與列舉
 * ============================================================================
 */

/**
 * 閘道 LINE Web Session 的運作狀態列舉
 * - CONNECTED：已成功連接並驗證 LINE Session 有效
 * - VALIDATING：正在向 LINE 官方伺服器進行身分驗證
 * - AUTH_REQUIRED：尚未登入，需要掃描 QR Code
 * - EXPIRED：既有 Session 已失效過期，需要人工重新授權
 * - DISCONNECTED：網路斷線或暫時無法連線至 LINE
 * - ERROR：CSRF 驗證失敗、被封鎖或發生未預期錯誤
 */
export type SessionState = 'CONNECTED' | 'VALIDATING' | 'AUTH_REQUIRED' | 'EXPIRED' | 'DISCONNECTED' | 'ERROR';

/**
 * 關鍵 Cookie 結構
 */
export interface CookieValue {
  name: 'ses' | '__Host-chat-ses' | 'XSRF-TOKEN';
  value: string;
}

/**
 * LINE 官方帳號登入會話憑證儲存結構
 */
export interface SessionCredentials {
  version: 1;
  botId: string;                                          // 官方帳號機器人 ID
  accountName?: string;                                  // 官方帳號名稱
  clientVersion?: string;                                // 前端客戶端版本
  csrfToken?: string;                                    // 前端 CSRF 權杖
  cookies: CookieValue[];                                // 聊天室核心 Session Cookies
  loginCookies?: import('./cookie-jar.js').StoredCookie[]; // 完整登入 Cookie Jar
  importedAt: string;                                    // 建立/更新時間 ISO 字串
}

/**
 * 聯絡人/對話資訊物件
 */
export interface Contact {
  chatId: string;           // LINE 對話室專屬 ID
  name: string;             // 聯絡人或群組名稱
  kind: 'user' | 'group';   // 對話類型：個人或群組
  friend: boolean;          // 是否為好友
  chatAvailable: boolean;   // 聊天功能是否已在後台開通
}

/**
 * 聯絡人別名白名單項目
 */
export interface ContactAlias {
  chatId: string;
  name: string;
}

/**
 * 別名對應表字典 (Key 為別名代碼，例如 "dad"、"security_group")
 */
export type AliasMap = Record<string, ContactAlias>;

/**
 * 閘道服務設定物件結構
 */
export interface GatewayConfig {
  instanceId: string;         // 閘道實體唯一識別碼
  listenHost: string;         // 監聽主機 IP 位址
  port: number;               // 監聽通訊埠 (預設 8787)
  contactsCacheTtlMs: number; // 聯絡人快取存活時間 (毫秒)
  uiAuthEnabled: boolean;     // Web UI 是否啟用密碼登入
  apiEnabled: boolean;        // 是否啟用外部 HTTP API
  secureCookies: boolean;     // Cookie 是否強制 Secure 標記
  rateLimitPerMinute: number; // 每分鐘發送頻率上限
  duplicateWindowMs: number;  // 防重複發送的時窗大小 (毫秒)
  maxImageBytes: number;      // 單張圖片最大位元組上限
  maxTempBytes: number;       // 暫存資料夾容量上限
  requestTimeoutMs: number;   // 網路請求逾時時間 (毫秒)
}

/**
 * 訊息傳送結果結構
 */
export interface SendResult {
  error_name?: string;                                    // 錯誤分類名稱
  details?: string;                                       // 遮蔽後的除錯細節
  result: 'SUBMITTED' | 'CONFIRMED' | 'FAILED' | 'UNKNOWN'; // 發送狀態
  sendId: string;                                         // 傳送識別代碼
  status?: number;                                        // HTTP 回應碼
  error?: string;                                         // 錯誤代碼 (如 RATE_LIMIT, AUTH)
}

/**
 * 記憶體運作日誌項目結構
 */
export interface OperationLog {
  localTime?: string; // 當地時區格式化時間
  timezone?: string;  // 時區字串
  details?: string;   // 詳細訊息
  time: string;       // ISO 時間戳記
  operation: string;  // 操作名稱 (如 SEND_TEXT, QR_LOGIN)
  target?: string;    // 目標對象
  result: string;     // 執行結果
  error?: string;     // 錯誤代碼
}
