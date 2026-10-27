/**
 * ============================================================================
 * 模組名稱：config.ts
 * 模組用途：管理 Add-on 閘道全域設定檔 (config.json) 的載入、自動生成與預設值維護
 * ============================================================================
 */

import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { GatewayConfig } from './types.js';
import { atomicWriteJson, ensurePrivateDir, readJsonSafe } from './storage.js';

/** 根資料目錄，優先取用環境變數 DATA_DIR，預設為容器內的 '/data' */
export const DATA_DIR = process.env.DATA_DIR || '/data';

/**
 * 閘道服務預設組態值
 */
export const DEFAULT_CONFIG: GatewayConfig = {
  instanceId: '',                    // 初始為空，首次開機自動生成 UUIDv4
  listenHost: '0.0.0.0',             // 監聽所有介面
  port: 8787,                        // 監聽連接埠
  contactsCacheTtlMs: 600_000,       // 聯絡人快取存活時間 (10 分鐘)
  uiAuthEnabled: false,              // Ingress 模式下預設關閉 UI 密碼驗證
  apiEnabled: false,                 // 外部 API 啟用旗標
  secureCookies: false,              // 內部 HTTP 連線不強制 Secure Cookie
  rateLimitPerMinute: 5,             // 每分鐘發送頻率上限
  duplicateWindowMs: 60_000,         // 防重複發送的時窗大小 (60 秒)
  maxImageBytes: 10 * 1024 * 1024,   // 圖片大小上限 (10 MiB)
  maxTempBytes: 20 * 1024 * 1024,    // 暫存目錄總容量上限 (20 MiB)
  requestTimeoutMs: 15_000           // 請求逾時時間 (15 秒)
};

/** 校驗設定檔物件欄位合法性 */
function validConfig(value: unknown): value is GatewayConfig {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return typeof v.listenHost === 'string' && Number.isInteger(v.port) && typeof v.apiEnabled === 'boolean' &&
    (v.instanceId === undefined || typeof v.instanceId === 'string');
}

/**
 * 載入或自動生成閘道設定檔
 * 
 * @param dataDir - 資料儲存目錄 (預設 /data)
 * @returns 包含載入完成的 GatewayConfig 與可能的警示訊息
 * @throws Error 若設定檔格式損毀則中斷啟動並提示復原備份
 */
export async function loadConfig(dataDir = DATA_DIR): Promise<{ config: GatewayConfig; warning?: string }> {
  // 確保私有資料目錄、金鑰目錄與暫存目錄存在且具備 0o700 權限
  await ensurePrivateDir(dataDir);
  await ensurePrivateDir(join(dataDir, 'secrets'));
  await ensurePrivateDir(join(dataDir, 'tmp'));

  const path = join(dataDir, 'config.json');
  const loaded = await readJsonSafe(path, DEFAULT_CONFIG, validConfig);
  if (loaded.warning) throw new Error('CONFIG_CORRUPT_RESTORE_BACKUP');
  if (!loaded.warning && loaded.value === DEFAULT_CONFIG) await atomicWriteJson(path, DEFAULT_CONFIG);

  const config = { ...DEFAULT_CONFIG, ...loaded.value };

  // 校驗 instanceId 是否為合法 UUID
  if (config.instanceId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(config.instanceId)) {
    throw new Error('INSTANCE_ID_CORRUPT_RESTORE_BACKUP');
  }

  // 若無 instanceId 則生成全域唯一識別碼並儲存
  const configChanged = !config.instanceId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(config.instanceId);
  if (configChanged) config.instanceId = randomUUID();

  // 強制覆寫 Add-on 必要連線參數
  config.listenHost = '0.0.0.0';
  config.port = 8787;
  config.apiEnabled = true;
  config.uiAuthEnabled = false;

  if (config.port < 1024 || config.port > 65535) config.port = DEFAULT_CONFIG.port;
  if (configChanged) await atomicWriteJson(path, config);

  return { config, warning: loaded.warning };
}
