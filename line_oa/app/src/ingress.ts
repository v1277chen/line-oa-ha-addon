/**
 * ============================================================================
 * 模組名稱：ingress.ts
 * 模組用途：Home Assistant Ingress 反向代理與安全存取邊界防護
 * 
 * 資安設計特色：
 * 1. 來源 IP 驗證：僅信任來自 Supervisor Ingress 閘道 IP (`172.30.32.2`) 的連線。
 * 2. Ingress 動態路由前綴解析：驗證並提取 `X-Ingress-Path` 標頭。
 * 3. 跨站偽造防護 (Anti-CSRF)：核對 `Sec-Fetch-Site` 與 `Origin` 標頭，拒絕跨站非同步操作。
 * ============================================================================
 */

import type { IncomingMessage } from 'node:http';

/**
 * 驗證發起請求之連線是否源自 Home Assistant Supervisor Ingress 代理
 * 
 * @param req - HTTP 請求物件
 * @returns 若來自 Supervisor 內部 IP (172.30.32.2) 則為 True
 */
export function trustedIngress(req: IncomingMessage): boolean {
  return ['172.30.32.2', '::ffff:172.30.32.2'].includes(req.socket.remoteAddress ?? '');
}

/**
 * 從 HTTP 標頭提取並校驗 Ingress 虛擬路徑前綴
 * 
 * @param req - HTTP 請求物件
 * @returns 合法的 Ingress 路徑 (例如 `/api/hassio_ingress/token`)，若無效則回傳 undefined
 */
export function ingressPath(req: IncomingMessage): string | undefined {
  const value = req.headers['x-ingress-path'];
  return typeof value === 'string' && /^\/api\/hassio_ingress\/[A-Za-z0-9_-]+$/.test(value.replace(/\/$/, ''))
    ? value.replace(/\/$/, '') : undefined;
}

/**
 * 檢查是否允許對 Ingress 介面執行寫入/變更操作 (POST/PUT/DELETE)
 * 
 * @param req - HTTP 請求物件
 * @returns 是否允許此變更操作
 */
export function ingressMutationAllowed(req: IncomingMessage): boolean {
  // GET 與 HEAD 請求為安全唯讀操作，直接放行
  if (req.method === 'GET' || req.method === 'HEAD') return true;
  // 嚴格阻擋跨站點 (Cross-site) 發起的資料修改請求
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const authority = req.headers['x-forwarded-host'] ?? req.headers.host;
    return new URL(origin).host === authority;
  } catch {
    return false;
  }
}
