/**
 * ============================================================================
 * 模組名稱：line-browser.ts
 * 模組用途：提供模擬桌面瀏覽器環境的 User-Agent 識別字串
 * 
 * 設計背景：
 * LINE 官方帳號商務後台 (LINE Business ID / chat.line.biz) 會檢查 HTTP 標頭。
 * 若使用一般 curl 或 Node.js 預設標頭，會被視為機器人或被導向簡易版非互動網頁。
 * 本模組依據目前執行的 CPU 硬體架構，生成匹配的 Chromium 瀏覽器識別標頭。
 * 注意：本 Add-on 僅在底層使用 Node.js 執行輕量 HTTPS 請求，並未啟動真實 Chromium 處理程序。
 * ============================================================================
 */

/**
 * 依據 CPU 硬體架構生成桌面版 Chromium User-Agent 字串。
 * 
 * @param architecture - 當前 Node.js 執行的系統架構 (例如 'x64'、'arm64')，預設為 process.arch
 * @returns 完整的 HTTP User-Agent 標頭字串
 * 
 * 處理邏輯：
 * 1. x64 / ia32 (常見 x86-64 PC/虛擬機)：模擬為 Windows 10 平台 (Windows NT 10.0; Win64; x64)
 * 2. arm64 / arm (如 Raspberry Pi 64 位元)：模擬為 macOS 平台 (Macintosh; Intel Mac OS X 10_15_7)
 * 3. 其他架構：模擬為 Linux X11 平台 (X11; Linux x86_64)
 */
export function lineUserAgent(architecture: NodeJS.Architecture = process.arch): string {
  const platform = architecture === 'x64' || architecture === 'ia32'
    ? 'Windows NT 10.0; Win64; x64'
    : architecture === 'arm64' || architecture === 'arm'
      ? 'Macintosh; Intel Mac OS X 10_15_7'
      : 'X11; Linux x86_64';
  return `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36`;
}

/**
 * 全域共用的 LINE User-Agent 常數實例
 */
export const LINE_USER_AGENT = lineUserAgent();
