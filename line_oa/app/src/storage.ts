/**
 * ============================================================================
 * 模組名稱：storage.ts
 * 模組用途：提供原子化寫入 (Atomic Write)、唯讀安全性檢查與持久化檔案操作
 * 
 * 資安與強韌性設計特色：
 * 1. 原子化置換 (Atomic Rename)：先將內容寫入暫存檔 (`.<hex>.tmp`)，執行 `sync()` 強制刷入磁碟，
 *    再呼叫 `rename()` 置換原檔，杜絕寫入中途斷電導致檔案損毀。
 * 2. 目錄同步 (Directory Fsync)：置換後對父目錄執行 `open()` 與 `sync()`，
 *    符合 POSIX 檔案持久化保證。
 * 3. 專屬私有檔案權限：目錄強制 0o700 (僅擁有者可讀寫執行)，檔案強制 0o600 (僅擁有者可讀寫)。
 * 4. 寫入序列鎖：同路徑寫入透過 Promise 鏈排隊，避免並行寫入造成暫存檔衝突。
 * ============================================================================
 */

import { mkdir, open, readFile, rename, chmod, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

/** 追蹤不同檔案路徑的進行中寫入 Promise 佇列 */
const writes = new Map<string, Promise<void>>();

/**
 * 確保目標目錄存在且具備專屬私有權限 (0o700)
 * 
 * @param path - 目錄絕對路徑
 */
export async function ensurePrivateDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
}

/**
 * 安全讀取並解析 JSON 檔案 (含自訂 Schema 驗證與自動修復檔案權限)
 * 
 * @param path - 檔案絕對路徑
 * @param fallback - 若檔案不存在或損壞時的回退預設值
 * @param validate - 型別防衛驗證函式 (Type Guard)
 * @returns 包含解析值與可能的警告訊息物件
 */
export async function readJsonSafe<T>(
  path: string,
  fallback: T,
  validate: (value: unknown) => value is T
): Promise<{ value: T; warning?: string }> {
  try {
    const raw = await readFile(path, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!validate(parsed)) return { value: fallback, warning: `INVALID_JSON_SCHEMA:${path}` };
    await chmod(path, 0o600);
    return { value: parsed };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { value: fallback };
    return { value: fallback, warning: `INVALID_JSON:${path}` };
  }
}

/**
 * 原子化非同步寫入 JSON 檔案
 * 
 * @param path - 目標檔案路徑
 * @param value - 欲序列化之資料物件
 * @param mode - 檔案權限模式，預設 0o600
 */
export async function atomicWriteJson(path: string, value: unknown, mode = 0o600): Promise<void> {
  const previous = writes.get(path) ?? Promise.resolve();
  const current = previous.then(async () => {
    await ensurePrivateDir(dirname(path));
    // 產生不可預測的隨機暫存檔名
    const temp = join(dirname(path), `.${randomBytes(12).toString('hex')}.tmp`);
    const handle = await open(temp, 'wx', mode);
    try {
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
      // 將資料強制刷入實體硬碟 (fsync)
      await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(temp, mode);
    try {
      // 原子化置換目標檔案
      await rename(temp, path);
      // 同步父目錄以持久化目錄項 (Directory Entry)。在 Windows (win32) 下不支援目錄 fsync，予以略過
      if (process.platform !== 'win32') {
        const directory = await open(dirname(path), 'r');
        try { await directory.sync(); } finally { await directory.close(); }
      }
    } catch (error) {
      await unlink(temp).catch(() => undefined);
      throw error;
    }
  });

  writes.set(path, current.catch(() => undefined));
  await current;
}
