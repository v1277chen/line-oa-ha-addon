/**
 * ============================================================================
 * 模組名稱：images.ts
 * 模組用途：管理上傳圖片的暫存檔案管理 (Staging)、容量總額限制與格式特徵碼驗證
 * 
 * 資安設計特色：
 * 1. 魔術位元組強檢驗：不僅核對 MIME 字串，更直接檢查 JPEG (FF D8 FF) 與 PNG (89 50 4E 47 ...) 簽名。
 * 2. 序列化容量檢查佇列 (Serialized Staging Queue)：透過 Promise 鏈確保多個並行上傳不會
 *    同時超額扣抵暫存磁碟容量。
 * 3. 專屬權限：暫存目錄設為 0o700，暫存檔案以排他建立 ('wx') 且設為 0o600 權限。
 * ============================================================================
 */

import { mkdir, open, readdir, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

/**
 * 圖片暫存與管理類別
 */
export class ImageSender {
  private staging: Promise<void> = Promise.resolve();

  /**
   * @param tmpDir - 暫存檔案儲存目錄路徑
   * @param maxFileBytes - 單檔最大容量限制 (位元組)
   * @param maxTotalBytes - 暫存目錄總容量上限 (位元組)
   */
  constructor(
    private readonly tmpDir: string,
    private readonly maxFileBytes: number,
    private readonly maxTotalBytes: number
  ) {}

  /**
   * 初始化暫存目錄並清空殘留的舊暫存檔
   */
  async init(): Promise<void> {
    await mkdir(this.tmpDir, { recursive: true, mode: 0o700 });
    await this.cleanup();
  }

  /**
   * 驗證圖片檔案的大小、MIME 類型與 Magic Bytes 簽名
   * 
   * @param buffer - 圖片位元組 Buffer
   * @param mime - 宣稱的 MIME 類型 ('image/jpeg' 或 'image/png')
   * @throws Error('IMAGE_TYPE_NOT_ALLOWED') 格式不被允許
   * @throws Error('IMAGE_SIZE_LIMIT') 超出單檔容量限制
   * @throws Error('IMAGE_SIGNATURE_INVALID') 檔案特徵碼與 MIME 不符 (偽造副檔名)
   */
  validate(buffer: Buffer, mime: string): void {
    if (!['image/jpeg', 'image/png'].includes(mime)) throw new Error('IMAGE_TYPE_NOT_ALLOWED');
    if (buffer.length === 0 || buffer.length > this.maxFileBytes) throw new Error('IMAGE_SIZE_LIMIT');
    // JPEG 開頭特徵：FF D8 FF
    const jpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    // PNG 開頭特徵：89 50 4E 47 0D 0A 1A 0A
    const png = buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    if ((mime === 'image/jpeg' && !jpeg) || (mime === 'image/png' && !png)) {
      throw new Error('IMAGE_SIGNATURE_INVALID');
    }
  }

  /**
   * 將圖片寫入安全暫存檔案，準備提供給 LINE 上傳
   * 
   * @param buffer - 圖片二進位內容
   * @param mime - MIME 類型
   * @returns 產生的暫存檔案絕對路徑
   * @throws Error('TEMP_CAPACITY_LIMIT') 暫存磁碟容量已達上限
   */
  async stage(buffer: Buffer, mime: string): Promise<string> {
    this.validate(buffer, mime);
    // 透過 staging 鏈確保檢查與寫入在單一序列中進行，防止併發超額消費空間
    const pending = this.staging.then(async () => {
      const current = await this.totalBytes();
      if (current + buffer.length > this.maxTotalBytes) throw new Error('TEMP_CAPACITY_LIMIT');
      const path = join(this.tmpDir, `${randomUUID()}${mime === 'image/png' ? '.png' : '.jpg'}`);
      // 使用 'wx' 旗標確保檔案不存在才建立，模式設為 0o600
      const handle = await open(path, 'wx', 0o600);
      try {
        await handle.writeFile(buffer);
        await handle.close();
        return path;
      } catch (error) {
        await handle.close().catch(() => undefined);
        await unlink(path).catch(() => undefined);
        throw error;
      }
    });
    this.staging = pending.then(() => undefined, () => undefined);
    return pending;
  }

  /** 刪除指定的暫存檔案 */
  async remove(path: string): Promise<void> {
    await unlink(path).catch(() => undefined);
  }

  /** 清空暫存目錄中的所有檔案 */
  async cleanup(): Promise<void> {
    for (const name of await readdir(this.tmpDir).catch(() => [] as string[])) {
      await unlink(join(this.tmpDir, name)).catch(() => undefined);
    }
  }

  /** 計算暫存目錄中現存檔案的總容量 (位元組) */
  async totalBytes(): Promise<number> {
    let total = 0;
    for (const name of await readdir(this.tmpDir)) {
      try {
        total += (await stat(join(this.tmpDir, name))).size;
      } catch (error) {
        // 忽略在掃描期間剛被其他傳送程序刪除的檔案，其他錯誤則往上拋出
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    return total;
  }
}
