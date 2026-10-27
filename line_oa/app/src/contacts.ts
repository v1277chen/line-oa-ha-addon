/**
 * ============================================================================
 * 模組名稱：contacts.ts
 * 模組用途：管理 LINE 官方帳號對話聯絡人查詢快取、持久化儲存與別名 (Alias) 白名單映射
 * 
 * 核心功能：
 * 1. 聯絡人快取：向 LINE 抓取聯絡人清單並快取於記憶體與 `contacts.json`。
 * 2. 別名白名單管理：管理 `aliases.json`，將簡短別名 (如 'mom') 映射至 LINE 內部 `chatId`。
 * 3. 升級遷移：自動相容舊版 (v0.4.0 前) 的設定檔案格式。
 * ============================================================================
 */

import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import type { AliasMap, Contact, ContactAlias } from './types.js';
import { atomicWriteJson, readJsonSafe } from './storage.js';
import { LineClient } from './line-client.js';

/** 聯絡人快取檔案結構 */
interface ContactCacheFile {
  version: 1;
  updatedAt: string;
  contacts: Contact[];
}

/** 校驗別名對應字典格式是否合法 */
function validAliases(value: unknown): value is AliasMap {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.entries(value).every(([key, item]) =>
    /^[a-z0-9_-]{1,32}$/.test(key) && !!item && typeof item === 'object' &&
    /^[A-Za-z0-9_-]{10,128}$/.test((item as ContactAlias).chatId) &&
    typeof (item as ContactAlias).name === 'string'
  );
}

/** 校驗單一聯絡人物件合法性 */
function validContact(value: unknown): value is Contact {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Partial<Contact>;
  return /^[A-Za-z0-9_-]{10,128}$/.test(item.chatId ?? '') &&
    typeof item.name === 'string' && item.name.length > 0 && item.name.length <= 100 &&
    (item.kind === 'user' || item.kind === 'group') &&
    typeof item.friend === 'boolean' && typeof item.chatAvailable === 'boolean';
}

/** 校驗聯絡人快取檔案合法性 */
function validContactCache(value: unknown): value is ContactCacheFile {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const file = value as Partial<ContactCacheFile>;
  return file.version === 1 && typeof file.updatedAt === 'string' && Number.isFinite(Date.parse(file.updatedAt)) &&
    Array.isArray(file.contacts) && file.contacts.length <= 10_000 && file.contacts.every(validContact);
}

/**
 * 聯絡人與別名服務類別
 */
export class ContactService {
  private cache = new Map<string, { at: number; list: Contact[]; next?: string }>();
  private stored = new Map<string, Contact>();
  private aliases = new Map<string, ContactAlias>();
  private generation = 0;
  private readonly contactsPath: string;
  private readonly aliasesPath: string;
  public warning?: string;

  /**
   * @param client - LINE API 用戶端實例
   * @param dataDir - 資料儲存目錄路徑
   * @param ttlMs - 查詢結果快取存活時間 (毫秒)
   */
  constructor(private readonly client: LineClient, dataDir: string, private readonly ttlMs: number) {
    this.contactsPath = join(dataDir, 'contacts.json');
    this.aliasesPath = join(dataDir, 'aliases.json');
  }

  /**
   * 從磁碟載入 aliases.json 與 contacts.json
   */
  async load(): Promise<void> {
    const warnings: string[] = [];
    const aliases = await readJsonSafe(this.aliasesPath, {} as AliasMap, validAliases);
    this.aliases = new Map(Object.entries(aliases.value));
    if (aliases.warning) warnings.push(aliases.warning);

    const contacts = await readJsonSafe<ContactCacheFile | null>(
      this.contactsPath,
      null,
      (value): value is ContactCacheFile | null => value === null || validContactCache(value)
    );
    if (contacts.value) {
      for (const contact of contacts.value.contacts) this.stored.set(contact.chatId, contact);
    } else if (contacts.warning) {
      // 相容性處理：v0.4.0 以前 contacts.json 存放別名，在此自動平滑遷移
      const legacy = await readJsonSafe<AliasMap | null>(
        this.contactsPath,
        null,
        (value): value is AliasMap | null => value === null || validAliases(value)
      );
      if (legacy.value && !legacy.warning) {
        this.aliases = new Map([...Object.entries(legacy.value), ...this.aliases]);
        await atomicWriteJson(this.aliasesPath, this.getAliases());
        await this.persistContacts();
      } else {
        warnings.push(contacts.warning);
      }
    } else {
      await this.persistContacts();
    }

    if (!aliases.warning && this.aliases.size === 0) await atomicWriteJson(this.aliasesPath, {});
    await this.persistContacts();
    this.warning = warnings.length ? warnings.join(';') : undefined;
  }

  /**
   * 搜尋或分頁取得 LINE 聯絡人清單
   * 
   * @param query - 搜尋關鍵字 (預設為空)
   * @param force - 是否強制穿透快取向 LINE 官方拉取最新資料
   * @param next - 分頁游標
   * @returns 聯絡人清單、下一頁游標與 cached 標記
   */
  async search(query = '', force = false, next?: string): Promise<{ list: Contact[]; next?: string; cached: boolean }> {
    if (query.length > 100 || (next && next.length > 500)) throw new Error('INVALID_INPUT');
    const key = `${query}\n${next ?? ''}`;
    const cached = this.cache.get(key);
    if (!force && cached && Date.now() - cached.at < this.ttlMs) {
      return { list: cached.list, next: cached.next, cached: true };
    }
    const generation = this.generation;
    const result = await this.client.getContacts(query, 20, next);
    if (generation !== this.generation) throw new Error('SESSION_CHANGED');
    this.cache.set(key, { at: Date.now(), ...result });
    if (this.cache.size > 20) this.cache.delete(this.cache.keys().next().value as string);
    for (const contact of result.list) this.stored.set(contact.chatId, contact);
    await this.persistContacts();
    return { ...result, cached: false };
  }

  /** 清空聯絡人快取 */
  clearCache(): void {
    ++this.generation;
    this.cache.clear();
    this.stored.clear();
  }

  /** 取得目前已快取的所有聯絡人清單 */
  allCached(): Contact[] { return [...this.stored.values()]; }

  /** 快取中的聯絡人筆數 */
  count(): number { return this.stored.size; }

  /** 取得完整的別名字典副本 */
  getAliases(): AliasMap { return structuredClone(Object.fromEntries(this.aliases)); }

  /** 列出所有別名與對應的對話類型 (供 Web UI 呈現) */
  listAliases(): Array<{ alias: string; name: string; type: 'user' | 'group' | 'unknown' }> {
    return [...this.aliases].map(([alias, value]) => ({
      alias,
      name: value.name,
      type: this.stored.get(value.chatId)?.kind ?? 'unknown'
    }));
  }

  /**
   * 依據別名字串解析出目標 ContactAlias 物件
   * 
   * @param alias - 別名代碼
   * @returns ContactAlias 物件，若不在白名單中則為 undefined
   */
  resolve(alias: string): ContactAlias | undefined {
    return this.aliases.get(alias);
  }

  /**
   * 設定或新增收件者別名
   * 
   * @param alias - 別名代碼 (如 'dad'，僅允許英數底線減號，長度 1~32 字元)
   * @param chatId - LINE 官方對話室 ID (必須先存在於目前快取聯絡人中)
   * @throws INVALID_ALIAS 當別名命名不符規範時
   * @throws CONTACT_NOT_IN_CACHE 當快取中未找到該 chatId 之聯絡人時
   */
  async setAlias(alias: string, chatId: string): Promise<void> {
    const cleanAlias = String(alias ?? '').trim().toLowerCase();
    if (!/^[a-z0-9_-]{1,32}$/.test(cleanAlias)) throw new Error('INVALID_ALIAS');
    const contact = this.stored.get(chatId);
    if (!contact) throw new Error('CONTACT_NOT_IN_CACHE');
    this.aliases.set(cleanAlias, { chatId, name: contact.name });
    await atomicWriteJson(this.aliasesPath, this.getAliases());
  }

  /**
   * 刪除指定別名
   * 
   * @param alias - 欲移除之別名代碼
   */
  async deleteAlias(alias: string): Promise<void> {
    this.aliases.delete(alias);
    await atomicWriteJson(this.aliasesPath, this.getAliases());
  }

  /**
   * 清理舊版持久化聯絡人檔案 (搜尋結果僅保留於記憶體 RAM 中)
   */
  private async persistContacts(): Promise<void> {
    // 搜尋結果保留於 RAM；舊版匯入之 contacts.json 檔案予以移除以節省磁碟空間
    await unlink(this.contactsPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}
