/**
 * ============================================================================
 * 模組名稱：diagnostics.ts
 * 模組用途：除錯與錯誤回報訊息格式化，以及機敏資訊遮蔽 (Secret Redaction)
 * 
 * 資安設計特色：
 * 1. 深度字串遮蔽：比對 Session Cookie、Authorization Bearer、PIN 碼、CSRF Token、
 *    URL 查詢參數與動態傳入的已知機密，全面替換為 `[已遮蔽]`。
 * 2. 巢狀結構遞迴解析：能將巢狀 JSON 物件或陣列逐層展開格式化為階層文字，
 *    同時對敏感欄位鍵名進行正規比對過濾。
 * 3. 網絡例外深層解構：遞迴展開 Node.js 網絡錯誤及其深層 cause。
 * ============================================================================
 */

/** 敏感鍵值名稱比對正規表示式 */
const sensitive = /cookie|authorization|token|csrf|password|passwd|secret|session|credential|api[-_]?key|loginState|returnUri|redirectUri|qrCode|pinCode/i;

/**
 * 對純文字字串進行機敏資訊遮蔽替換
 * 
 * @param value - 原始文字內容
 * @param secrets - 需強制替換的已知機密字串清單
 * @returns 去除敏感資料後的安全字串
 */
export function redactText(value: string, secrets: string[] = []): string {
  // 去除不可見控制字元與可能影響雙向文字顯示的危險 Unicode
  let text = value.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '');

  // 優先替換長度較長的已知動態機密字串
  for (const secret of [...new Set(secrets.filter(Boolean))].sort((a, b) => b.length - a.length)) {
    for (const encoded of new Set([secret, encodeURIComponent(secret)])) {
      text = text.split(encoded).join('[已遮蔽]');
    }
  }

  // 透過正規式遮蔽常見敏感標頭、HTML 屬性、Bearer Token 與 URL 參數
  text = text.replace(/((?:set-cookie|cookie|authorization)\s*:\s*)[^\r\n]+/gi, '$1[已遮蔽]')
    .replace(/(\bapp-data\s*=\s*)(?:"[^"]*"|'[^']*')/gi, '$1"[已遮蔽]"')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [已遮蔽]')
    .replace(/(<input\b[^>]*\bvalue\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '$1"[已遮蔽]"')
    .replace(/((?:["']?)(?:[\w-]*(?:token|csrf|password|secret|session|cookie|credential|api[-_]?key)|ses|loginState|pin|pinCode)["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&<>}]+)/gi, '$1[已遮蔽]')
    .replace(/([?&](?:amp;)?[\w.-]+=)[^\s&#"'<>]*/g, '$1[已遮蔽]')
    .replace(/(\/qrlogin\/(?:v1|oauth2)\/[^\s/?"'<>]+\/)[^\s/?"'<>]+/gi, '$1[已遮蔽]');
  return text;
}

/**
 * 將物件、陣列或字串轉換為具可讀性且經過敏感資訊遮蔽的診斷格式文字
 * 
 * @param value - 任意格式的除錯或回應內容
 * @param secrets - 已知的機密清單
 * @returns 格式化排版後的安全診斷文字
 */
export function diagnosticText(value: unknown, secrets: string[] = []): string {
  function lines(item: unknown, prefix = '', depth = 0): string[] {
    if (depth > 25) return [`${prefix}[巢狀深度超過限制]`];
    if (typeof item === 'string') {
      // 若文字為 JSON 格式，先嘗試解析以便展開結構
      try {
        const parsed: unknown = JSON.parse(item);
        if (parsed && typeof parsed === 'object') return lines(parsed, prefix, depth + 1);
      } catch {}
      return [`${prefix}${redactText(item, secrets)}`];
    }
    if (Array.isArray(item)) {
      return item.length
        ? item.flatMap((v, i) => lines(v, `${prefix}[${i + 1}] `, depth + 1))
        : [`${prefix}（空清單）`];
    }
    if (item && typeof item === 'object') {
      return Object.entries(item).filter(([, v]) => v !== undefined).flatMap(([key, v]) =>
        sensitive.test(key) || /^(?:ses|pin)$/i.test(key)
          ? [`${prefix}${key}: [已遮蔽]`]
          : v && typeof v === 'object'
            ? [`${prefix}${key}:`, ...lines(v, `${prefix}  `, depth + 1)]
            : lines(v, `${prefix}${key}: `, depth + 1)
      );
    }
    return [`${prefix}${String(item)}`];
  }
  return redactText(lines(value).join('\n'), secrets);
}

/**
 * 提取並深層解構 Node.js 網路錯誤詳細資訊 (包含原因鏈)
 * 
 * @param error - 攔截到的例外物件
 * @returns 包含錯誤名稱、代碼與訊息的字典
 */
export function networkDetails(error: unknown): Record<string, unknown> {
  return error instanceof Error
    ? {
        name: error.name,
        code: (error as NodeJS.ErrnoException).code,
        message: error.message,
        ...(error.cause instanceof Error ? { cause: networkDetails(error.cause) } : {})
      }
    : { message: String(error) };
}
