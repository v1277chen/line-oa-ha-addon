/**
 * ============================================================================
 * 模組名稱：multipart.ts
 * 模組用途：純 Node.js 原生實作高效能、安全之 multipart/form-data 圖片上傳解析器
 * 
 * 資安設計特色：
 * 1. 零第三方依賴：完全使用 Node.js Buffer 操作，無外部 npm 表單解析包的潛在漏洞。
 * 2. 嚴格邊界 (Boundary) 校驗：防止換行注入與格式混淆。
 * 3. 欄位白名單機制：僅接納 'who'、'image'、'message'、'request_id' 四種指定欄位，
 *    阻擋重複欄位 (Duplicate Fields) 攻擊。
 * 4. 嚴格 UTF-8 字串校驗：防止非合法編碼或含有空字元 (Null byte) 造成的路徑截斷。
 * ============================================================================
 */

/**
 * 解析後之圖片表單結構
 */
export interface ImageMultipart {
  who: string;          // 收件者別名
  image: Buffer;        // 圖片二進位 Buffer
  imageType: string;    // MIME 類型 (例如 'image/jpeg')
  message?: string;     // 附加文字 (若有)
  requestId?: string;   // 請求追蹤 UUID
}

/**
 * 從 Content-Disposition 標頭字串中提取特定 key (如 name 或 filename) 之內容值
 */
function dispositionValue(header: string, key: string): string | undefined {
  const match = new RegExp(`(?:^|;)\\s*${key}="([^"]*)"`, 'i').exec(header);
  return match?.[1];
}

/**
 * 從 HTTP Content-Type 標頭中提取並校驗 multipart boundary 字串
 * 
 * @param contentType - HTTP 標頭值
 * @returns 合法的 boundary 分界字串
 * @throws Error('INVALID_MULTIPART') 格式不符
 */
export function multipartBoundary(contentType: string): string {
  const match = /^multipart\/form-data\s*;\s*boundary=(?:"([A-Za-z0-9'()+_,.\/:=? -]{1,70})"|([A-Za-z0-9'()+_,.\/:=?-]{1,70}))\s*$/i.exec(contentType);
  const boundary = match?.[1] ?? match?.[2];
  if (!boundary || /[\r\n]/.test(boundary)) throw new Error('INVALID_MULTIPART');
  return boundary;
}

/**
 * 針對 POST /api/v1/messages/image 請求 Body 進行安全分段解析
 * 
 * @param body - 原始 HTTP 請求二進位 Buffer
 * @param contentType - Content-Type 標頭字串
 * @returns 解析後之 ImageMultipart 物件
 * @throws Error('INVALID_MULTIPART') 格式錯誤、欄位缺失或含非法字元
 */
export function parseImageMultipart(body: Buffer, contentType: string): ImageMultipart {
  const boundary = multipartBoundary(contentType);
  const delimiter = Buffer.from(`--${boundary}`);
  const nextDelimiter = Buffer.from(`\r\n--${boundary}`);

  if (!body.subarray(0, delimiter.length).equals(delimiter)) throw new Error('INVALID_MULTIPART');

  const fields = new Map<string, { value: Buffer; type?: string; filename?: string }>();
  let position = delimiter.length;

  while (position < body.length) {
    if (body.subarray(position, position + 2).toString() === '--') break;
    if (body.subarray(position, position + 2).toString() !== '\r\n') throw new Error('INVALID_MULTIPART');
    position += 2;

    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), position);
    if (headerEnd < 0 || headerEnd - position > 16_384) throw new Error('INVALID_MULTIPART');

    const headerText = body.subarray(position, headerEnd).toString('latin1');
    const headers = new Map<string, string>();
    for (const line of headerText.split('\r\n')) {
      const split = line.indexOf(':');
      if (split <= 0) throw new Error('INVALID_MULTIPART');
      headers.set(line.slice(0, split).trim().toLowerCase(), line.slice(split + 1).trim());
    }

    const disposition = headers.get('content-disposition') ?? '';
    if (!/^form-data(?:;|$)/i.test(disposition)) throw new Error('INVALID_MULTIPART');

    const name = dispositionValue(disposition, 'name');
    if (!name || !['who', 'image', 'message', 'request_id'].includes(name) || fields.has(name)) {
      throw new Error('INVALID_MULTIPART');
    }

    const filename = dispositionValue(disposition, 'filename');
    const dataStart = headerEnd + 4;
    const dataEnd = body.indexOf(nextDelimiter, dataStart);
    if (dataEnd < 0) throw new Error('INVALID_MULTIPART');

    fields.set(name, { value: body.subarray(dataStart, dataEnd), type: headers.get('content-type'), filename });
    position = dataEnd + nextDelimiter.length;
  }

  const who = fields.get('who');
  const image = fields.get('image');
  if (!who || who.filename !== undefined || !image || image.filename === undefined) throw new Error('INVALID_MULTIPART');

  const text = (field: string, max: number): string | undefined => {
    const part = fields.get(field);
    if (!part) return undefined;
    if (part.filename !== undefined || part.value.length > max || part.value.includes(0)) throw new Error('INVALID_MULTIPART');
    const value = part.value.toString('utf8');
    if (!Buffer.from(value).equals(part.value)) throw new Error('INVALID_MULTIPART');
    return value;
  };

  return {
    who: text('who', 64) ?? '',
    image: Buffer.from(image.value),
    imageType: image.type?.toLowerCase() ?? '',
    ...(fields.has('message') ? { message: text('message', 5000) } : {}),
    ...(fields.has('request_id') ? { requestId: text('request_id', 128) } : {})
  };
}
