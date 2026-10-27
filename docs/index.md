# LINE OA — Home Assistant Add-on 說明文件

歡迎閱讀 **LINE OA Home Assistant Add-on** 官方技術與架構說明文件。

本 Add-on 作為 Home Assistant 與 LINE 官方帳號（LINE Official Account）之間的通訊閘道（Gateway），支援發送文字、圖片與各類即時推播通知。

---

## 快速導覽目錄

1. **[安裝與更新說明 (installation.md)](installation.md)**  
   詳細介紹如何透過 Home Assistant Supervisor / App Store 新增儲存庫並安裝本 Add-on。

2. **[硬體架構支援 (architectures.md)](architectures.md)**  
   說明支援的硬體架構（amd64 / aarch64）以及 Raspberry Pi 64 位元系統要求。

3. **[API 相容性規範 (api-compatibility.md)](api-compatibility.md)**  
   詳細列出 HTTP API v1 介面端點、參數定義、回傳格式與錯誤代碼。

4. **[配對與安全性架構 (secure-pairing.md)](secure-pairing.md)**  
   解說與 HACS 整合進行一次性 Bootstrap Token 換取專屬 API Key 的安全交握機制。

5. **[安全防護指南 (security.md)](security.md)**  
   說明憑證遮蔽、防 SSRF 設計、網路隔離邊界等資安細節。

6. **[備份與還原機制 (backups.md)](backups.md)**  
   說明設定檔、LINE 登入 Token 之備份還原與排除暫存檔之策略。

7. **[疑難排解指南 (troubleshooting.md)](troubleshooting.md)**  
   常見錯誤代碼、網路逾時、LINE 官方帳號聊天室開通失敗之解決步驟。

---

> 💡 **注意事項**：使用本 Add-on 必須搭配 [LINE OA HACS 整合](https://github.com/xangin/line-oa-hacs)。
