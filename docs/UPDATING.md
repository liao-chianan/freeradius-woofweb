# 版本更新設計

目前可以重新執行 `install.sh` 手動更新。網頁一鍵更新尚未實作，但下面這些基礎已經就緒。

## 已就緒

- **版本號**：`VERSION` 是唯一來源，頁尾與 `radius-manager version` 都讀它。
- **程式與資料分離**：更新只替換 `/opt/radius-manager/releases/<版本>`，不碰下列資料。

  | 位置 | 內容 |
  |---|---|
  | `/etc/radius-manager` | 管理者帳密、工作階段金鑰、HTTPS 憑證 |
  | `/var/lib/radius-manager` | 設定、登入紀錄資料庫、AP 清單、備份 |
  | `/var/lib/radius-manager-root` | root 才能讀的狀態 |
  | `/etc/freeradius/3.0/clients.conf`、`ldap-google.conf`、`certs/`、`authorized_macs` | 各單位自己的金鑰、憑證與名單 |

- **原子切換與回滾**：`/opt/radius-manager/current` 是符號連結。新版本的 FreeRADIUS 設定檢查失敗或服務起不來時，安裝程式會切回上一版。
- **設定範本**：`freeradius/` 的範本每次更新都會重新套用，所以不要手動改這些檔案。
- **特權操作**：網頁服務沒有 root 權限，更新會是 helper 的一個新動作，不必放寬網頁服務的權限。

## 網頁更新功能的實作計畫

1. **檢查版本**：查 GitHub Releases API 的最新 tag，與 `VERSION` 比較。由使用者按下才檢查，或每天最多一次。
2. **發布檔**：每個 release 附 tar 檔、`SHA256SUMS` 與簽章。helper 內建發布者公鑰，**先驗簽再解開**，簽章不符就中止。只比對 GitHub 上的雜湊不夠，帳號被盜時雜湊也會一起被換掉。
3. **新增 helper 動作 `update`**：參數只接受符合格式的版本號，下載網址由 helper 自己組，不接受網頁傳來的網址。
4. **流程**：下載 → 驗簽 → 備份 → 解開到 `releases/<版本>` → 執行資料遷移 → `freeradius -C` → 切換 `current` → 重啟 → 健康檢查 → 失敗就切回並還原備份。
5. **資料遷移**：`migrations/NNN_name.py` 依序執行，已執行到的編號記在 `/var/lib/radius-manager-root/state.json`。
6. **保留舊版**：`releases/` 留最近 3 版。

更新會重新啟動 FreeRADIUS，認證可能短暫中斷，頁面要先提醒。系統套件由 Debian 更新，建議開啟 unattended-upgrades。
