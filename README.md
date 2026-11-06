# freeradius-woofweb專案介紹


在Debian上配合開源專案freeradius的自製簡易管理web介面，用來管理校內的無線網路Wi-Fi 的 802.1X 認證
後端驗證可搭配mac address白名單、google workspace帳號、samba AD帳號、以及外部proxy代理

感謝freeradius原始開發團隊 https://github.com/FreeRADIUS/

# 既有功能說明：

- **放行裝置名單**：以 MAC 認證，可依裝置指定 VLAN
- **AD 帳號**：PEAP-MSCHAPv2，透過 winbind 驗證
- **Google Workspace 帳號**：透過 Secure LDAP 驗證，Google SSID 優先提議 EAP-TTLS，內層接受 PAP 與 GTC
- **Wi-Fi 使用權限**：在 AD 帳號頁勾選群組、在 Google 帳號頁勾選機構，只有勾選的才能通過驗證（預設不限制）
- **黑名單**：AD 帳號頁與 Google 帳號頁各有黑名單，名單內的帳號一律拒絕（優先於群組與裝置數設定）；Google 以完整 email 比對
- **Proxy 代理**：指定的 SSID 以可選的外層（PEAP、TTLS）與內層（MSCHAPv2、PAP、GTC）連到本機，確認帳號符合黑白名單（關鍵字）後把內層驗證轉給外部 RADIUS（MSCHAPv2 以 MS-CHAPv2、PAP 與 GTC 以 PAP），並依 SSID 規則指派 VLAN；成功與失敗都有紀錄
- **SSID 規則**：依 SSID 關鍵字決定驗證方式與 VLAN
- **登入紀錄、驗證失敗歷史、AP 管理、每個帳號的裝置數上限**

## 安裝方式
在一台全新的 Debian 13 上，用一行指令裝好 FreeRADIUS 與網頁管理介面，管理學校或企業 Wi-Fi 的 802.1X 認證。
在全新的 Debian 13，用有 sudo 權限的帳號執行（Debian 預設沒有 curl，所以用 wget）：

```bash
wget -O install.sh https://raw.githubusercontent.com/liao-chianan/freeradius-woofweb/main/install.sh && sudo bash install.sh
```
第一次安裝會詢問管理介面的連接埠（直接按 Enter 用預設的 3333或者自行輸入）。

裝完會顯示一次性連結，用瀏覽器開啟後完成初始化。管理介面是 `https://<主機 IP>:<連接埠>/woofradius/`，其他路徑（包括 `/`）一律回 404，外部掃描看不到登入頁。一開始用自簽憑證，所以瀏覽器會出現警告。連接埠與路徑存在 `/etc/radius-manager/web.env`。

連結遺失可用這個方式找回：`sudo radius-manager setup-url`

### 需要開放的連線

| 方向 | 連接埠 | 用途 |
|---|---|---|
| 控制器／AP → 這台 | UDP 1812 | RADIUS 認證 |
| 管理者 → 這台 | TCP 3333（安裝時可改） | 管理介面 |
| 這台 → 網域控制站 | TCP 88、389、445 | AD（有啟用才需要） |
| 這台 → ldap.google.com | TCP 636 | Google（有啟用才需要） |

## 初始化精靈

1. 單位名稱與時區
2. 管理者帳號（強密碼）
3. 管理介面的來源 IP 限制（預填目前連線的 IP）
4. RADIUS secret 與用戶端網段
5. AD 帳號驗證（可驗證連線，失敗可跳過）
6. Google 帳號驗證（可驗證連線，失敗可跳過）
7. RADIUS 伺服器憑證與名稱
8. SSID 規則與名單裝置的預設 VLAN

全部都可以之後到「系統設定 → 主機與驗證設定」變更，也可以在那裡重新驗證 AD 與 Google。

## 版本更新

選單最右方的「版本更新」頁：

- 開啟時自動比對目前版本與 GitHub 上最新的版本標籤（`vX.Y.Z`），列出新版本的說明（取自該版本的 `CHANGELOG.md`）
- **更新**：再次輸入管理者密碼後在背景執行；先備份目前的程式與全部設定，再用新版本的 `install.sh` 安裝（失敗會自動切回原本的版本）。FreeRADIUS 與網頁服務會重新啟動
- **回溯**：每次更新或回溯前的備份保留最近 10 份，可從頁面重新安裝備份中的程式（設定與資料維持現狀）
- **校驗**：下載 GitHub 上同一版本，逐一比對已安裝的程式檔（SHA-256）
- **匯出設定**：再次輸入密碼後下載 .tar.gz，內含金鑰與私鑰，請妥善保存
- 專案為 private 時，可在頁面產生唯讀的部署金鑰（deploy key）加到 GitHub；公開專案不需要

發行新版本：更新 `VERSION` 與 `CHANGELOG.md`（「## X.Y.Z (日期)」一段），提交後打上 `vX.Y.Z` 標籤並推送。

## 管理指令

```bash
sudo radius-manager setup-url     # 重新產生初始化連結
sudo radius-manager reset-admin   # 重設管理者密碼
sudo radius-manager clear-ip      # 被來源 IP 限制鎖在外面時
radius-manager version            # 目前版本
```

## 安全設計

- 網頁服務以無特權帳號 `radmgr` 執行並有 systemd 沙箱，碰不到 RADIUS 金鑰
- 需要 root 的操作透過佇列交給 `radius-manager-helper`，它會重新驗證所有輸入，不經過 shell，密碼不放命令列
- 初始化連結是一次性的，建立管理者後立即失效
- 登入失敗 5 次鎖定 5 分鐘，拒絕跨站 POST，管理介面走 HTTPS
- `auth_badpass` 與 `auth_goodpass` 一律關閉，避免 PAP／GTC 的明文密碼寫進 log


## 更新

重新執行安裝指令即可更新程式，設定與資料都會保留。設計細節與之後的網頁更新功能見 [docs/UPDATING.md](docs/UPDATING.md)。

## 解除安裝

```bash
sudo bash uninstall.sh --yes
```

會刪除所有設定與資料，並移除 FreeRADIUS 與 Samba，無法復原。

## 授權

[MIT](LICENSE)
