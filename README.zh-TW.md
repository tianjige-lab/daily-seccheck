# daily-seccheck

每天一次、**零模型**（不用任何 AI 服務）的資安巡檢腳本，Windows PowerShell 寫成。只檢查、不修補、不改設定；只報「新的」發現，沒有新東西就安靜。

由天機閣（Tianjige Lab）釋出，MIT 授權。

## 它檢查什麼

每一項都是可以單獨開關的模組（在 `config.json` 的 `modules` 打開或關閉）：

| 模組 | 做什麼 | 資料送到哪裡 |
|---|---|---|
| `osv` | 把 `package-lock.json`（本機的，或用 ssh 從主機抓回來的）裡的「套件名稱＋版本」拿去比對 [OSV](https://osv.dev)（含 GitHub Advisory 與 OSSF 惡意套件庫）。惡意套件一律報；一般弱點只報正式環境依賴、且達到你設的嚴重度。 | 只送套件名稱與版本給 `api.osv.dev` |
| `hosts` | 用 ssh 巡 **Debian／Ubuntu 系** Linux 主機（用 `dpkg`、`apt`、`unattended-upgrades`；其他發行版會得到空值並產生誤判，請不要開這個模組）：待安裝的安全更新、核心與待重開、OpenSSH 可升級、自動更新是否啟用、你指定的服務有沒有設開機自啟；有裝 Caddy 才會檢查 Caddy，沒裝就自然略過。 | 只在你的主機上執行唯讀指令 |
| `node` | 比對你列出的各台機器的 Node.js 版本與 nodejs.org 官方的最新安全版。 | 讀取 `nodejs.org/dist/index.json` |
| `router` | 比對路由器廠商公布的最新韌體版本與你目前跑的版本（版本號放在設定裡，自己維護）。 | 讀取你設定的網址 |
| `windowsUpdate` | 本機與你列出的遠端 Windows 機器「最後一次安裝更新距今幾天」超過門檻就報。 | 只在你的機器上執行 |
| `kev` | 美國 CISA「已知遭利用弱點」清單新增項目，用你的關鍵字比對。 | 讀取 `cisa.gov` 公開 JSON |
| `keyleak` | 掃近期新增／變動的文字檔，找金鑰樣式（GitHub／OpenAI 風格／Google／Slack／AWS／私鑰／JWT／Telegram bot）；拿現役金鑰的指紋比對，命中就升為 P0；並檢查機密資料夾的權限有沒有被放寬。**值盲**：只報路徑、種類與 8 碼指紋，金鑰本身從不印出、不寫檔。 | 不連網 |

## 安裝

需要 Windows PowerShell 5.1（或 PowerShell 7）、Node.js 18 以上（只有 `osv` 模組要）、`ssh`（只有 `hosts`、`osv` 遠端與遠端 Windows 要）。

```powershell
git clone <本專案網址> daily-seccheck
cd daily-seccheck
Copy-Item config.example.json config.json
notepad config.json    # 改成你自己的主機、路徑與關鍵字；不用的模組設 false
```

`config.example.json` 裡所有位址都是示意用的保留位址（`192.0.2.x`、`example.invalid`），請換成你自己的。**`config.json` 不要提交到版本控制**（`.gitignore` 已排除）。

首次部署先「播種」，把現有的發現全記為已知，避免第一天被一長串舊問題淹沒：

```powershell
.\daily-seccheck.ps1 -Seed
```

之後的每一天：

```powershell
.\daily-seccheck.ps1            # 有新發現才會寫告警檔
.\daily-seccheck.ps1 -DryRun    # 只印出會報什麼，什麼都不寫（不寫告警、基準、run.log，也不建立 state 資料夾）
```

## 排程（Windows 工作排程器）

```powershell
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\path\to\daily-seccheck\daily-seccheck.ps1"'
$trg = New-ScheduledTaskTrigger -Daily -At 07:40
Register-ScheduledTask -TaskName 'Daily Security Check' -Action $act -Trigger $trg -Description 'read-only security check'
```

提醒：`ssh` 要能不輸入密碼就連上（金鑰認證、`BatchMode=yes`）；排程用的帳號必須能讀到那把金鑰。
**第一次連線請先手動做一次**：用排程帳號、同一把金鑰，對設定裡的每一台主機各 `ssh` 一次，把 host key 接受進 `known_hosts`。腳本使用 `BatchMode=yes`，`known_hosts` 沒有該主機時會直接失敗；**請不要用 `StrictHostKeyChecking=no` 繞過**，那會讓中間人攻擊變得可行。

## 輸出

- `state/baseline.json`：已知發現的清單（用來去重）。已消失的發現會自動移出，之後復發會再報。
- `state/run.log`：每次一行，記錄發現數、新增數與失敗的檢查項（`-DryRun` 不會寫）。
- 有新發現時，在 `alertDirs` 列的每個資料夾各寫一份 `ALERT-seccheck-<日期時間>.md`。你可以把其中一個資料夾指到會被別的通知工具監看的位置。

## 安全性設計與限制

- **只讀**：不升級套件、不重開機、不改任何設定。`hosts` 模組在遠端只執行讀取指令。
- **值盲**：`keyleak` 不顯示、不記錄任何金鑰內容；告警只含檔案路徑、樣式種類與雜湊指紋。指紋比對用 SHA-256，只有「與現役金鑰完全相同」才會升為 P0。
- **誤報與漏報**：金鑰樣式是常見格式的啟發式規則，會有誤報（測試檔裡的假金鑰），也不可能涵蓋所有格式。已知誤報請用 baseline 接受。掃描只看近 `hoursBack` 小時內有變動的文字檔，單檔上限預設 1 MB，會略過 `node_modules`、`.git`、虛擬環境等目錄（要多排除哪些，用設定檔 `keyleak.excludeDirs`，或直接執行 `keyleak-scan.ps1` 時帶 `-ExcludeDirs`）。
- **私鑰判斷**：只有標題行（例如文件裡提到 PEM 格式）不算，必須帶有足夠長度的金鑰本文才算。
- **設定值先驗證再使用**：`config.json` 裡會被放進遠端指令的值（主機名稱、ssh 目標、服務名稱、遠端檔案路徑、遠端 Windows 的 node 路徑）都先過白名單檢查；不合格的項目會被略過並回報成 `config-invalid:...`，不會靜默帶過。ssh 目標不可以以 `-` 開頭，呼叫 ssh 時一律加 `--`。設定檔仍應只有管理者能改。
- **機密資料夾權限檢查用 SID**：以 Everyone（`S-1-1-0`）、內建 Users（`S-1-5-32-545`）、Authenticated Users（`S-1-5-11`）比對，不受 Windows 顯示語言影響；可用 `-DeniedSids` 調整。
- **不會替你修**：發現只是通知；怎麼處理、要不要輪替金鑰，由你決定。
- 腳本執行時會用到的外部網路：OSV、nodejs.org、cisa.gov，以及你自己設定的路由器網址與主機。其餘全在你的機器內。

## 測試

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test-keyleak-scan.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test-hardening.ps1
```

`test-hardening.ps1` 用一個假的 `ssh`（只記錄呼叫，不連任何機器）驗證：設定值的白名單檢查、ssh 的 `--` 與目標檢查、缺少 `hosts`／`remoteWindows` 鍵時不會多跑一輪空項目、`-DryRun` 什麼都不寫、`osv-scan.mjs` 的錯誤處理；每一項也都注入故障確認測試抓得到。

`test-keyleak-scan.ps1` 用執行時才組合出來的假金鑰（檔案裡沒有金鑰形字串），涵蓋：各樣式都會被抓到、乾淨檔不報、過期檔不掃、被排除的目錄不進、現役金鑰命中升 P0、值不會出現在輸出、權限被放寬會報、日期戳備份夾去重。並且對掃描器注入 8 種故障（不掃檔、忽略現役集合、洩漏值、掃到舊檔、不剪枝、關掉權限檢查、日期戳不去重、放寬私鑰判斷），每一種都必須被測試抓到，否則測試本身就算失敗。

## 維護

本專案的維護是盡力而為：歡迎回報問題與送修改，但不保證回覆或合併的時間。腳本在你自己的電腦上執行，不依賴我們的任何服務；即使本專案暫停更新，已安裝的版本仍可照常運作。

## 授權

MIT，見 `LICENSE`。
