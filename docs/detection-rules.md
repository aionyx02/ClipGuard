# ClipGuard 判斷準則

這份文件是 ClipGuard **偵測行為的規格**：什麼情況要攔截、提醒或放行，以及背後的理由。

- **改規則的人**：先改這份文件，再改程式碼和測試，三者要一致。
- **Review 的人（人或 agent）**：依「[Review 檢查清單](#9-review-檢查清單)」逐項核對 PR。程式行為跟這份文件不一樣時，要嘛是 bug，要嘛是文件要更新，PR 裡必須說明是哪一種。

> 文件中刻意不放完整的惡意指令範例，以免觸發防毒（Defender 會把含 ClickFix 範例的檔案隔離）。測試裡的樣本要在執行時用片段組合，網址一律用 `example.invalid`。

---

## 1. 設計原則

| # | 原則 | 具體含義 |
|---|---|---|
| P1 | **寧可漏擋，不可誤清** | 只有「確定是詐騙」才清空剪貼簿（Malicious）。不確定的情況只提醒（Suspicious），使用者的資料不會因誤判消失。 |
| P2 | **一次複製最多一則通知** | 通知會互相覆蓋（攔截通知帶有「點擊還原」），所以依優先順序只顯示一則；不同次複製之間也會節流，不顯示過期的通知。見 §2。 |
| P3 | **不留存剪貼簿內容** | 不寫檔、不記 log、不連網。被攔截的原文只存在記憶體裡，用於還原。 |
| P4 | **通知不顯示完整機密** | 一律遮罩，例如 `A12****789`；錢包地址連遮罩版都不顯示，見 §6。 |
| P5 | **有檢查碼就要驗** | 有檢查碼的格式（身分證、統編、信用卡、IBAN、各國身分證號、BTC 地址）必須通過驗證才算命中，用來壓低誤報。例外：韓國住民登錄番號 2020 年後的號碼檢查碼是隨機的，改成一定要有關鍵字（§5.6）。 |
| P6 | **沒有檢查碼的短格式要有上下文** | 只是 8 位數字這類格式，必須搭配關鍵字才算命中（例如統編、美國 SSN、日本個人番號）。國際電話沒有檢查碼，改成一定要以 `+` 開頭。 |
| P7 | **Core 是純邏輯** | 判斷都放在 `ClipGuard.Core`，不依賴 WinForms 或 Win32，每條規則都要有單元測試。 |

## 2. 處理流程與通知優先順序

```
剪貼簿變動（啟動時也會先跑一次）
  ├─ 只讀前 1 Mi 字（ClipboardLimits.MaxAnalyzedChars，見 §2.2）；還沒顯示的舊通知作廢（§2.1）
  ├─ 內容 = 使用者剛還原的文字 → 放行，狀態設為 Suspicious（入口仍提醒）
  ├─ ① 指令偵測        Malicious → 清空、存隔離區、紅色通知（點擊可還原）
  │                    Suspicious → 黃色提醒，不清空
  ├─ ② 機密偵測        只在 ① = None 時執行
  ├─ ③ 隱藏字元        只在 ① = None 且 ② 沒有命中時才通知
  ├─ ④ 錢包掉包        每次都會記錄；命中時通知，取代 ① 的提醒、②、③（① 清空時不通知）
  └─ 記下機密摘要      ① 沒有清空剪貼簿時，記下「種類＋遮罩＋剪貼簿序號」給 ⑥ 用（不記原文）
前景視窗切換 → ⑤ 執行入口守衛（依目前的剪貼簿狀態）
按下 Ctrl+V／Shift+Insert → ⑥ 貼上攔截（依機密摘要與設定，見 §5.3）
```

⑥ 不是通知，而是置頂的確認框，不參與下表的優先順序；只有在貼上流程失敗（切不回原視窗、寫不進剪貼簿）時才會跳一則 Warning 通知。ClipGuard 自己為了「貼遮罩版」暫時寫入的遮罩版、事後還原的原文，不會再跳機密通知。

| 優先 | 通知 | 等級 |
|---|---|---|
| 1 | 指令被攔截 | Error（紅） |
| 2 | 錢包掉包 | Error |
| 3 | 指令可疑 | Warning（黃） |
| 4 | 機密（個資、API key、登記的機密） | Warning |
| 5 | 隱藏字元 | Warning |

錢包掉包現在也會抓句子裡的地址（§6.2），所以可能和其他通知碰在同一次複製。它排在「指令被攔截」之後：攔截通知帶有「點擊還原」，而且剪貼簿已經清空，假地址也一起清掉了。它排在其他提醒之前：掉包代表電腦上很可能有正在執行的惡意程式，比「這段文字含機密或隱藏字元」更急。被蓋掉的只是通知，剪貼簿狀態（入口守衛用的 Suspicious）照常設定。

程式位置：`src/ClipGuard.App/TrayApp.cs`（`OnClipboardChanged`）、`src/ClipGuard.Core/ClipboardGuardState.cs`。

### 2.1 通知節流（#24 F18）

程式：`src/ClipGuard.Core/NotificationThrottle.cs`（決策，時間可注入）；`TrayApp.cs` 只負責顯示和計時。

Windows 會把通知排隊依序顯示，連續複製時，幾十秒後跳出的都是早就過期的通知。所以所有通知（包括執行入口守衛和貼上攔截的錯誤通知）都先經過節流：

```
送出通知
  ├─ 攔截通知（可還原）→ 立刻顯示
  ├─ 距上一則 ≥ 1 秒 → 立刻顯示
  │   └─ 上一則顯示不到 6 秒（可能還在畫面上或佇列裡）→ 先撤掉它再顯示
  └─ 其他 → 進等待區（只有一格，留最新的；等待中的 Error 不讓 Warning 蓋掉），到期再顯示
剪貼簿換了內容 → 等待區清空（講的是舊內容）
```

- **取代，不排隊**：撤掉舊通知的方法是把系統匣圖示移除再加回（`NIM_DELETE` + `NIM_ADD`），新通知才不會排在舊的後面。
- **攔截通知（P2）**：一律立刻顯示，不會因為剪貼簿換掉而作廢。顯示期間（6 秒）只有 Error 等級（例如剛攔截就打開 Win+R 的入口警告）能取代它；Warning 要等它顯示完，期間剪貼簿換掉就作廢。不管通知有沒有被取代，系統匣選單的「還原被清除的內容」都還能用。
- **點擊動作**：每次顯示都會覆蓋（攔截通知是「還原」，其他是無）。不在通知關閉時清掉，因為撤掉舊通知時，它的關閉訊息可能晚於新通知才到；`Restore` 自己會檢查還有沒有可還原的內容。
- 通知內文沒有加「是哪一次複製」：節流後最多晚 1 秒（或攔截通知的 6 秒）顯示，而且剪貼簿換掉就作廢，不會顯示別次複製的通知。

### 2.2 讀取上限（#24 F20）

複製時只讀剪貼簿的前 `ClipboardLimits.MaxAnalyzedChars` = **1,048,576 字**（1 Mi 個 UTF-16 字元，約 2 MB），直接從 `CF_UNICODETEXT` 的記憶體複製需要的那一段，不經過 WinForms／OLE（那條路會把整段複製好幾份，5 MB 的內容峰值約 250 MB；改完實測 5.4M 字的內容峰值約 82 MB，其中閒置時就有 50 MB）。

- **為什麼是 1 Mi 字**：不小於所有偵測器各自的上限，截斷不會讓偵測變弱。指令偵測縮完空白後最多看 256 Ki 字、4000 行（§3.0），截斷前還留了約 768 Ki 字給空白、空行這類不計入的填充；機密偵測的上限剛好等於這個值（1 Mi 字，§5.0），登記的機密 20,000 字（§5）。
- **這是唯一的讀取上限**：調高任何偵測器的長度上限時（例如 #22），不能超過它，超過的部分根本讀不到（`ClipboardLimitsTests` 會擋）。
- **隔離**：截斷過的內容被判為 Malicious 時，另外讀一次完整內容存進隔離區，還原時不會少一截；「使用者剛還原的文字」用讀進來的那段前綴比對。
- 截斷時不把代理對切成一半。

## 3. 指令偵測（ClickFix / FileFix）

程式：`src/ClipGuard.Core/CommandDetector.cs`、`CommandNormalizer.cs`。

### 3.0 比對前的處理（#19）

**長度**：不會因為總長度就整段跳過。

| 內容長度 | 分析範圍 |
|---|---|
| ≤ 4096 字 | 整段一起分析（訊號可以分散在不同行） |
| > 4096 字 | 先把同一行內超過 64 個的連續空白縮成 64 個空格（仍滿足「30 個以上空白接 `#`」），縮完 ≤ 4096 字就整段分析。否則分段分析，取最高等級：開頭 4096 字（涵蓋第一行和 Win+R 的 259 字上限），加上之後的每一行；比 4096 字長的行切成每次前進 2048 字的重疊片段，2048 字以內的指令不管在行內哪裡都會完整落在某一段。總共最多分析 256 KB、4000 行，超過的部分不分析，避免卡住 UI |

含 `.*` 的規則（LOLBin、誘餌註解）用 `RegexOptions.NonBacktracking`，同一個字重複很多次時不會變成 O(n²)。

**正規化**（`CommandNormalizer`，純函式）：規則比對的是正規化後的文字；原文另外保留給隔離區還原，不寫檔、不記 log。白話說明（§3.3）也用同一份正規化結果，只看前 4096 字。依序處理：

| 步驟 | 例子 |
|---|---|
| 拿掉看不見、可以把關鍵字拆開的字元：軟連字號 U+00AD、零寬字元 U+200B–200D、U+2060、U+FEFF、U+180E、韓文填充字元 U+115F、U+1160、U+3164、U+FFA0，以及 TAG 區塊 U+E0000–E007F（UTF-16 的代理字元對）。隱藏字元通知（§6.1）允許一般文字裡的軟連字號，所以拆開關鍵字的問題只能在這裡處理 | `pow<U+00AD>ershell` → `powershell` |
| dash 變體換成 `-`：U+2010–2015、U+2212、U+FE58、U+FE63、全形 U+FF0D | `–w hidden` → `-w hidden` |
| 去掉 cmd 的 `^` 跳脫；`^^` 變 `^`；行尾的 `^` 接下一行 | `m^s^h^t^a` → `mshta` |
| 代入 `set x=…`、`set "x=…"` 設定的 `%x%`，以及延遲展開（`cmd /v:on`）的 `!x!`（只代入一層；最多 16 個變數、64 次代入、值最長 1024 字）。沒設定過的 `!x!` 不動，句子裡的驚嘆號不受影響（#21） | `set x=…&& call %x%`、`call !a!!b!` |
| 展開固定的系統環境變數：`%SystemRoot%`、`%windir%`、`%SystemDrive%`、`%ComSpec%`、`%ProgramFiles%` 等，以及 PowerShell 的 `$env:windir` 寫法。不讀本機的真實環境變數 | `%ComSpec% /c` → `cmd /c` |
| 合併字中間的引號 | `"m"sh"ta"`、`ms""hta` → `mshta` |
| 已知程式（powershell、pwsh、mshta、cmd、certutil、bitsadmin、rundll32、regsvr32、msiexec、conhost、curl、wget，以及 #21 的 wscript、cscript、hh、cmstp、pcalua、odbcconf、installutil、ftp、explorer、net、net1）的完整路徑只留檔名，有沒有引號、`.exe` 都可以 | `"C:\…\System32\mshta.exe"` → `mshta` |

- 只縮短「已知程式」的路徑：其他路徑（例如 `C:\x\a.ps1`）保持原樣，因為 PowerShell 的參數判斷要用到它。新增規則用到的程式時要一起加進清單（`CommandNormalizer.KnownPrograms`）。
- 只有 `/` 的路徑（`github.com/powershell/powershell`）和網址（含 `://`）不算路徑，避免把網址當成指令。
- 單獨一行的完整路徑（例如只有 `C:\Windows\System32\mshta.exe`）跟只寫 `mshta.exe` 一樣判為 Suspicious，因為貼進 Win+R 就會執行。句子裡提到路徑則不算。

### 3.1 兩類訊號

**執行訊號**：這段文字會叫起可執行程式。

| 訊號 | 成立條件 |
|---|---|
| PowerShell | `powershell` / `pwsh`（可帶 `.exe`）出現在行首或分隔字元後，且後面接 `-x` 或 `/x` 參數、引號、`#`、`$`、`&`、括號、cmdlet 或別名（iwr、irm、iex、`Invoke-*`、`Start-*` 等）、腳本路徑或 `.ps1`。也可以單獨出現在管線後面，或後面只接 `-`（從標準輸入讀指令，#20 F5） |
| mshta | 後面接 URL、`vbscript:`、`javascript:`、`about:`，或 `.hta` 檔 |
| cmd | `cmd /c`、`cmd /k`，前面可以先接其他開關（`cmd /q /v:on /c`） |
| cmd 延遲展開（#21） | `cmd /v:on`、`cmd /v`（可以接在其他開關後面）。`!x!` 由正規化代入，組出來的指令照一般規則判斷 |
| 下載或執行用的 LOLBin | certutil 加 `-urlcache`、bitsadmin 加 `/transfer`、rundll32 加腳本或 URL、regsvr32 加 `/i:` 和 URL、msiexec 加 URL、conhost 加 `--headless` |
| #21 的 LOLBin | wscript / cscript 加腳本檔（`.vbs`、`.js`、`.wsf`…）或 `//e:`；hh 加 URL、UNC、`mk:@MSITStore:`、`its:` 或 `.chm`；cmstp 加 `.inf`；pcalua 加 `-a`；odbcconf 加 `/x` 或 `-x` 開關；InstallUtil 加 `.dll` / `.exe`；ftp 加 `-s:檔案` |
| 執行遠端分享上的檔案（#21） | `\\主機\分享\…` 加可執行的副檔名（exe、lnk、bat、cmd、dll、msi、hta、ps1、vbs、js、cpl、scr、search-ms…），而且在「下指令的位置」：行首、分隔字元後，或 start、explorer、call、rundll32、pcalua、cmd 等程式後面。`\\主機@SSL\DavWWWRoot\` 也一樣 |
| WebDAV 遠端資料夾（#21） | `\\主機@SSL\…`、`\\主機@埠號\…`、`\\主機\DavWWWRoot`，在下指令的位置，或接在 `net use`、`pushd` 後面 |
| 掛載網路磁碟後執行（#21） | `net use Z: \\主機\…`（或 `*`）之後，在下指令的位置執行 `Z:\…` 的可執行檔；`*` 時任何磁碟機代號都算 |
| Protocol handler（#21） | `search-ms:` / `search:` 帶 `query=`、`crumb=`、`displayname=` 等參數；`ms-msdt:` 後面接 `/x` 或 `-x` 參數 |
| 下載後交給 shell | curl/wget 的輸出 pipe 給 sh、bash 或 zsh |
| 下載後直接執行（#20） | 見下方說明。本身就是執行訊號：不寫程式名稱、貼進 PowerShell 視窗的寫法也算 |

「像在下指令」這個條件是為了排除一般句子（例如 `I use powershell every day`，#8）和網址路徑（`github.com/powershell/...`）。#21 的程式也一樣：只提到程式名稱的句子（`wscript and cscript are …`）、句子中間的 UNC 路徑（`檔案放在 \\fileserver\share\setup.exe`）都不算；單獨一行的 UNC 執行檔算，因為貼進 Win+R 就會執行（同 §3.0）。

**下載後直接執行**（`DownloadExecution.cs`）指的是下面任何一種寫法，只看正規化後的文字：

| 寫法 | 例子（片段） |
|---|---|
| 下載結果 pipe 給 iex、Invoke-Expression、powershell、pwsh、cmd、sh / bash / zsh。下載指令後面至少要有一個參數，避免把表格 `\| curl \| cmd \|` 當成指令 | `irm … \| iex`、`curl … \| cmd`、`curl … \| powershell -` |
| iex 直接包住下載 | `iex(iwr …)`、`iex ((New-Object Net.WebClient).DownloadString(…))`、`iex "& { $(irm …) }"` |
| 先存進變數，再 iex 那個變數 | `$c = iwr …` 加上 `iex $c` |
| `[ScriptBlock]::Create` 搭配任何下載 | `&([scriptblock]::Create((irm …)))` |
| 下載成檔案（`-OutFile`、`DownloadFile`、`curl -o`、`certutil -urlcache`、`bitsadmin /transfer`、`Start-BitsTransfer`）再啟動（`Start-Process`、`start`、`&`、在下指令的位置直接寫 `.exe` / `.bat` / `.msi`…） | `iwr … -OutFile a.exe; Start-Process a.exe` |

**詐騙訊號**：

| 訊號 | 強度 |
|---|---|
| 隱藏視窗：`-WindowStyle` 的任何前綴（`-w`、`-win`、`-WindowSt`…，W 開頭的參數只有它）、`-` 或 `/` 開頭（dash 變體由正規化處理），值是 `hidden`（或它的前綴 `h`、`hid`…）或數字 `1`（ProcessWindowStyle：Normal=0、Hidden=1、Minimized=2、Maximized=3），可加引號，也可以寫成 `-w:hidden`（#20 F3） | 強 |
| 下載後直接執行，而且來源**不在**官方安裝網站清單（見 §3.2，#20 F4） | 強 |
| `-enc` 系列參數加 16 字以上的 Base64 | 強 |
| 註解（`#` 之後）含 robot、captcha、verif、human、cloudflare、驗證、機器人、人機，或 #27 加的多語版本（見下方） | 強 |
| 勾選符號 ✅ ✔ ☑ | 強 |
| 30 個以上空白後接 `#`（把真正的指令擠出輸入框） | 強 |
| mshta 直接接遠端 URL | 強 |
| 從網路下載（iwr、irm、DownloadString、WebClient…） | **弱** |
| 把內容當程式碼執行（iex / Invoke-Expression） | **弱** |

**誘餌註解的多語版本**（#27，`CommandDetector.BaitCommentPattern`）：

| 語言 | 關鍵字 |
|---|---|
| 簡中 | 验证、机器人、人机 |
| 日 | ロボット、人間であること、認証 ID（「認証」後面要接 ID） |
| 韓 | 로봇、사람인지、인증 ID（「인증」後面要接 ID） |
| 葡、法 | robô（不含 robot）、vérif（有重音） |
| 俄 | робот、капч、верифик |
| 越 | người máy、xác minh |
| 西、德、義、印尼、土耳其 | 已經被 robot（roboter、robotem）、verif（verificación、Verifizierung、verifikasi）、human（humano、humain）涵蓋 |

- 只收 ClickFix 誘餌會用、一般註解很少用的字。日文的「認証」、韓文的「인증」單獨出現太常見（認証トークン、인증서＝憑證），所以要後面接 ID 才算，例如假驗證畫面的「認証 ID: 4821」。
- 跟原本一樣只看 `#` 後面，而且要有執行訊號才會變成 Malicious（P1）；單獨一句「私はロボットではありません」不處理。測試：`CommandBaitTests`，每個語言都有該命中和不該命中的註解。

### 3.2 判定表

| 執行訊號 | 強詐騙訊號 | 結果 | 動作 |
|---|---|---|---|
| 無 | 不論 | None | 不處理 |
| 有 | 無（可以有弱訊號） | **Suspicious** | 提醒，不清空 |
| 有 | 有 | **Malicious** | 清空並隔離，可還原 |

**下載後直接執行與官方安裝網站清單**（#20 F4、F17）：「下載後直接執行」是 ClickFix 的核心動作，所以本身就判 Malicious，不必等隱藏視窗這類訊號。但官方安裝指令也長這樣，為了不清掉合法內容（P1），來源全部是下表的網站時只判 Suspicious。

| 網站（含子網域） | 用途 |
|---|---|
| astral.sh | uv、ruff |
| bun.sh | Bun |
| get.scoop.sh、scoop.sh | Scoop |
| deno.land | Deno |
| sh.rustup.rs | rustup |
| get.pnpm.io | pnpm |
| community.chocolatey.org | Chocolatey |
| claude.ai | Claude Code |
| ollama.com | Ollama |
| dot.net | dotnet-install |
| aka.ms | 微軟官方短網址（例如 install-powershell） |

- **收錄條件**：官方文件要使用者貼上「下載後執行」的指令，而且網域由專案本身控制。raw.githubusercontent.com 這類任何人都能放檔案的網站不收，所以 Homebrew、nvm 的安裝指令會被攔截（可以點通知還原）。
- **比對主機名稱，不是子字串**：主機必須等於清單裡的網站，或是它的子網域。`astral.sh.example.invalid`、`notastral.sh` 都不算；網址裡的帳號欄位（`https://astral.sh@主機/`）以真正的主機為準；主機在反斜線處截斷；不是純 ASCII 的主機一律不算。
- **看哪些行**：下載、執行（iex、ScriptBlock）、設定變數（`$u = …`、`set u=…`）的那幾行裡，每一個主機都要在清單裡；找不到任何主機（例如 `irm $u | iex` 而 `$u` 不在文字裡）就不算。其他行（例如 README 附的 GitHub 連結）不看，官方指令連同說明一起複製時不會被升級。
- **拼出來的網址不可信**：文字裡有字串串接（`'…'+'…'`）、`-join`、`-f`、`-replace`、`[char]`、反引號、`FromBase64String` 時，不套用清單。
- **清單只拿掉「下載後直接執行」這一個強訊號**：官方網站的指令如果還有隱藏視窗、誘餌註解等強訊號，一樣判 Malicious。
- 「從網路下載」「iex」單獨出現仍只算弱訊號。scoop 不寫程式名稱的寫法（只有下載＋iex）現在跟 uv、bun 一樣判 Suspicious（F17：原本完全不提醒）。

### 3.3 白話說明（`CommandExplainer.cs`）
- 指令被判為 Suspicious 或 Malicious 時，會產生一段 zh-TW 的白話說明，例如「從 example.invalid 下載並執行」「隱藏視窗」「藏了一段編碼過的指令」。
- #21 的訊號跟偵測共用同一組樣式，各有一句說明，例如「用 wscript／cscript 執行腳本檔」「執行 example.invalid 網路分享上的檔案」「連到 example.invalid 的 WebDAV 遠端資料夾」「用 ms-msdt: 呼叫疑難排解工具（Follina 漏洞的手法）」。
- 下載來源的主機用跟官方網站清單一樣的方式取出（帳號欄位以真正的主機為準），最多列 3 個。
- `-enc` 系列參數會用 UTF-16LE 解碼並顯示；解出來不是合理文字時就不顯示。
- 通知內容最多 255 字元，標題最多 63 字元，超過的部分以 `…` 截斷。

### 3.4 已知缺口（尚未修正）
| 缺口 | Issue |
|---|---|
| 超過 4096 字時，訊號分散在不同行而且不在開頭 4096 字內（例如第 1 行的指令配上第 200 行的誘餌註解）時，各行分開看，可能只判 Suspicious；同一行裡用超過 2048 個非空白字元把執行訊號和詐騙訊號隔開時也一樣；超過 256 KB / 4000 行的部分不分析 | #19 的取捨 |
| 剪貼簿超過 1 Mi 字的部分根本不讀（§2.2），所以先塞超過 1 Mi 字的空白再接指令也看不到（縮空白是在讀進來之後才做） | #24 的取捨 |
| cmd 子字串展開（`%x:~0,3%`、`!x:~0,3!`）、`set /p`、多層變數代入、`for` 迴圈組字、PowerShell 的變數或字串串接組出程式名稱（`& ('ms'+'hta')`）、反引號跳脫、全形英文字母 | 尚未開 issue |
| 官方網站清單以外的合法安裝指令（Homebrew、nvm 等放在 raw.githubusercontent.com 的）會被攔截，要點通知還原 | #20 的取捨（F17） |
| 官方網站清單只認得常見的字串拼接寫法；用 `[string]::Concat`、`.Insert()`、環境變數等其他方式組出清單外的網址，而且同一行放清單內網址當幌子時，可能只判 Suspicious | #20 的取捨 |
| 「下載後直接執行」沒涵蓋的寫法：msiexec 直接裝遠端套件、`Invoke-Command`、`.Invoke()`、下載後用相對路徑以外的方式啟動（例如 `rundll32` 載入剛下載的 DLL）仍只提醒 | 尚未開 issue |
| `setlocal enabledelayedexpansion`（批次檔裡的延遲展開）本身不算訊號；`!x!` 仍會代入 | #21 的取捨 |
| 遠端檔案只在「下指令的位置」才算：`pushd \\主機\…` 之後用相對路徑執行、`net use` 的磁碟代號前面先寫其他開關（`net use /persistent:no Z: …`）沒有涵蓋 | #21 的取捨 |
| #21 的 LOLBin、UNC/WebDAV、`search-ms:`、`ms-msdt:` 單獨出現只提醒（P1），要搭配強詐騙訊號才攔截 | #21 的取捨 |

## 4. 執行入口守衛

程式：`src/ClipGuard.Core/ExecutionEntryGuard.cs`、`src/ClipGuard.App/ForegroundWatcher.cs`（`EVENT_SYSTEM_FOREGROUND`）。

| 入口 | 判斷（Windows 11 zh-TW 實測） |
|---|---|
| Win+R | class `#32770`，行程 explorer，標題「執行」或 Run |
| 檔案總管 | class `CabinetWClass` / `ExploreWClass`，行程 explorer |
| 檔案對話框 | class `#32770`，標題是「開啟」、Open、File Upload 等清單中的其中一個 |
| 終端機 | Windows Terminal、conhost、WezTerm 等的 class 或行程名稱 |

| 剪貼簿狀態 | 結果 |
|---|---|
| 剛攔截（隔離中）或 Malicious | 紅色：「小心！你剛打開了…」 |
| Suspicious（包含使用者還原的指令） | 黃色提醒 |
| 其他 | 不提醒 |

- 同一個視窗加上同一份剪貼簿內容，只提醒一次（`EntryWarningGate`）。
- 檔案總管只看前景視窗，不偵測網址列焦點。原因是 XAML 網址列的焦點 class 跟檔案清單分不出來，而且等使用者按 Ctrl+L 才提醒就太晚了。

## 5. 機密偵測

程式：`src/ClipGuard.Core/SecretDetector.cs`、`SecretRules.cs`、`SecretTextNormalizer.cs`、`Checksums.cs`、`PiiFormats.cs`、`SecretMasker.cs`、`SecretPacks.cs`；規則檔 `rules/*.json`（§5.4）。個資分成通用包和國家包（#27，§5.6）。

API key 分三層（#26）：

| 層 | 規則 | 位置 |
|---|---|---|
| 1. 已知格式 | 手寫的前綴規則（GitHub、sk-、AWS、Stripe、JWT、PEM…），加上從 gitleaks 轉換的 198 條服務格式 | `rules/api-keys.json`、`rules/gitleaks.json` |
| 2. 上下文＋亂度 | 值前面有像金鑰的名稱（`api_key=`、`"token": `、`Authorization: Bearer`），而且值夠長、夠亂 | `rules/context.json`，§5.5 |
| 3. 自行登記 | 前兩層都抓不到的，使用者自己登記（HMAC） | §5.1 |

### 5.0 比對前的處理（#22）

**正規化**（`SecretTextNormalizer`）：規則比對的是正規化後的文字，每個字都記得來自原文哪裡，結果的位置一律換回原文（貼遮罩版會把原文那一整段換掉，包括中間的零寬字元）。遮罩字串用正規化後的值，所以全形號碼的遮罩是半形的 `A12****789`。

| 步驟 | 例子 |
|---|---|
| 逐字 NFKC：全形英數字、全形標點、全形空白變半形 | `Ａ１２３４５６７８９` → `A123456789` |
| dash 變體（U+2010–2015、U+2212、U+FE58）換成 `-` | `A123–456–789` |
| 刪掉零寬字元 U+200B–200D、U+2060、U+FEFF 和軟連字號 U+00AD | `A123​456789` |

**號碼裡的分隔符號**：數字之間可以有**單一個**空白、`.`、`-` 或一個換行（`\r\n` 也算一個）。為了不把不相干的數字（日期清單、表格、IP、版本號）湊成機密，各類型另有限制：

| 類型 | 限制 |
|---|---|
| 身分證、居留證 | 分隔符號最多 3 個（`A 123 456 789`、`A12345-6789`、中間換行都可以） |
| 信用卡 | 先切出「用分隔符號接起來的數字組」，再找連續幾組合起來 13–19 碼的。有分組時只接受 4-4-4-4（最後一組 1–4 碼）、Amex 4-6-5、Diners 4-6-4，而且分隔符號要一致（換行可以取代任何一種，例如卡號折行）。沒分組的號碼中間不能換行 |
| 手機 | 只接受固定的分組：`0912-345-678`、`0912-345678`、`(09)1234-5678`、`(09)12-345-678` |
| 統編 | 不允許分隔符號 |
| IBAN（#27） | 只接受每 4 碼一個空白（`DE89 3704 0044 …`）或完全不分隔；要大寫 |
| 國際電話（#27） | `+` 後面的數字組之間可以有一個空白、`.` 或 `-`，區碼可以加括號（`+1 (202) 555-0123`、`+44 (0)20 …`）；不接受換行 |
| 中國身分證、SSN、個人番號、住民登錄番號（#27） | 只接受各自的固定分段（`110105 19491231 002X`、`078-05-1120`、`1234 5678 9018`、`900101-1234567`），SSN 的兩個分隔符號要一樣 |

**長度**：不會因為總長度就整段跳過。

| 內容長度 | 分析範圍 |
|---|---|
| ≤ 1,048,576 字（`MaxScanLength`，等於系統匣讀剪貼簿的上限） | 整段分析 |
| 更長（只會發生在直接呼叫 Core 時） | 開頭和結尾各 524,288 字，中間不分析。機密常在頭尾（.env、log 最後幾行） |

分析時切成每段 64K 字、往後多看 8K 字、往前多看 64 字（上下文關鍵字最遠 32 字加上關鍵字本身 24 字）的重疊片段（`SegmentStep`、`Overlap`），結果只算在起點所在的那一段，所以短於 8K 字的機密（JWT 的上限也在這之內）一定完整落在某一段裡，不會被切斷或重複。合併重疊結果是線性時間，滿滿都是號碼的內容也不會變成 O(n²)。所有包都開時，1 Mi 字的最壞情況（每 11 字一個身分證、每 14 字一個「統編＋號碼」）C# 約 0.15 秒、插件約 0.13 秒（§5.6）。

### 規則一覽

| 類型 | 規則 | 驗證 |
|---|---|---|
| 身分證、居留證 | 1 個英文字母加 9 位數字；第 2 碼 1、2 是身分證，8、9 是新式居留證，A–D 是舊式居留證。前後不能緊鄰英數字 | 檢查碼 |
| 統一編號 | 8 位數字，**前面 20 字內**要出現統一編號、統一編、統編、營利事業、稅籍、VAT、Tax ID、UBN 等關鍵字（上下文關鍵字，§5.4；#27 起可以隔一個換行，`vat` 不會比到 private） | 權重 1,2,1,2,1,2,4,1，總和要能被 **5** 整除；第 7 碼是 7 時有特例（依財政部 110-12-22 公告的新規則） |
| 信用卡 | 13–19 碼，分組方式見 §5.0，而且要符合發卡機構的前綴和長度 | Luhn |
| 手機 | `09` 加 8 碼；`+886 9…` 或沒有加號的 `886 9…`（`+886 0912…` 多寫的 0 也接受）；`(09)` 加 8 碼。市話（`(02)2555-6666`）不偵測：沒有檢查碼，8 碼數字太常見 | 沒有檢查碼 |
| 其他國家的格式、IBAN、國際電話（#27） | 見 §5.6 | 見 §5.6 |
| API key（第 1 層，手寫） | 前綴比對：GitHub（`gh?_`、`github_pat_`）、`sk-ant-`、`sk-`、Stripe、AWS（`AKIA` / `ASIA`）、Slack、Google、GitLab、npm、PEM 私鑰標頭。前後不能緊鄰同類字元 | 只比對前綴和長度 |
| API key（第 1 層，gitleaks） | 198 條服務專屬格式（Shopify、DigitalOcean、Twilio、Postman…），部分要求前面有服務名稱（`adafruit … = <值>`） | 依各規則：固定前綴、長度、gitleaks 的亂度門檻與 allowlist |
| JWT | `eyJ…` 開頭、三段 base64url（header ≤ 512、payload ≤ 6144、signature ≤ 1024 字，signature 可以是空的）。結尾可以接句點；五段的 JWE 不算 | header 要能解成 JSON 物件，而且有字串型別的 `alg` |
| 疑似金鑰或密碼、Authorization 權杖（第 2 層） | 見 §5.5 | 長度、亂度、排除佔位字 |

- JWT 歸在 API key 類（`SecretKind.ApiKey`，標籤「JWT」），遮罩成 `eyJ********xyz`（P4）。
- API key 類規則檔的命中都是 `SecretKind.ApiKey`，通知格式跟以前一樣是「標籤 遮罩」：有固定前綴的保留前綴（`shpat_********3f1`、`ghp_********xyz`），沒有前綴的只留最後 3 碼（`********x7Q`）。PEM 只顯示標頭，貼遮罩版時一路遮到 END 行。
- 重疊時的優先順序就是規則的順序：`api-keys.json`（10）→ `gitleaks.json`（20）→ `context.json`（30）→ 國家包（40，依檔名）→ 通用包（50）。同一把 key 被手寫規則和 gitleaks 同時抓到時，標籤用手寫的；`+886 9…` 同時是台灣手機和國際電話時，用台灣手機。#27 之前個資內部的順序是身分證 → 卡號 → 統編 → 手機，現在是身分證 → 統編 → 手機 → 卡號，這幾種實際上不會重疊（數字邊界和分組都不同），所以結果不變。
- 統編要求關鍵字的原因：改成「能被 5 整除」之後，隨機的 8 位數字約有 1/5 會通過檢查碼，日期和訂單號碼都會誤報（P6）。所以**沒有關鍵字的統編刻意不偵測**（#22 F13），README 的已知限制也有寫。
- 掃描上限（`SecretDetector.MaxScanLength`）不能超過剪貼簿的讀取上限（§2.2）。

### 5.1 登記的機密（`RegisteredSecretStore.cs`、`DpapiKeyProtector.cs`）
- 長度限制 6–256 字元，標籤最多 40 字。
- 只存 `(id, label, length, HMAC-SHA256, createdAt)`，路徑是 `%LOCALAPPDATA%\ClipGuard\secrets.json`。
- HMAC 金鑰是 32 bytes 的亂數，用 DPAPI（CurrentUser）保護，存在 `key.bin`。金鑰解不開時直接報錯，**不會**自動重建。
- 比對方式：依每一種登記過的長度，對內容做滑動視窗算 HMAC，再用 `FixedTimeEquals` 比對。最多掃前 20,000 字。
- **禁止**改用單純的 SHA-256。身分證、手機這類資料只有約 1e8–1e9 種組合，可以被暴力反推。
- **登記對話框**（`SecretRegistration.cs` 檢查、`SecretGuard.cs` 的 `RegisterSecretForm`）：機密空白、長度不在 6–256、確認欄空白、兩次不一樣、重複登記或寫檔失敗時，對話框不關，錯誤顯示在欄位旁（ErrorProvider）和按鈕上方的紅字，焦點留在出錯的欄位（不一樣時清空確認欄）。標籤可以留空（存成「未命名」）。錯誤訊息只說原因，不含輸入的內容。
- **無障礙**：三個輸入框都有 AccessibleName／AccessibleDescription；標籤帶 Alt 快速鍵（`&L`、`&S`、`&C`），TabIndex 緊接在輸入框前面；出錯時把錯誤寫進該欄的 AccessibleDescription 並發出 UIA 通知。跟確認框一樣，沒按 Alt 的單一字母不會觸發快速鍵。
- 以前寫入失敗（太短、重複）會先關掉對話框、跳一個沒有 owner 的訊息框再重開；訊息框可能落在別的視窗後面，看起來像對話框自己消失（#24 黑箱測試時遇過兩次）。現在所有錯誤都在對話框裡顯示，成功的訊息框以對話框為 owner。

### 5.2 已知缺口
| 缺口 | Issue |
|---|---|
| 超過 1 Mi 字時，中間那段不分析（只分析頭尾）；長於 8K 字的 JWT、JWE（五段）不偵測 | #22 的取捨 |
| 沒有關鍵字的統編刻意不偵測（P6，見上） | #22 F13，刻意的 |
| 兩個以上連續分隔符號（`A12345  6789`）、分隔符號超過上限、不在上述分組裡的卡號或手機寫法（例如 `09-1234-5678`、`41 11 11…`） | #22 的取捨 |
| 號碼前面緊貼著零寬字元和英數字時（`X​A123456789`），零寬字元刪掉後會黏在一起，不算命中 | #22 的取捨 |
| 登記的機密仍只掃前 20,000 字，也沒有正規化（比對的是 HMAC，全形版本是另一個字串） | 尚未開 issue |
| 沒有固定前綴、前面也沒有金鑰名稱的 key（例如一行裡只有一串亂碼）不偵測；名稱是中文（`金鑰：…`、`密碼=…`）也不算（§5.5） | #26 的取捨 |
| 第 2 層的值不能有空白、引號、`$`、`&`、括號，所以含這些字元的密碼抓不到；短於 16 字、亂度不夠（例如 `password=hunter2`、由英文單字組成的密碼）、32 字以下又沒有數字的也不算 | #26 的取捨 |
| `curl -u 帳號:密碼`、只看檔名的規則（`.p12`、Terraform、NuGet 設定）、Kubernetes Secret YAML 沒有收（§5.4 的略過清單） | #26 的取捨 |
| 長於 8K 字的機密（`Overlap`）可能被分段切斷，跟 JWT 一樣 | #22、#26 的取捨 |
| 個資只有 §5.6 的國家；IBAN 要大寫；國際電話沒有 `+` 就不算，後面緊接著另一組數字（`+1 202 555 0123 4`）時整段被當成太長而漏掉；IBAN 後面空一格接 4 個大寫英數字時也一樣 | #27 的取捨 |
| 沒有檢查碼的國家格式（SSN、住民登錄番號）和 12 位數的個人番號，前面沒有關鍵字就不偵測；關鍵字不限同一行，可能把上一行的「SSN」算進來 | #27 的取捨（P6） |
| 中國的 15 碼舊身分證、日本的法人番號、韓國的外國人登錄番號以外的證件不偵測 | #27 的取捨 |
| 貼上攔截預設只管**登記的機密**；個資與 API key 要自己在系統匣打開才會攔（取捨見 §5.3） | #25 |
| 貼上攔截攔不到右鍵選單的「貼上」、拖放、程式自己讀剪貼簿，以及系統管理員權限的視窗 | #25 |

### 5.3 貼上攔截（嚴格模式）

程式：`src/ClipGuard.Core/PasteGuard.cs`（決策、遮罩）、`PasteGuardSettingsStore.cs`；`src/ClipGuard.App/PasteInterceptor.cs`、`KeyboardPasteHook.cs`、`PasteConfirmForm.cs`。

只在複製時通知不夠：Windows 會把通知排隊，使用者手快 Ctrl+V 再按 Enter，機密就送出了。所以剪貼簿含機密時，要在**貼上當下**擋住。

```
複製 → 記下機密摘要（種類＋遮罩＋剪貼簿序號，不記原文）
按下 Ctrl+V／Ctrl+Shift+V／Shift+Insert（低階鍵盤 hook）
  ├─ 目標是 ClipGuard 自己、在允許清單內 → 放行
  ├─ 剪貼簿序號跟摘要不同（剛複製、還沒分析）→ 先擋，分析完再決定攔或照原樣送回
  ├─ PasteGuard.Decide = Allow → 放行
  └─ Intercept → 吞掉按鍵，跳置頂確認框並搶焦點
       Enter／Esc = 取消 │ 貼遮罩版（Alt+M）│ 貼原文（只能點或 Alt+O）
```

| 剪貼簿裡的機密 | 預設 | 可在系統匣「貼上前確認」切換 |
|---|---|---|
| 登記的機密 | **攔截** | 「攔截已登記的機密」 |
| 個資、API key | 不攔截（只有複製時的通知） | 「也攔截個資與 API key」 |

- **預設只攔登記的機密**：使用者主動登記的才確定是高價值機密；電話、統編常常是故意要貼給別人的，每次都要確認會讓人把功能關掉。
- **允許清單**：內建 1Password、KeePass、KeePassXC、Bitwarden、Dashlane、Enpass、Keeper、RoboForm、NordPass、Proton Pass、LastPass、Windows 認證視窗（`CredentialUIBroker`、`consent`、class `Credential Dialog Xaml Host`），以及 ClipGuard 自己的視窗。使用者可以再加程式（比對行程名稱，不分大小寫、可帶 `.exe` 或路徑，必須完全相同，不是包含）。查不到行程名稱時不放行。
- **確認框的預設是「取消」**：Enter 和 Esc 都不貼任何東西、也不動剪貼簿。桌面版的「貼遮罩版」要暫時換掉剪貼簿再對別的程式送按鍵，比較容易出錯（例如焦點跑掉），所以誤按的 Enter 只做零副作用的事。這跟插件不同（插件的 Enter 是貼遮罩版，見 §7）。
- **「貼原文」不在 Tab 順序裡**，Enter 永遠按不到；沒按 Alt 的單一字母也不會觸發按鈕，使用者繼續打字不會誤選。
- **確認框還沒做決定時**，hook 只吞掉送往**原本要貼上的那個視窗**（比對最上層視窗 GA_ROOT）的 Enter，避免在確認框搶到焦點前的空檔按下「送出」。其他程式的 Enter 照常，使用者沒注意到確認框也不會整台電腦的 Enter 失靈（`PasteGuard.ShouldSwallowEnter`）。確認框開著時，其他視窗的貼上照一般規則判斷：要攔的一樣擋下（不開第二個確認框），不用攔的照常貼上。
- **逾時**：確認框 60 秒沒有回應就自動取消（結果同「取消」，焦點切回目標）；等待狀態本身也有同樣的上限，任何路徑（包括剛複製就貼上的那條）都不會一直卡著。
- **貼遮罩版**：遮罩版把每筆機密換成通知裡的遮罩字串；登記的機密換成固定的 `********`（不帶標籤、不透露長度）；PEM 私鑰從標頭一路遮到 END 行。流程是暫時把剪貼簿換成遮罩版 → 切回原視窗 → 送出帶標記的貼上 → 600 ms 後換回原內容。等待期間使用者又複製了別的東西，就不換回。兩次寫入都標記為不收進剪貼簿歷程記錄（Win+V）。還原時只保留文字類格式（純文字、RTF、HTML、CSV）。
- **重入**：自己送的按鍵帶 `dwExtraInfo` 標記，hook 直接放行；自己寫入的遮罩版與還原的原文，3 秒內出現在剪貼簿都不會再跳機密通知。
- **hook 的安全**：設定不可能攔截任何東西時（預設設定又沒有登記機密）根本不裝 hook。回呼只讀欄位、做純邏輯判斷，對話框一律排到之後；回呼出錯就放行，不能讓鍵盤失靈；結束程式時先拔 hook。不記錄任何按鍵。
- **設定檔**：`%LOCALAPPDATA%\ClipGuard\paste-guard.json`，只有兩個開關和允許清單（最多 100 個名稱），不含機密。沒改過設定不會建立檔案；檔案損毀時用預設值並提醒。

已知限制：

| 限制 | 原因 |
|---|---|
| 右鍵選單的「貼上」、拖放、程式自己讀剪貼簿（例如按鈕觸發）攔不到 | 只 hook 鍵盤；這些路徑不經過按鍵 |
| 系統管理員權限的視窗攔不到 | UIPI：一般權限的 hook 收不到送往較高權限視窗的按鍵，也無法對它送按鍵 |
| 防毒軟體可能把低階鍵盤 hook 視為可疑 | 鍵盤側錄程式也用同一個 API；所以只在需要時才安裝 |
| 貼遮罩版要等 600 ms 才換回原文，極慢的程式可能讀到原文或還沒讀 | 沒有「目標已讀完剪貼簿」的通知可等 |
| 確認框開著時，送往原目標視窗的 Enter 會被吞掉（最多 60 秒） | 刻意的：決定之前不讓 Enter 在那個程式送出任何東西 |
| 複製後約 50 ms 內按 Ctrl+V，危險指令（Malicious）仍會被貼出去；約 150 ms 後剪貼簿已清空（#24 F21 實測） | 指令攔截靠的是複製後清空剪貼簿，不是貼上攔截；WM_CLIPBOARDUPDATE 處理完之前，目標程式已經讀到內容。一般人複製後不會這麼快貼上，所以只記錄 |

### 5.4 共用規則檔（`rules/*.json`，#26）

桌面版和插件讀**同一份**規則：API key 類的規則（#26），以及 #27 起的個資包（`rules/pii-<包>.json`，§5.6）。

```
rules/*.json ──(內嵌資源)──────────────────> C# SecretRules（啟動時編譯一次）
      │
      └─ node tools/build-extension-rules.mjs ─> extension/lib/rules.generated.js ─> rules.js
gitleaks.toml ─ node tools/convert-gitleaks.mjs ─> rules/gitleaks.json（commit 進 repo）
```

- **桌面版**：`ClipGuard.Core.csproj` 把 `rules/*.json` 內嵌進組件，執行時不讀檔、不連網（P3）。
- **插件**：執行時讀不到 `extension/` 外面的檔案，所以用 `tools/build-extension-rules.mjs` 把規則複製成 `extension/lib/rules.generated.js`（commit 進 repo）。`extension/test/rules.test.js` 會重新產生一次跟檔案比對，忘了執行就會失敗。
- **gitleaks**：toml 先另外下載（`gh api`），再用 `tools/convert-gitleaks.mjs <toml> <版本> <commit>` 轉換；執行時從不連網。授權見 `THIRD_PARTY_NOTICES.md`。目前是 v8.30.1（commit `5f6ec56`）。

**檔案格式**（`format: 1`）：

| 欄位 | 說明 |
|---|---|
| `name`、`priority` | 檔案依 `priority` 由小到大排（同值依檔名），前面的規則在重疊時優先。目前 api-keys 10、gitleaks 20、context 30、國家包 40、通用個資包 50 |
| `pack`（#27） | 檔案層級：`universal`（沒寫就是這個，一律開啟）或兩個大寫字母的國家代碼（`TW`、`US`…），見 §5.6 |
| `exclude`、`stopwords`（檔案層級） | 套用到檔案裡每一條規則（gitleaks 的全域 allowlist 就放這裡） |
| `skipped` | 只有 gitleaks.json 有：沒收的規則和原因（產生的，不要手改） |
| `rules[].id` | 所有檔案裡不能重複。gitleaks 的加 `gitleaks.` 前綴 |
| `kind` | `api-key`、`national-id`、`resident-certificate`、`business-id`、`credit-card`、`mobile-phone`、`phone-number`、`bank-account`，對應 `SecretKind` 的同名值；插件結果的 `type` 就是這個字串（#27 以前是 `tw-id`、`ubn`、`tw-mobile`）。新增時 C# 的 `ReadRule` 和 JS 的 `KINDS` 兩邊一起加 |
| `label` | 通知裡顯示的名稱 |
| `regex`、`ignoreCase` | 語法限制見下方 |
| `finder`（#27） | 取代 `regex`：regex 寫不出來的格式用程式寫的候選產生器，兩邊各實作一次（`PiiFormats.Finder`、`pii.js` 的 `FINDERS`）。目前只有 `card-groups`（信用卡分組，§5.0：要在幾組數字裡挑第一個 Luhn 對的）。`regex` 和 `finder` 一定要有其中一個 |
| `secretGroup` | 機密是第幾個群組；沒寫就是第一個有比對到、不是空字串的群組，沒有群組就是整段（同 gitleaks）。結果的位置、遮罩、貼遮罩版都只針對這一段 |
| `keywords` | 小寫。文字轉小寫後至少出現一個才跑 regex（同 gitleaks 的預先篩選，是效能的關鍵）。沒寫表示一律跑 |
| `notPrecededBy`、`notFollowedBy` | 取代 lookaround：前一個字元符合 `notPrecededBy`（單一字元的類別）或比對結果後面接著 `notFollowedBy` 時不算 |
| `minLength`、`maxLength` | 機密的長度 |
| `entropy` | 數字（gitleaks 的固定門檻），或 `{hex, base36, base64}` 各一組 `[a, b, cap]`（§5.5）。亂度 ≤ 門檻就不算 |
| `digitRequiredBelow` | 機密短於這個長度時一定要有數字 |
| `rejectSequential` | 一半以上的相鄰字元相同或連號時不算（`aaaa`、`0123456789abcdef`） |
| `exclude` | `[{regex, target, ignoreCase}]`，符合就不算。`target`：`secret`（預設）、`match`（整段比對結果）、`line`（所在的那一行）、`key`（群組 1 往前延伸到整個識別字，給金鑰名稱用）。`ignoreCase` 表示先把目標轉小寫，regex 要寫小寫 |
| `stopwords` | 機密（轉小寫）包含其中一個就不算（同 gitleaks） |
| `validate` | 額外的驗證，兩邊各實作一次（`PiiFormats.Validator`、`rules.js`／`pii.js` 的 `VALIDATORS`）：`jwt-header`、`tw-id`（含分隔符號最多 3 個）、`tw-ubn`、`iban`、`e164`、`cn-id`、`jp-my-number`、`hk-id`、`sg-nric`、`us-ssn`（含分隔符號一致）。驗證收到的是含分隔符號的字串，自己去掉 |
| `context`（#27） | `{keywords, before, after}`：機密前面 `before` 字內（關鍵字的結尾）或後面 `after` 字內（關鍵字的開頭）要出現其中一個關鍵字。比對的是**正規化後的文字**，不是 ASCII 版本，所以 `統編`、`マイナンバー`、`주민등록번호` 可以直接寫；英文字母不分大小寫（只轉 A–Z，長度不變），開頭或結尾是英文字母的關鍵字不能緊貼著其他英文字母（`vat` 不比 private、`ssn` 不比 Assn）。關鍵字要小寫、1–24 字，`before`、`after` 0–32 而且不能都是 0（要落在每段往前多看的 64 字內）。整段文字裡沒有任何關鍵字時直接跳過這條規則 |
| `mask` | `{keepStart, keepEnd, canonical}`：遮罩時保留的開頭、結尾長度（`keepEnd` 預設 3），`canonical` 是遮罩前先換成的標準寫法：`alnum-upper`（只留英數字、轉大寫）、`digits`、`tw-mobile`（`+886 9…` 換成 `09…`）、`e164`（`+` 加數字）。或 `"pem-block"`：只顯示標頭，貼遮罩版遮到 END 行。#27 起插件和桌面版的遮罩字串一樣（`SecretMasker.Mask` ＝ `pii.js` 的 `maskValue`：星號最多 8 個、至少遮 4 個字） |

**regex 語法**：只用 .NET 和 JS（沒有 `u` 旗標）行為一樣的子集合，而且不能用 lookaround、backreference、possessive、atomic group 和行內旗標 `(?i)`（要整條不分大小寫就用 `ignoreCase`）。理由：

- **線性時間**：.NET 用 `RegexOptions.NonBacktracking` 編譯（不支援 lookaround），最壞情況也是線性。JS 是回溯引擎，所以 gitleaks 規則裡在 JS 會變成 O(n²) 的（curl 那兩條）不收；兩邊的測試都會拿每條規則跑 1 Mi 字的病態輸入。
- **`$`** 是「整段結尾」（JS 沒有 `m` 旗標時的意思）；.NET 的 `$` 在最後一個換行前也成立，所以載入時換成 `\z`。
- **ASCII 版本**：`\b`、`\w`、不分大小寫在 .NET 認 Unicode，在 JS 只認 ASCII。所以規則比對的是「非 ASCII 字元都換成 U+001A」的版本（長度不變，位置直接對回原文），兩邊結果一樣，而且中文緊貼著 key（`金鑰dop_v1_…`）也找得到。
- **NonBacktracking 的群組**：.NET 9 的 NonBacktracking 找到的範圍正確，但有些 pattern 的捕獲群組是空的（實測 context-assignment），所以範圍交給 NonBacktracking，群組在那一小段裡用一般引擎（`^(?:…)\z`，逾時 200 ms）重比一次。

**gitleaks 怎麼轉**（`tools/convert-gitleaks.mjs`）：`\w`、`\d`、`\s`、`.` 展開成 RE2 的 ASCII 定義（`\s` 不含 `\v`，`.` 不含 `\n`）；只在開頭的 `(?i)` 改成 `ignoreCase`，其他位置的 `(?i)`、`(?-i:…)` 展開成 `[Aa]`；`(?P<name>…)` 改成一般群組（編號不變）；POSIX 類別展開；開頭只用來包住變數名稱的 `[\w.-]{0,50}?` 拿掉（不影響找到的機密，但 JS 每個位置都要試 50 次）。allowlist 裡「本身就是一把完整 key」的範例字串不收：它們會被 GitHub push protection 擋，也會被當成外洩。

**沒收的 gitleaks 規則**（24 條，完整原因在 `rules/gitleaks.json` 的 `skipped`）：

| 原因 | 規則 |
|---|---|
| 第 2 層負責 | generic-api-key |
| 手寫規則已涵蓋 | github-pat、github-oauth、github-app-token、github-refresh-token、github-fine-grained-pat、jwt、private-key |
| client ID 是公開的識別碼 | adobe、asana、bitbucket、discord、linkedin、looker、messagebird、plaid 的 client-id |
| 只在特定檔案類型才成立（剪貼簿沒有檔名） | freemius-secret-key、hashicorp-tf-password、kubernetes-secret-yaml、nuget-config-password、pkcs12-file |
| JS 會變成 O(n²) | curl-auth-header、curl-auth-user |
| 會把 git SHA 當成 token | sourcegraph-access-token（有一個分支是單獨的 40 位 hex） |

### 5.5 上下文＋亂度（第 2 層，`rules/context.json`）

兩條規則：

| 規則 | 上下文 | 值 |
|---|---|---|
| context-assignment（疑似金鑰或密碼） | 名稱含 `api_key`／`apikey`／`api-key`、`secret`、`token`、`password`／`passwd`、`pwd`、`credential`、`private_key`、`access_key`、`auth_key`、`signing_key`、`encryption_key`、`master_key`、`session_key`（不分大小寫，`.`、`_`、`-` 都可以），後面接 `=`、`:`、`:=`、`=>`、`?=`、`+=`，名稱和值可以有引號。涵蓋 `.env` 的 `KEY=value`、`export`、JSON 的 `"apiKey": "…"`、YAML、程式碼的指定、`X-API-Key:` 標頭、`$env:X = "…"` | 16–512 字的 `[A-Za-z0-9_+/=.~!@#%^*-]`，後面要接空白、引號、`;`、`,`、`)`、`}`、`]`、`>`、`&` 或結尾 |
| context-authorization（Authorization 權杖） | `Authorization:`（或 `=`）加 `Bearer`、`Token`、`Basic`、`ApiKey`，包括 `curl -H "Authorization: Bearer …"` | 16–1024 字的 `[A-Za-z0-9_+/=.~-]` |

值要再通過：

1. **亂度**：Shannon entropy 要**大於** `min(cap, a + b·log2(長度))`，依字元組成分三類：

   | 類別 | 條件 | a | b | cap | 16 字 | 32 字 | 64 字 |
   |---|---|---|---|---|---|---|---|
   | hex | 只有 `0-9a-f`（可以有 `-`，UUID） | 0.70 | 0.49 | 3.5 | 2.66 | 3.15 | 3.5 |
   | base36 | 只有小寫英數，或只有大寫英數 | 0.49 | 0.665 | 4.2 | 3.15 | 3.82 | 4.2 |
   | base64 | 其他 | 0.19 | 0.785 | 4.5 | 3.33 | 4.12 | 4.5 |

   **校準**：每類每個長度（16、20、24、32、40、64）用固定種子產生 5,000 個隨機字串，門檻取約第 1 百分位數（99% 的隨機 key 會通過）。例如隨機 32 字英數的第 1 百分位數是 4.20、中位數 4.54；隨機 32 位 hex 是 3.25、3.62。同樣長度下單字組成的值低很多：`your_api_key_here` 3.29、`changeme_changeme` 2.91、`REPLACE_WITH_YOUR_SECRET` 3.69、`deadbeef…` 2.16。只靠亂度分不開的是 camelCase 識別字（`accessTokenFromStorage` 3.66、`this.configuration.secretToken` 3.85），所以加了下面第 2、4 點。
2. **32 字以下一定要有數字**：隨機 20 字英數沒有數字的機率約 3%，識別字幾乎都沒有數字。
3. **不是連號或同一個字重複**（`rejectSequential`）。
4. **排除**：佔位字（`example`、`sample`、`dummy`、`placeholder`、`changeme`、`replace`、`insert`、`redacted`、`xxxx`、`todo`、`fake`、`your_`、`_here`、`<…>`、`${…}`、`{{…}}`）；屬性存取 `a.b.c`（`process.env.SECRET_KEY`、`settings.API_KEY`）；路徑（`/`、`./`、`~/` 開頭，或以 `.json`、`.pem`、`.key` 等副檔名結尾）；只有數字和標點。
5. **名稱排除**（`key` 目標，名稱會往前延伸到整個識別字）：以 `url`、`uri`、`endpoint`、`path`、`file`、`dir`、`name`、`type`、`length`、`count`、`size`、`limit`、`ttl`、`expires`、`timeout`、`header`、`field`、`prefix`、`format`、`version`、`policy`、`id`、`hash`、`digest`、`checksum`、`md5`、`sha*` 結尾，或含 `tokeniz`、`csrf`、`xsrf`、`public`、`publishable`、`page_token`、`max_tokens`。

**UUID 與 git SHA 的決定**：有沒有金鑰名稱才是分界。

| 情況 | 結果 | 理由 |
|---|---|---|
| `token: <UUID>`、`secret=<40 位 hex>` | **警告** | Heroku 等服務的 key 就是 UUID；明確寫著 secret／token 的 40 位 hex 多半就是 token。誤報只是多一則提醒（P1） |
| `id: <UUID>`、`token_id: <UUID>`、`commit: <SHA>`、`password_hash: <hex>`、`git log` 輸出 | 不警告 | 沒有金鑰名稱，或名稱表示它是識別碼或雜湊 |

`token = GetToken()`、`password = input()` 這類程式碼不會命中：值後面接的是 `(`，不是結尾字元。

**誤報樣本**：`tests/fixtures/secret-false-positives.json`，C# 和插件的測試都跑同一份，涵蓋 md5／sha1／sha256、UUID、git log 與短 SHA、Base64 圖片（`data:` URL）、C#／JS／Python 程式碼、`package-lock.json` 和 `yarn.lock` 的 integrity、minified JS、`.env` 佔位字、連號、不是機密的 token 欄位、中文句子。

**效能**（`SecretRulesTests`、`rules.test.js` 會量）：每條規則各跑 5 種 1 Mi 字的病態輸入（關鍵字重複、關鍵字加 `=`、關鍵字加 40 個字母、關鍵字後面接 1 Mi 個字母…），C# 最慢的一條 66 ms、JS 49 ms。整個 `SecretDetector.Find` 在 1 Mi 字、所有規則的關鍵字都出現時約 80 ms，滿滿的 `.env`（2 萬多筆命中）約 145 ms（C#；JS 約 115、155 ms）。不會因為長度整段跳過。

### 5.6 個資規則包（#27）

```
通用包（一律開）  信用卡 Luhn │ IBAN mod-97 │ 以 + 開頭的國際電話 │ API key（§5.4、§5.5）
國家包（依地區）  TW CN JP KR HK SG US
桌面版：RegionInfo.CurrentRegion → 國家包，加上 secret-packs.json 的 extra、拿掉 disabled
插件：navigator.languages 的每一個語言 → 國家包（聯集）
```

| 包 | 規則 | 驗證 | 上下文 |
|---|---|---|---|
| 通用 | 信用卡（§5.0 的分組） | IIN 前綴＋Luhn | 不需要 |
| 通用 | IBAN：國家代碼＋2 碼檢查碼＋BBAN，每 4 碼一個空白或不分隔 | 國家在 SWIFT 的長度表裡、長度剛好、mod 97 = 1 | 不需要 |
| 通用 | 國際電話：**一定要以 `+` 開頭**，數字共 8–15 碼 | 國碼是 ITU 已分配的；+1、+7 剛好 11 碼，北美區碼不能 0、1 開頭 | 不需要（`+` 本身就是上下文） |
| TW | 身分證、居留證、統編、手機（§5 的規則一覽） | 同以前 | 統編要（前 20 字） |
| CN | 居民身分證 18 碼（地區碼 1–8 開頭、出生日期、順序碼、檢查碼 0–9/X） | ISO 7064 MOD 11-2，出生日期是真的日期 | 不需要 |
| JP | 個人番號 12 碼（4-4-4） | 檢查碼（番号法施行令第 8 條） | **要**：マイナンバー、個人番号、My Number（前 32 字）。12 位數太常見，隨機 12 位數有 1/10 會通過檢查碼 |
| KR | 住民登錄番號 YYMMDD-SNNNNNN（S 1–8） | 只檢查月日；2020 年 10 月後的號碼最後一碼是隨機的，不驗檢查碼 | **要**：주민등록번호、주민번호、주민등록、RRN（前 32 字） |
| HK | 身分證：1–2 個字母＋6 碼＋檢查碼（0–9 或 A） | mod 11 | 檢查碼在括號裡（`A123456(3)`）不需要；沒括號（`A1234563`）要：HKID、Hong Kong ID、identity card、身份證、身分證（前 32 字） |
| SG | NRIC（S、T）、FIN（F、G、M）：字母＋7 碼＋檢查字母 | 權重 2,7,6,5,4,3,2，T/G 加 4、M 加 3，查表 | 不需要（跟台灣身分證一樣明確） |
| US | SSN 3-2-4（分隔符號一致或沒有） | 沒有檢查碼；排除區碼 000、666、900–999，組號 00，序號 0000 | **要**：SSN、Social Security、Soc Sec、SS#、社會安全（前 32 字或後 16 字） |

- **種類**：各國身分證號是 `NationalId`，居留證、新加坡 FIN 是 `ResidentCertificate`，國際電話是新的 `PhoneNumber`，IBAN 是新的 `BankAccount`（兩個都加在 `SecretKind` 最後面）。標籤在規則檔裡，目前是 zh-TW。
- **遮罩**：IBAN、卡號留前 4 後 4（`DE89********3000`），國際電話留國碼開頭 3 字和最後 3 碼（`+44*******958`），沒有前綴意義的號碼（SSN、個人番號、住民登錄番號）只留最後 3–4 碼，其他國家的身分證留前後幾碼（`110********02X`、`A*****63`、`S******7D`）。
- **選擇包**（`SecretPacks`）：`CountryOf` 把地區代碼（`TW`）或語系名稱（`zh-TW`、`zh-Hant-HK`、`zh_CN`）的地區部分對到國家包；只有語言時只認 `ja` → JP、`ko` → KR（其他語言跨太多國家）。`ForRegion(地區, extra, disabled)` 回傳要開的包，不認得的代碼忽略。`SecretDetector.Find(text)` 沒指定包時用 `SecretPacks.Default`（通用＋TW，#27 之前的行為）。
- **桌面版**：`SecretGuard` 啟動時讀 `RegionInfo.CurrentRegion` 和 `%LOCALAPPDATA%\ClipGuard\secret-packs.json`（`{"extra": ["JP"], "disabled": ["TW"]}`，目前沒有設定畫面，手動編輯；檔案壞掉就只依地區），之後不再重讀。
- **插件**：`content.js` 用 `packsForLocales(navigator.languages)`，每個偏好語言都算（`zh-TW`、`en-US` 都列著就開 TW 和 US）。插件沒有設定畫面，所以用聯集；美國包要關鍵字、其他包要檢查碼，多開一個包的誤報有限。
- **誤報樣本**：`SecretPacksTests`／`packs.test.js` 在所有包都開時跑日期、時間戳記、訂單與追蹤號碼、沒有關鍵字的 12 位數、美國格式的市話、UUID、大寫 hex、Base64、版本號（含 semver 的 `+`）、IP、時區 `UTC+0800`、檢查碼不對的型號、ISBN，以及共用的 `secret-false-positives.json`，都不能有任何命中。
- **效能**：每條個資規則各跑 14 種 1 Mi 字的病態輸入（滿滿的數字、`1 `、`+1 `、`A1`、`DE89 `、括號、關鍵字加號碼、只有關鍵字…）：C# 最慢一條 135 ms、JS 47 ms；所有包都開時整個 `Find` 最慢 145 ms（C#，每 14 字一個統編）、126 ms（JS，每 25 字一個個人番號）。

## 6. 隱藏字元與錢包掉包

### 6.1 隱藏字元（`HiddenCharDetector.cs`）：一律只判 Suspicious
| 項目 | 規則 | 例外 |
|---|---|---|
| 零寬字元 | U+200B、U+2060、U+FEFF；U+200C 和 U+200D 不在例外情況時 | emoji 的 ZWJ 序列，以及阿拉伯文、波斯文、印度系文字中的 ZWNJ / ZWJ |
| Unicode TAG | U+E0000–E007F（UTF-16 的代理對 U+DB40 U+DC00–DC7F，一個字元算一個）。可以把整段英文藏成看不見的字，給 AI 讀的 prompt injection | 只放行有標準圖案的區旗：🏴 + `gbeng`／`gbsct`／`gbwls` + 結束 TAG（英格蘭、蘇格蘭、威爾斯）。其他組合在各平台都只顯示成黑旗，TAG 部分一樣看不見，照算；區旗後面多接的 TAG 也照算 |
| Soft hyphen | U+00AD，只在換行處才顯示 | 夾在兩個字母之間（德文等語言的斷字點），而且那一行不像指令（§6.1 結尾換行同一套判斷）、不含 `://` 或 `www.` |
| 蒙古文母音分隔符 | U+180E（Unicode 6.3 起是看不見的格式字元） | 夾在兩個蒙古文字母（U+1800–18AF）之間 |
| 韓文填充字元 | U+115F、U+1160、U+3164、U+FFA0（顯示成空白，常被拿來做「看不見的名字」） | U+115F 後面接母音字母、U+1160 前面接子音字母（組合韓文字母的正常用法）；U+3164、U+FFA0 沒有現代的正常用法，不放行 |
| 變體選擇符 | 連續兩個以上（U+FE00–FE0F、U+E0100–E01EF），可逐 byte 藏資料（variation selector smuggling）；U+E0100 以上接在非漢字後面 | 一個字後面接一個（emoji 的 U+FE0F、漢字異體字序列）；連續但全是 U+FE0E／U+FE0F（重複的 emoji 樣式選擇符，常見手誤） |
| Bidi 控制字元 | U+202A–202E、U+2066–2069 | 無 |
| 同形字 | 一個英文單字裡混入看起來一樣的西里爾或希臘字母；或整段沒有真正的西里爾或希臘文字，卻出現全由同形字組成的單字 | 真正的俄文、希臘文，以及 `2πr`、`μm`、中日韓文字 |
| 結尾換行 | 最後一行看起來像 shell 指令，而且結尾有換行 | 一般句子 |

通知只顯示字元的 code point（例如 U+0435），不顯示原文；TAG 只顯示數量，不解碼藏起來的內容。

**長度**：不會因為總長度就整段跳過（以前超過 100,000 字直接不檢查）。每一項都是逐字線性掃描，桌面版最多讀進來的 1,048,576 字也在 1 秒內完成。唯一較貴的是「soft hyphen 那一行像不像指令」，同一行只判斷一次，整段最多判斷 256 行，之後的行只檢查網址。

沒有加入的字元與理由：U+2061–2064（看不見的數學運算子，Word 方程式複製出來的文字會帶 U+2061，誤報風險高）；U+200E／U+200F（LRM／RLM，希伯來文、阿拉伯文常用）；U+034F、U+17B4／17B5 等（看不見，但沒有已知的濫用案例，之後有需要再加）。

已知缺口：soft hyphen 夾在兩個字母之間、所在的那行又不像指令或網址時放行，所以可以用來拆開句子裡的關鍵字；第 256 行之後的 soft hyphen 不判斷指令；CommandNormalizer 不會去掉這些字元（§3.0），拆開指令名稱的情況要靠這裡提醒。

### 6.2 錢包掉包（`WalletAddress.cs`、`WalletSwapDetector.cs`、`src/ClipGuard.App/UserInput.cs`）

Clipper 惡意程式監聽剪貼簿，看到地址就換成攻擊者的地址，做法是**原地取代**：句子裡的其他文字一個字都不變。它跟「使用者自己又複製了另一個地址」的差別有三個：換得很快、換的時候使用者沒有任何操作、前後文字完全相同。

**找地址**：剪貼簿裡每一段連續英數字（前後不能緊鄰英數字）都拿去驗證，所以句子裡的地址也找得到，hash、Base64 這類更長的字串不會被切一段出來誤認。只掃前 100,000 字，每份內容最多驗證 256 個長度符合的候選字串。支援 BTC（Base58Check、bech32、bech32m）、TRON（Base58Check）、ETH（只檢查格式，沒有驗 EIP-55）。

**記憶**：只記最後一次含地址的內容：地址、「地址換成佔位字元、去頭尾空白後的文字」的 SHA-256（不留原文）、時間。不含地址的內容不會清掉記憶，所以 A → `x` → B 一樣拿 A 比。

**判定**：新內容去掉地址後的文字必須跟記住的**完全相同**、只有地址不同（數量也要一樣），幣種可以不同（ETH → BTC 也算）。前後文字不同就是使用者複製了別段，不算。

| 情況 | 複製後 ≤ 1 秒 | 1–3 秒 | > 3 秒 |
|---|---|---|---|
| 地址在句子裡（有其他非空白文字） | 警告 | 警告 | 不警告 |
| 整段只有地址（一個或多個） | 警告 | 只有「複製後使用者沒有任何輸入」才警告 | 不警告 |

- **1 秒**：人要選取、複製兩個不同地址，1 秒內做不到；clipper 通常在幾十毫秒內換掉，輪詢型的約 0.5–1 秒（#23 實測到 600–1000 ms）。
- **3 秒**：記憶的上限。超過 3 秒的掉包使用者多半已經切到別的視窗，而記太久會讓「隔一陣子複製自己的另一個地址」被比對到。
- **沒有輸入**：用 `GetLastInputInfo` 取得最後一次鍵盤或滑鼠輸入的時間（不裝 hook、不記錄按鍵）。使用者要複製第二個地址一定得按鍵或點滑鼠；複製後 500 ms 內的輸入（放開 Ctrl、C）算是複製 A 的一部分。
- **句子裡的地址**：同一段文字只換了地址，人不會在 3 秒內這樣複製兩次，所以不看輸入狀態。

**誤報與漏報的取捨**：

| 情況 | 結果 | 理由 |
|---|---|---|
| 使用者 1 秒後複製自己的另一個地址 | 不警告（有輸入） | 主要的誤報來源，用輸入訊號排除 |
| 1 秒內連續複製兩個不同地址（例如複製錯了馬上重複製） | **會警告（誤報）** | 很少見；通知不清空剪貼簿（P1），只要求核對 |
| 地址清單、含多個不同地址的文件 | 不警告 | 前後文字不同 |
| 手機透過雲端剪貼簿在 3 秒內同步另一個地址過來 | **可能警告（誤報）** | 本機沒有輸入；極少見 |
| clipper 在 1–3 秒才換，期間使用者剛好在動滑鼠 | 漏報 | 滑鼠移動也算輸入，分不出是不是「複製」 |
| clipper 自己模擬輸入，或超過 3 秒才換 | 漏報 | 刻意繞過，見下方已知缺口 |

- 通知不顯示地址，連遮罩版都不顯示。假地址的頭尾常跟真地址一樣，顯示遮罩版反而會讓人誤以為沒被換掉。通知只寫幣種和間隔。
- 已知缺口：超過 3 秒才換；1–3 秒才換、只有地址、而且使用者正好有輸入；clipper 同時改了其他文字；地址被拆開（中間插零寬字元或換行）；第 256 個候選字串之後、或第 100,000 字之後的地址；ETH 沒驗 EIP-55，其他鏈（SOL、XRP 等）不支援。

## 7. 瀏覽器插件（`extension/`）

| 功能 | 規則 |
|---|---|
| 貼上機密 | 只有偵測到機密時才攔下貼上，否則**完全不介入**。提示框選項：貼遮罩版（預設，按 Enter）、貼原文、取消（按 Esc）。密碼欄位不處理 |
| 提示框焦點 | 提示框一出現就搶焦點（預設按鈕），提示框裡的按鍵（含選完後放開 Enter 的 keyup）不會傳給網頁，所以網頁在 window／document 上聽的 Enter 也收不到。已用本機測試頁（form 的 input、Enter 送出的 textarea 和 contenteditable）在 headless Chromium 驗證：Ctrl+V 後馬上按 Enter 只會貼上遮罩版，不會送出；再按一次 Enter 才會送出遮罩版 |
| Pastejacking | 比對「使用者選取的文字」和「頁面寫進剪貼簿的內容」。被取代、多了指令或換行、多了隱形字元時警告。複製後 2 秒內頁面又寫入剪貼簿，而且使用者這段期間沒有任何點擊或按鍵，才算是被改寫 |
| 權限 | 不使用 `permissions`、`host_permissions`；不連網、不存資料、沒有 service worker |

**機密規則的來源**：所有規則（API key、JWT、PEM、上下文＋亂度、#27 起的個資包）跟桌面版共用 `rules/*.json`（§5.4），比對引擎在 `extension/lib/rules.js`，檢查碼、信用卡分組、遮罩在 `extension/lib/pii.js`，跟 C# 的 `SecretRules`、`PiiFormats`、`Checksums`、`SecretMasker` 逐項對應，兩邊的測試用同樣的樣本（`SecretPacksTests` ＝ `packs.test.js`）。#27 以前的不一致（舊式居留證、統編關鍵字距離、重疊取哪一筆、遮罩字串、API key 留幾碼）都已經統一。

**目前和 C# 端不一致的地方**（見 #27）：

| 項目 | C#（桌面） | JS（插件） |
|---|---|---|
| 國家包怎麼選（§5.6） | 一個地區設定（`RegionInfo.CurrentRegion`）加上 `secret-packs.json` | `navigator.languages` 裡每個語言的聯集，沒有手動設定 |
| 機密的正規化、分隔符號、JWT、長度上限（§5.0） | 有 | 同一套（`normalizeForSecrets`、`cardCandidates`、`MAX_SCAN_LENGTH` = 1 Mi 字頭尾）。插件不分段，頭尾各一次正規化 |
| 規則檔的 regex 引擎 | NonBacktracking（保證線性時間），群組在比對到的那段重比 | V8 的回溯引擎；會變成 O(n²) 的規則在轉換時就不收（§5.4），兩邊的測試都量每條規則 |
| 指令樣式 | 完整版 `CommandDetector` | 只有少數幾種（用於判斷 Pastejacking）；沒有 #20 的「下載後直接執行」、官方網站清單，也沒有 #21 的 LOLBin、UNC/WebDAV、protocol handler，也沒有誘餌註解（含 #27 的多語版本） |
| 指令正規化（§3.0） | 有（`CommandNormalizer`） | 沒有：完整路徑、`^`、引號拆字、dash 變體都認不得 |
| 貼上提示的 Enter | 取消（§5.3） | 貼遮罩版。插件直接插入文字，不必換剪貼簿，沒有桌面版的副作用 |
| 貼上攔截的範圍 | 預設只攔登記的機密 | 所有偵測到的機密（插件沒有登記機密） |
| 看不見的字元（§6.1） | 各字元有例外規則（區旗、斷字點、韓文組合、單一變體選擇符） | 同一份清單加上 U+200E／200F、U+2061–2064，但**沒有例外規則**，也不看 U+FE00–FE0F：插件比的是「網頁寫入」比「使用者選取」多出來的數量，使用者自己選到的區旗、斷字點兩邊都有，會互相抵銷 |

## 8. 測試資料規範
- 只能用假資料：自己算出能通過檢查碼的號碼、發卡機構公開的測試卡號、明顯是假的 key。#27 的國家包用官方或規格公布的範例號碼（GB 11643 的 `11010519491231002X`、ECBS／SWIFT 的 IBAN 範例、SSA 已作廢的 `078-05-1120`、`219-09-9999`、各國保留給虛構用的電話號碼），其他在測試裡用另外寫的演算法補上檢查碼（`SecretPacksTests` 的 `Iban`、`ChinaId`、`MyNumber`），順便跟 `Checksums` 交叉驗證。
- 網址一律用 `example.invalid`。惡意指令樣本要在執行時用片段組合，不要以完整字串寫進檔案（理由同文件開頭的防毒說明）。
- 偵測規則的測試要同時有「該命中」和「不該命中」兩種樣本。誤報樣本至少包含：日期、訂單號碼、UUID、hash、Base64、一般中英文句子、官方安裝指令。
- **API key 樣本不能完整寫進檔案**（包括規則檔和測試）：GitHub 的 push protection 會擋，防毒也可能有反應。測試用「前綴 + 固定種子的亂數」在執行時產生（C# 的 `SecretRulesTests.Gen` 和 JS 的 `gen` 產生一樣的字串）。規則檔只放 regex；`SecretRulesTests` 會掃一次規則檔，確認裡面沒有長得像 key 的字串。
- 機密的誤報樣本放在 `tests/fixtures/secret-false-positives.json`，桌面版和插件共用；新增誤報案例時加在這裡。

## 9. Review 檢查清單

Review 一個會動到偵測行為的 PR 時，逐項確認：

- [ ] **文件一致**：行為改變有同步更新本文件對應章節；新增或修掉的缺口有更新「已知缺口」表和 issue 編號。
- [ ] **P1**：新規則會不會讓合法內容被**清空**？會清空的話，有沒有足夠強的詐騙訊號？
- [ ] **P2**：新的通知有沒有放進 §2 的優先順序？會不會蓋掉「攔截並可還原」那則通知？
- [ ] **P3 / P4**：沒有把剪貼簿原文寫進檔案、log、例外訊息或通知；機密一律遮罩。
- [ ] **P5 / P6**：有檢查碼的格式有驗證；沒有檢查碼的短格式有要求上下文。
- [ ] **P7**：判斷邏輯在 Core，App 只負責接線；有單元測試，同時涵蓋命中與不命中。
- [ ] **長度上限**：新規則碰到超長輸入時，不是「整段跳過」（#19 的教訓），而且不會卡住 UI。
- [ ] **繞過**：想想正規化問題，例如大小寫、全形、路徑、引號、`^`、dash 變體、零寬字元。
- [ ] **C# / JS 一致**：改到兩邊都有的規則時，兩邊都要改，或是在 §7 的不一致表裡記下來。
- [ ] **規則檔**：改了 `rules/*.json` 有重新產生 `extension/lib/rules.generated.js`；新的 regex 符合 §5.4 的語法限制，兩邊的「1 Mi 病態輸入」測試都過；gitleaks 規則只透過 `tools/convert-gitleaks.mjs` 更新，不手改 `rules/gitleaks.json`。
- [ ] **測試資料**：符合 §8 的規範。
