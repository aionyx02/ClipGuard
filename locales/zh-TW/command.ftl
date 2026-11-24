# 指令偵測（crates/core/src/command）。舊版 CommandDetector 的理由與 CoreStrings 的 Explain_*。

## 判定理由：執行訊號

cmd-reason-powershell = 呼叫 PowerShell
cmd-reason-mshta = 呼叫 mshta（常用來執行遠端 HTA）
cmd-reason-cmd = 呼叫 cmd 執行指令
cmd-reason-delayed-expansion = cmd 延遲展開（用 !變數! 組出指令）
cmd-reason-certutil = 用 certutil 下載檔案
cmd-reason-bitsadmin = 用 bitsadmin 下載檔案
cmd-reason-rundll32 = 用 rundll32 執行腳本或遠端檔案
cmd-reason-regsvr32 = 用 regsvr32 載入遠端腳本
cmd-reason-msiexec = 用 msiexec 安裝遠端套件
cmd-reason-conhost = 用 conhost 無視窗執行
cmd-reason-curl-shell = 下載後直接交給 shell 執行
cmd-reason-script-host = 用 wscript／cscript 執行腳本
cmd-reason-html-help = 用 hh 開啟說明檔（可內嵌腳本）
cmd-reason-cmstp = 用 cmstp 安裝設定檔（可藉此執行程式）
cmd-reason-pcalua = 用 pcalua 間接啟動程式
cmd-reason-odbcconf = 用 odbcconf 載入 DLL
cmd-reason-installutil = 用 InstallUtil 執行 .NET 程式
cmd-reason-ftp-script = 用 ftp 執行指令檔
cmd-reason-remote-file = 執行網路分享（UNC／WebDAV）上的檔案
cmd-reason-webdav = 連到 WebDAV 遠端資料夾
cmd-reason-search-ms = 用 search-ms: 開啟搜尋視窗（可指向遠端資料夾）
cmd-reason-ms-msdt = 用 ms-msdt: 呼叫疑難排解工具（Follina 手法）
cmd-reason-net-use = 掛載網路磁碟後執行裡面的檔案
cmd-reason-download-exec = 下載後直接執行
cmd-reason-osascript = 用 osascript 執行 AppleScript
cmd-reason-quarantine = 移除 macOS 的隔離標記（跳過 Gatekeeper 檢查）
cmd-reason-decode-shell = 把藏起來的編碼內容解開後交給 shell 執行
cmd-reason-dev-tcp = 從 shell 開網路連線（/dev/tcp、nc）

## 判定理由：詐騙訊號

cmd-reason-hidden-window = 隱藏視窗執行
cmd-reason-encoded = 執行 Base64 編碼過的指令
cmd-reason-iex = 把下載內容當程式碼執行（iex）
cmd-reason-download = 從網路下載內容
cmd-reason-bait-comment = 誘餌註解（假裝是人機驗證）
cmd-reason-check-mark = 含勾選符號（假驗證常見）
cmd-reason-padding = 用大量空白把真正的指令擠出輸入框
cmd-reason-mshta-remote = mshta 直接執行遠端網址
cmd-reason-unofficial-source = 下載並執行的來源不是已知的官方安裝網站
cmd-reason-reverse-shell = 把 shell 的控制權交給遠端電腦（反向 shell）
cmd-reason-background = 在背景脫離執行，而且不顯示任何輸出
cmd-reason-msiexec-quiet = 用 msiexec 靜默安裝遠端套件
cmd-reason-obfuscated = 用混淆手法（拼字串、編碼）藏住要執行的東西

## 解混淆步驟（洋蔥 trace）
# $count = 這一步改了幾處。

cmd-deob-invisible = 拿掉看不見的字元
cmd-deob-dash = 把長得像 - 的字換成 -
cmd-deob-caret = 拿掉 cmd 的 ^ 跳脫
cmd-deob-variable = 代入 cmd 的 %變數%
cmd-deob-quote = 合併字中間的引號
cmd-deob-program-path = 把程式的完整路徑縮成檔名
cmd-deob-markdown = 拿掉 markdown 的程式碼標記
cmd-deob-full-width = 把全形英文字母換成半形
cmd-deob-backtick = 拿掉 PowerShell 的反引號跳脫
cmd-deob-url-decode = 解開網址編碼（%xx）
cmd-deob-hex-decode = 解開十六進位編碼
cmd-deob-char-code = 把 [char] 字碼換成字母
cmd-deob-concat = 接起用 + 拼出來的字串
cmd-deob-join = 算出 -join 的結果
cmd-deob-format = 算出 -f 格式化的結果
cmd-deob-replace = 算出 -replace／.Replace() 的結果
cmd-deob-string-method = 算出 [string]::Concat／Join／Format 的結果
cmd-deob-ps-variable = 代入 PowerShell 的字串變數
cmd-deob-unwrap = 拆開被當成指令執行的字串
cmd-deob-base64 = 解開 Base64
cmd-deob-encoded-command = 解開 PowerShell 的 -EncodedCommand
cmd-deob-cmd-substring = 展開 cmd 的子字串（%x:~a,b%）
cmd-deob-nested-variable = 代入藏在其他變數裡的 cmd 變數

## 白話說明
# $count = 來源主機數（0 = 不知道來源），$h1..$h3 = 主機名稱（最多 3 個）。

cmd-explain-separator = ；
cmd-explain-display = 白話：{ $summary }
cmd-explain-decoded = 解碼：{ $decoded }
cmd-explain-download-and-run =
    { $count ->
        [0] 從網路下載並執行
        [1] 從 { $h1 } 下載並執行
        [2] 從 { $h1 }、{ $h2 } 下載並執行
       *[other] 從 { $h1 }、{ $h2 }、{ $h3 } 下載並執行
    }
cmd-explain-regsvr32 =
    { $count ->
        [0] 從網路載入並執行遠端腳本
        [1] 從 { $h1 } 載入並執行遠端腳本
        [2] 從 { $h1 }、{ $h2 } 載入並執行遠端腳本
       *[other] 從 { $h1 }、{ $h2 }、{ $h3 } 載入並執行遠端腳本
    }
cmd-explain-msiexec =
    { $count ->
        [0] 從網路下載並安裝套件
        [1] 從 { $h1 } 下載並安裝套件
        [2] 從 { $h1 }、{ $h2 } 下載並安裝套件
       *[other] 從 { $h1 }、{ $h2 }、{ $h3 } 下載並安裝套件
    }
cmd-explain-download-file =
    { $count ->
        [0] 從網路下載檔案
        [1] 從 { $h1 } 下載檔案
        [2] 從 { $h1 }、{ $h2 } 下載檔案
       *[other] 從 { $h1 }、{ $h2 }、{ $h3 } 下載檔案
    }
cmd-explain-mshta-host = 用 mshta 執行 { $host } 上的程式
cmd-explain-mshta-script = 用 mshta 執行一段腳本
cmd-explain-rundll32 = 用 rundll32 執行一段腳本
cmd-explain-start-process-admin = 以系統管理員權限啟動其他程式
cmd-explain-start-process = 啟動其他程式
cmd-explain-hidden = 隱藏視窗，執行過程你看不到
cmd-explain-bypass = 關閉 PowerShell 的腳本安全限制
cmd-explain-defender = 修改 Windows Defender 設定
cmd-explain-encoded-undecodable = 藏了一段無法解碼的編碼指令
cmd-explain-encoded = 藏了一段編碼過的指令
cmd-explain-generic = 會執行系統指令
cmd-explain-delayed-expansion = 用 cmd 的延遲展開（!變數!）把指令拆開藏起來
cmd-explain-script-host = 用 wscript／cscript 執行腳本檔
cmd-explain-html-help = 用 hh 開啟說明檔，裡面可以藏腳本
cmd-explain-cmstp = 用 cmstp 安裝連線設定檔，可藉此執行任意程式
cmd-explain-pcalua = 透過 pcalua 間接啟動其他程式
cmd-explain-odbcconf = 用 odbcconf 載入並執行 DLL
cmd-explain-installutil = 用 InstallUtil 執行 .NET 程式
cmd-explain-ftp-script = 用 ftp 照一份指令檔執行
cmd-explain-remote-file-host = 執行 { $host } 網路分享上的檔案
cmd-explain-remote-file = 執行網路分享上的檔案
cmd-explain-webdav-host = 連到 { $host } 的 WebDAV 遠端資料夾
cmd-explain-webdav = 連到 WebDAV 遠端資料夾
cmd-explain-net-use = 掛載網路磁碟後執行裡面的程式
cmd-explain-search-ms = 用 search-ms: 開啟搜尋視窗，裡面的檔案可能來自遠端
cmd-explain-ms-msdt = 用 ms-msdt: 呼叫疑難排解工具（Follina 漏洞的手法）
