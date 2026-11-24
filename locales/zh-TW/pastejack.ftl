# Pastejacking (legacy extension _locales pj_*).

pastejack-hidden = 含有看不見的字元（零寬或雙向控制字元）
# $signal: powershell | mshta | cmd | pipe-shell | iex | lolbin | sudo (see pastejack-sig-*).
pastejack-added = 網頁加入的內容{ $signal ->
        [powershell] { pastejack-sig-powershell }
        [mshta] { pastejack-sig-mshta }
        [cmd] { pastejack-sig-cmd }
        [pipe-shell] { pastejack-sig-pipe-shell }
        [iex] { pastejack-sig-iex }
        [lolbin] { pastejack-sig-lolbin }
       *[sudo] { pastejack-sig-sudo }
    }
pastejack-newline = 加入換行，貼進終端機會直接執行
pastejack-replaced = 寫入剪貼簿的內容和你選取的文字不同
pastejack-sig-powershell = 呼叫 PowerShell
pastejack-sig-mshta = 呼叫 mshta
pastejack-sig-cmd = 呼叫 cmd 執行指令
pastejack-sig-pipe-shell = 下載後直接交給 shell 執行
pastejack-sig-iex = 把內容當程式碼執行（iex）
pastejack-sig-lolbin = 呼叫常被濫用的系統程式
pastejack-sig-sudo = 以 sudo 執行指令
