# Execution-entry guard (core::policy::entry). $entry: run_dialog | file_explorer | file_dialog | terminal

entry-malicious-title = 小心！你剛打開了{ $entry ->
        [run_dialog] 「執行」視窗
        [file_explorer] 檔案總管
        [file_dialog] 檔案對話框
       *[terminal] 終端機
    }
entry-malicious-quarantined = 剛才攔截的指令已從剪貼簿清空。
entry-malicious-in-clipboard = 剪貼簿裡有惡意指令。
entry-malicious-advice = 叫你按 Win+R、開檔案總管或終端機貼上指令的「驗證」是詐騙手法，請直接關掉。
entry-suspicious-title = 你打開了{ $entry ->
        [run_dialog] 「執行」視窗
        [file_explorer] 檔案總管
        [file_dialog] 檔案對話框
       *[terminal] 終端機
    }，剪貼簿裡有會執行程式的指令
entry-suspicious-body = 貼上前請確認指令來源可信。網站要你貼上指令「完成驗證」一定是詐騙。
