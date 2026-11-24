# Execution-entry guard (core::policy::entry). $entry: run_dialog | file_explorer | file_dialog | terminal

entry-malicious-title = Careful! You just opened { $entry ->
        [run_dialog] the Run dialog
        [file_explorer] File Explorer
        [file_dialog] a file dialog
       *[terminal] a terminal
    }
entry-malicious-quarantined = The command that was just blocked has been cleared from the clipboard.
entry-malicious-in-clipboard = The clipboard contains a malicious command.
entry-malicious-advice = A "verification" that asks you to press Win+R, or open File Explorer or a terminal, and paste a command is a scam. Close it.
entry-suspicious-title = Opened { $entry ->
        [run_dialog] the Run dialog
        [file_explorer] File Explorer
        [file_dialog] a file dialog
       *[terminal] a terminal
    } with a command in the clipboard
entry-suspicious-body = Make sure the command comes from a trusted source before pasting. A site that asks you to paste a command to "complete verification" is always a scam.
