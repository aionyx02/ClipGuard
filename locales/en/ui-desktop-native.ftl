# Desktop app strings rendered by Rust (apps/desktop/src-tauri): tray menu,
# notifications, command errors. The React UI's strings are in ui-desktop.ftl.

## Tray (legacy TrayApp menu)
ui-desktop-tray-status-normal = Protection is on
ui-desktop-tray-status-degraded = Protection is partly limited
ui-desktop-tray-status-failed = Protection is not working
ui-desktop-tray-restore = Restore cleared content
ui-desktop-tray-register-secret = Register a secret…
ui-desktop-tray-manage-secrets = Manage registered secrets…
ui-desktop-tray-paste-menu = Confirm before paste (strict mode)
ui-desktop-tray-strict-registered = Intercept registered secrets
ui-desktop-tray-strict-detected = Also intercept personal data and API keys
ui-desktop-tray-allowlist = Allowlist…
ui-desktop-tray-settings = Settings…
ui-desktop-tray-quit = Quit

## Notifications. Notifications cannot be clicked; restore is in the tray menu.
ui-desktop-toast-quarantine-title = Blocked a suspicious "paste and run" command
ui-desktop-toast-quarantine-head = The clipboard was cleared. Real websites never ask you to press Win+R and paste a command.
ui-desktop-toast-quarantine-tail = If you are sure it is safe, restore it from the PasteWarden tray menu.
ui-desktop-toast-suspicious-title = The clipboard holds a command that runs programs
ui-desktop-toast-suspicious-head = Make sure it comes from a trusted source before pasting.
ui-desktop-toast-secret-title = The clipboard holds sensitive data
# $label: the kind of data; $masked: the masked value
ui-desktop-toast-secret-line = { $label } { $masked }
ui-desktop-toast-secret-more = …and { $count } more
ui-desktop-toast-secret-advice = Check who and which site you are pasting to.
ui-desktop-toast-hidden-title = The clipboard has invisible or disguised characters
ui-desktop-toast-hidden-head = Check the content before pasting.
ui-desktop-toast-wallet-swap-title = The wallet address may have been swapped
ui-desktop-toast-wallet-swap-detail = The { $currency ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } address you just copied was replaced by a different one after { $ms } ms. Clipboard-hijacking malware may be running.
ui-desktop-toast-wallet-swap-detail-other = The { $currency ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } address you just copied was replaced by a { $other ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } address after { $ms } ms. Clipboard-hijacking malware may be running.
ui-desktop-toast-wallet-swap-advice = Do not paste it. Fake addresses often share the first and last characters; check every character and scan for malware.
ui-desktop-toast-elevated-title = PasteWarden can't confirm pastes here
# $kind: rendered ui-desktop-kind-* message
ui-desktop-toast-elevated-unprotected = This window runs as administrator, so PasteWarden can't intercept pastes into it. The clipboard holds: { $kind }.
ui-desktop-toast-secure-input-title = PasteWarden can't confirm pastes right now
ui-desktop-toast-secure-input-unprotected = An app turned on secure input, so PasteWarden can't intercept pastes. The clipboard holds: { $kind }.
ui-desktop-toast-not-pasted-title = Not pasted
ui-desktop-toast-paste-timeout = Checking the clipboard took too long, so nothing was pasted. Please paste again.
ui-desktop-toast-cannot-read = Couldn't read the clipboard. Please copy it again.
ui-desktop-toast-cannot-write = Couldn't write to the clipboard. Please try again later.
ui-desktop-toast-cannot-send = Couldn't send the paste to the original window. Please paste again yourself.
ui-desktop-toast-still-masked-title = The clipboard still holds the masked version
ui-desktop-toast-still-masked-body = Couldn't switch back to the original content. Copy it again if you need it.
ui-desktop-toast-restore-failed-title = Couldn't restore
ui-desktop-toast-restore-failed-body = Writing to the clipboard failed. The content is kept; try again from the tray menu.
ui-desktop-toast-settings-problem-title = There is a problem with PasteWarden's settings

## Command errors (messageId)
ui-desktop-error-save-failed = Couldn't save the settings.
ui-desktop-error-store-corrupt = A settings file was damaged; defaults are used.
ui-desktop-error-key-unavailable = Couldn't read the key for registered secrets from the system keychain.
ui-desktop-error-worker-stopped = PasteWarden isn't responding. Please restart it.
ui-desktop-error-invalid-argument = Invalid value.
ui-desktop-error-allowlist-empty = Enter an app name.
ui-desktop-error-allowlist-too-long = The app name is too long.
ui-desktop-error-allowlist-duplicate = This app is already on the allowlist.
ui-desktop-error-allowlist-full = The allowlist is full.
ui-desktop-error-allowlist-missing = This app isn't on the allowlist.
ui-desktop-error-label-too-long = The label can have at most { $max } characters.
ui-desktop-error-secrets-full = You can register at most { $max } secrets.
ui-desktop-error-secret-missing = This secret no longer exists.
ui-desktop-error-no-pending-paste = There is no paste waiting for confirmation.
ui-desktop-error-nothing-to-restore = There is nothing to restore.
ui-desktop-error-restore-failed = Couldn't restore the content.
ui-desktop-error-open-settings-failed = Couldn't open System Settings.
ui-desktop-error-unsupported = Not available on this system.
