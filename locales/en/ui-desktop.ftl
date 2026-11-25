# Desktop React UI (apps/desktop/src): settings, paste confirmation, first-run onboarding.
# Ids use the `ui-desktop-` prefix. Native strings (tray, notifications) are in ui-desktop-native.ftl.
# `$platform` is windows, macos or linux.

## Shared
ui-desktop-cancel = Cancel
ui-desktop-quit = Quit PasteWarden
ui-desktop-error-generic = Something went wrong. Please try again.
ui-desktop-open-accessibility = Open Accessibility settings

## Protection status (§4.8.1)
ui-desktop-status-loading = Reading protection status…
ui-desktop-status-title-normal = All protection is working.
ui-desktop-status-title-degraded = Some protection is limited right now. Details below.
ui-desktop-status-title-failed = Some protection is not working. Details below.
ui-desktop-area-watch = Clipboard monitoring
ui-desktop-area-write = Clearing, masking and restoring
ui-desktop-area-foreground = Foreground window (entry warnings, allowlist)
ui-desktop-area-intercept = Confirm before paste
ui-desktop-state-active = Working
ui-desktop-state-degraded = Limited
ui-desktop-state-unavailable = Unavailable
ui-desktop-status-unknown = This protection is limited right now.

# One per Reason (crates/platform/src/status.rs, §4.9.4)
ui-desktop-status-hook-lost = Paste protection has stopped for now: PasteWarden is not receiving keyboard events and is trying to recover. Until then, pasting a secret will not ask you first.
ui-desktop-status-elevated-foreground = The current window runs as administrator, so PasteWarden can't intercept pastes there. Malicious commands are still cleared when copied.
ui-desktop-status-disabled-in-settings = You turned this protection off in settings.
ui-desktop-status-secure-input = An app has turned on Secure Input (a password field, or Terminal's Secure Keyboard Entry), so pastes can't be intercepted for now.
ui-desktop-status-no-accessibility = PasteWarden doesn't have Accessibility permission, so it only notifies you and can't stop a paste. Interception starts once you allow it.
ui-desktop-status-no-accessibility-after-update = After an update, macOS needs you to allow PasteWarden again. The old entry in System Settings may still look switched on, but it no longer works: remove it and add PasteWarden again.
ui-desktop-status-pasteboard-access-ask = macOS asks every time PasteWarden reads the clipboard. In System Settings → Privacy & Security, set PasteWarden's clipboard access to “Always Allow”.
ui-desktop-status-pasteboard-access-denied = System Settings doesn't allow PasteWarden to read the clipboard, so copied content can't be checked. In System Settings → Privacy & Security, set PasteWarden's clipboard access to “Always Allow”.
ui-desktop-status-no-data-control = This desktop (for example GNOME) doesn't let apps read the clipboard in the background. Use “Check clipboard” in the tray menu, or install the browser extension.
ui-desktop-status-xwayland-unverified = The clipboard can only be monitored through XWayland; copies made in native Wayland apps may be missed.
ui-desktop-status-cosmic-disabled = COSMIC doesn't allow background clipboard access by default. Set the environment variable COSMIC_DATA_CONTROL_ENABLED=1 and log in again.
ui-desktop-status-no-foreign-toplevel = The foreground window isn't available, so entry warnings and the allowlist are off.
ui-desktop-status-wayland-no-intercept = Wayland doesn't let apps intercept keys, so PasteWarden only notifies you and can't stop a paste.
ui-desktop-status-x11-no-intercept = This version doesn't intercept pastes on X11 (it would clash with your shortcut tools); it only notifies you.
ui-desktop-status-no-display = No graphical session found (neither Wayland nor X11), so the clipboard can't be monitored.
ui-desktop-status-no-secret-service = No Secret Service found (such as GNOME Keyring or KWallet), so the key can't be stored safely and secrets can't be registered.
ui-desktop-status-android-no-background = Android doesn't let apps read the clipboard in the background. Select text, or use Share, and pick PasteWarden to check it.
ui-desktop-status-host-failed = PasteWarden couldn't connect to the system, so it can't protect the clipboard right now. Restart PasteWarden; if this keeps happening, restart the computer.

## Re-allowing Accessibility (graphical steps only)
ui-desktop-reauth-step-1 = Click the button below, or open System Settings → Privacy & Security → Accessibility.
ui-desktop-reauth-step-2 = Select PasteWarden in the list and click “−” below it to remove it, even if its switch looks on.
ui-desktop-reauth-step-3 = Click “+”, choose PasteWarden in the Applications folder, and turn its switch on.
ui-desktop-reauth-step-4 = Come back to PasteWarden; the status updates within a few seconds. If it hasn't after a minute, quit PasteWarden from its menu bar icon and open it again.

## Settings
ui-desktop-settings-title = PasteWarden settings
ui-desktop-settings-subtitle = Every check runs on this computer. Clipboard content is never sent anywhere.
ui-desktop-section-status = Protection status
ui-desktop-section-paste-guard = Confirm before pasting secrets
ui-desktop-section-paste-guard-desc = When the clipboard holds a secret, choose to cancel, paste a masked version, or paste the original before it goes anywhere.
ui-desktop-paste-guard-keyboard-only = Only keyboard pastes ({ $platform ->
        [macos] Cmd+V
       *[other] Ctrl+V
    } and similar) are intercepted. Right-click menus, Edit → Paste and drag and drop are not. See “What is protected” below.
ui-desktop-paste-guard-registered = Confirm before pasting registered secrets
ui-desktop-paste-guard-registered-desc = Passwords, keys and anything else you registered below.
ui-desktop-paste-guard-detected = Confirm before pasting detected secrets
ui-desktop-paste-guard-detected-desc = ID numbers, credit cards, API keys, private keys, recovery phrases and more.
ui-desktop-section-allowlist = Allowlist
ui-desktop-section-allowlist-desc = Pasting into these apps never asks first, for example your password manager. Matched by exact program name.
ui-desktop-allowlist-label = Program name
ui-desktop-allowlist-placeholder = { $platform ->
        [windows] e.g. KeePassXC.exe
        [macos] e.g. org.keepassxc.keepassxc
       *[other] e.g. keepassxc
    }
ui-desktop-allowlist-add = Add
ui-desktop-allowlist-none = No apps added yet.
ui-desktop-allowlist-remove = Remove { $name } from the allowlist
ui-desktop-allowlist-empty-name = Enter a program name.
ui-desktop-section-secrets = Registered secrets
ui-desktop-section-secrets-desc = Register passwords or keys you use often, so PasteWarden can warn you before pasting secrets its rules wouldn't recognize.
ui-desktop-secrets-secret = Secret to register
ui-desktop-secrets-confirm = Enter it again
ui-desktop-secrets-label = Name (optional)
ui-desktop-secrets-label-placeholder = e.g. Work VPN password
ui-desktop-secrets-add = Register
ui-desktop-secrets-added = Registered.
ui-desktop-secrets-privacy = PasteWarden keeps only an HMAC hash of the secret, never the secret itself, and can't show it again. The name is stored as plain text, so don't put the secret in it.
ui-desktop-secrets-list = Registered
ui-desktop-secrets-none = No secrets registered yet.
ui-desktop-secrets-meta = { $length } characters · registered { $date }
ui-desktop-secrets-remove = Remove
ui-desktop-secrets-remove-label = Remove “{ $label }”
ui-desktop-secrets-remove-confirm = Remove it
ui-desktop-secrets-forget = Clear all registered secrets
ui-desktop-secrets-forget-desc = Removes every registered secret. Use this if PasteWarden says the key in the system credential store (Windows Credential Manager, macOS Keychain) is missing: then register your secrets again.
ui-desktop-secrets-forget-confirm = Clear them all
ui-desktop-section-scope = What is protected
ui-desktop-section-scope-desc = Different ways of pasting get different protection. The table follows the protection status above as it changes.
ui-desktop-scope-caption = Which protection covers each way of pasting
ui-desktop-scope-col-method = Way of pasting
ui-desktop-scope-col-copy = When copied (malicious commands cleared)
ui-desktop-scope-col-confirm = Confirm before paste (secrets)
ui-desktop-scope-cell-covered = Covered
ui-desktop-scope-cell-partial = Limited right now
ui-desktop-scope-cell-not-covered = Not covered
ui-desktop-scope-cell-unavailable = Unavailable right now
ui-desktop-scope-method-keyboard = Keyboard ({ $platform ->
        [macos] Cmd+V
       *[other] Ctrl+V
    })
ui-desktop-scope-method-context-menu = Right-click → Paste
ui-desktop-scope-method-edit-menu = An app's Edit → Paste
ui-desktop-scope-method-drag-drop = Drag and drop
ui-desktop-scope-method-remote-desktop = Remote desktop clipboard sync
ui-desktop-scope-method-elevated = Into an administrator window
ui-desktop-scope-method-secure-input = While Secure Input is on
ui-desktop-scope-method-middle-click = Middle click (PRIMARY selection)
ui-desktop-scope-note-commands = Malicious commands are cleared the moment you copy them. The clipboard is already empty, so nothing gets pasted, however you paste.
ui-desktop-scope-note-secrets = Confirm-before-paste for secrets only works for keyboard pastes. If you paste a secret with the right-click menu, a menu or drag and drop, PasteWarden won't ask first.
ui-desktop-scope-note-elevated = Administrator windows still have some protection: malicious commands are cleared when copied and entry warnings still appear. Only confirm-before-paste for secrets can't reach them.
ui-desktop-section-limits = { $platform ->
        [windows] Known limits on Windows
        [macos] Known limits on macOS
       *[other] Known limits on Linux
    }
ui-desktop-limits-windows-1 = Windows running as administrator don't receive PasteWarden's key interception, so pasting a secret into them won't ask first.
ui-desktop-limits-windows-2 = If you paste right after copying, PasteWarden waits for the check to finish (up to 2 seconds). If it takes longer, the paste is dropped and you get a notice.
ui-desktop-limits-macos-1 = PasteWarden checks the clipboard every 250 ms. A Cmd+V within that time of copying may get through.
ui-desktop-limits-macos-2 = While an app has Secure Input on (a password field, Terminal's Secure Keyboard Entry), pastes can't be intercepted.
ui-desktop-limits-macos-3 = After every PasteWarden update, remove the old entry under Accessibility and add it again, or paste interception stays off.
ui-desktop-limits-linux-1 = This version doesn't intercept pastes on Linux. It clears malicious commands when copied and notifies you.
ui-desktop-limits-linux-2 = The PRIMARY selection used by middle click is not monitored. Password managers such as KeePassXC also put passwords there, and a middle click pastes them.
ui-desktop-limits-linux-3 = GNOME doesn't let apps read the clipboard in the background; use the browser extension instead.
ui-desktop-limits-linux-4 = On Wayland, when the foreground window isn't available, entry warnings and the allowlist are off.
ui-desktop-section-appearance = Appearance and language
ui-desktop-section-appearance-desc = Follows your system by default; you can pick one yourself.
ui-desktop-section-about = About
ui-desktop-about-version = PasteWarden { $version }
ui-desktop-about-privacy = No usage data, no crash reports, and clipboard content never goes online.

## Secret kinds (confirmation)
ui-desktop-kind-national-id = National ID number
ui-desktop-kind-resident-certificate = Resident certificate number
ui-desktop-kind-business-id = Business ID number
ui-desktop-kind-credit-card = Credit card number
ui-desktop-kind-mobile-phone = Mobile number
ui-desktop-kind-api-key = API key or private key
ui-desktop-kind-registered = A secret you registered
ui-desktop-kind-phone-number = Phone number
ui-desktop-kind-bank-account = Bank account number
ui-desktop-kind-mnemonic = Wallet recovery phrase
ui-desktop-kind-other = Other secret

## Paste confirmation
ui-desktop-confirm-title = The clipboard holds a secret
ui-desktop-confirm-desc = What you're about to paste contains a secret. What should PasteWarden do?
ui-desktop-confirm-desc-target = What you're about to paste into { $target } contains a secret. What should PasteWarden do?
ui-desktop-confirm-kinds = Found
ui-desktop-confirm-preview = Masked preview
ui-desktop-confirm-keys = Enter or Esc cancels and pastes nothing.
ui-desktop-confirm-cancel = Cancel
ui-desktop-confirm-masked = Paste masked
ui-desktop-confirm-original = Paste original
ui-desktop-confirm-waiting = No paste is waiting for confirmation.

## First-run onboarding
ui-desktop-onboarding-title = Welcome to PasteWarden
ui-desktop-onboarding-progress = Step { $step } of { $total }
ui-desktop-onboarding-next = Next
ui-desktop-onboarding-back = Back
ui-desktop-onboarding-welcome-title = Welcome to PasteWarden
ui-desktop-onboarding-welcome-1 = PasteWarden checks what you copy in the background. Malicious commands that a web page tricks you into copying are cleared the moment you copy them.
ui-desktop-onboarding-welcome-2 = When the clipboard holds an ID number, a credit card, an API key or a password you registered, a keyboard paste asks you first.
ui-desktop-onboarding-welcome-privacy = Every check runs on this computer. Clipboard content is never sent anywhere.
ui-desktop-onboarding-limits-title = First, what PasteWarden can't protect
ui-desktop-onboarding-limits-intro = PasteWarden only sees keyboard paste shortcuts. Right-click → Paste, an app's Edit → Paste, drag and drop, and remote desktop clipboard sync all get past it.
ui-desktop-onboarding-limits-commands = Malicious commands are not affected: they are cleared the moment you copy them, so nothing gets pasted, however you paste.
ui-desktop-onboarding-limits-secrets = But confirm-before-paste for secrets only works for keyboard pastes. Pasting a secret any other way won't ask you first.
ui-desktop-onboarding-limits-later = You can see this table again under “What is protected” in settings.
ui-desktop-onboarding-limits-ack = Got it
ui-desktop-onboarding-mac-accessibility-title = Let PasteWarden intercept pastes
ui-desktop-onboarding-mac-accessibility-why = To stop a Cmd+V and ask you first, macOS needs you to allow PasteWarden under Accessibility. PasteWarden only looks for the paste shortcut and doesn't record what you type.
ui-desktop-onboarding-mac-accessibility-without = You can skip this: PasteWarden still checks what you copy and notifies you, it just can't stop a paste.
ui-desktop-onboarding-mac-step-1 = Click the button below to open System Settings → Privacy & Security → Accessibility.
ui-desktop-onboarding-mac-step-2 = Find PasteWarden in the list and turn its switch on. If it isn't listed, click “+” and choose PasteWarden in the Applications folder.
ui-desktop-onboarding-mac-step-3 = Come back here. Once it works, this page shows “Permission granted”.
ui-desktop-onboarding-mac-granted = Permission granted. Paste interception is on.
ui-desktop-onboarding-done-title = All set
ui-desktop-onboarding-done-1 = PasteWarden stays in the system tray (the menu bar on macOS). Protection status, settings and registered secrets are in its menu.
ui-desktop-onboarding-done-2 = When protection is limited, the icon changes and settings explain why.
ui-desktop-onboarding-finish = Start using PasteWarden
