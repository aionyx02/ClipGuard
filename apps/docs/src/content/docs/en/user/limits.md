---
title: What is protected, and platform limits
description: Where the desktop app can't protect you, and the known limits on each platform.
sidebar:
  order: 15
---

PasteWarden's rule is simple: **whenever you might think you're protected and you aren't, you should be able to see it.** This page lists every case it can't cover. The desktop app's settings show the same table, and it follows the current protection status as it changes.

## Two kinds of protection

- **When copied**: PasteWarden checks the clipboard the moment you copy. Malicious commands (such as the ones a fake verification page asks you to paste into the Run dialog) are cleared right then. The clipboard is already empty, so **nothing gets pasted, however you paste**.
- **Confirm before paste**: when the clipboard holds a secret (an ID number, a credit card, an API key, a private key, a recovery phrase or a password you registered), PasteWarden asks before you paste: cancel, paste a masked version, or paste the original. This **only recognizes the keyboard paste shortcut**.

## Which ways of pasting are protected

| Way of pasting | When copied (malicious commands cleared) | Confirm before paste (secrets) |
|---|---|---|
| Keyboard (Ctrl+V on Windows and Linux, Cmd+V on macOS) | Covered | Covered (not on Linux, see below) |
| Right-click → Paste | Covered | **Not covered** |
| An app's Edit → Paste | Covered | **Not covered** |
| Drag and drop | Covered | **Not covered** |
| Remote desktop clipboard sync | Covered | **Not covered** |
| Into an administrator window (Windows) | Covered | **Not covered** |
| While Secure Input is on (macOS) | Covered | **Not covered** |
| Middle click (PRIMARY selection on Linux) | **Not covered** | **Not covered** |

In short: malicious commands are blocked however you paste, but **secrets only get a confirmation when you paste with the keyboard**. Pasting a secret with the right-click menu, a menu or drag and drop goes through without asking.

## Windows

- **Administrator windows**: windows running as administrator (an administrator terminal, for example) don't receive PasteWarden's key interception, so pasting a secret into them won't ask first. They aren't unprotected: malicious commands are still cleared when copied, and the warning when you open a terminal still appears. If the clipboard holds a secret and you switch to an administrator window, PasteWarden shows one notification.
- **Pasting right after copying**: PasteWarden waits for the check to finish, up to 2 seconds. If it takes longer, the paste is dropped and you get a notice.

## macOS

- **Accessibility permission**: to stop a Cmd+V and ask you first, macOS needs you to allow PasteWarden under **System Settings → Privacy & Security → Accessibility**. Without it PasteWarden still works, but only notifies you and can't stop a paste.
- **Allow it again after every update**: PasteWarden has no Apple Developer signature, so macOS treats each update as a different app and the old permission stops working, even if its switch still looks on. Add it again like this:
  1. Open **System Settings → Privacy & Security → Accessibility**.
  2. Select PasteWarden in the list and click **−** below it to remove it.
  3. Click **+**, choose PasteWarden in the Applications folder, and turn its switch on.
  4. Come back to PasteWarden; the protection status in settings returns to normal within a few seconds.
- **Secure Input**: password fields, Terminal's Secure Keyboard Entry and some password managers turn on Secure Input. While it's on no app receives keystrokes, so PasteWarden can't intercept pastes either. macOS doesn't say which app turned it on.
- **A window of about 250 ms**: PasteWarden checks the clipboard every 250 ms. A Cmd+V within that time of copying may get through.
- **Clipboard access prompts**: recent macOS versions may ask you every time PasteWarden reads the clipboard. In **System Settings → Privacy & Security**, set PasteWarden's clipboard access to “Always Allow”.

All of this is done in System Settings. **PasteWarden will never ask you to paste a command into a terminal.**

## Linux

- **No paste interception**: Wayland doesn't let apps intercept keys, and on X11 it would clash with your shortcut tools, so on Linux this version clears malicious commands when copied and notifies you, without confirm-before-paste.
- **The PRIMARY selection is not monitored**: selecting text puts it in PRIMARY, and a middle click pastes it. Password managers such as KeePassXC put passwords there too. PasteWarden doesn't check PRIMARY.
- **GNOME**: GNOME doesn't let apps read the clipboard in the background, so PasteWarden can't check it automatically there. Use “Check clipboard” in the tray menu, or install the browser extension.
- **COSMIC**: background clipboard access is off by default. Set the environment variable `COSMIC_DATA_CONTROL_ENABLED=1` and log in again.
- **XWayland**: if the desktop can only be monitored through XWayland, copies made in native Wayland apps may be missed.
- **Foreground window**: on Wayland, when the foreground window isn't available, entry warnings and the allowlist are off.
- **Registered secrets** need a Secret Service (such as GNOME Keyring or KWallet) to store the key. Without one you can't register secrets; PasteWarden won't fall back to writing the key to an ordinary file.

## Browser extension

With only the extension installed, protection stays inside browser tabs: blocking what pages write to the clipboard, and confirming before you paste a secret into a page. Apps outside the browser (terminals, the Run dialog, chat apps) need the desktop app. See [Features](../features/).
