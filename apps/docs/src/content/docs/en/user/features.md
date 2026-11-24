---
title: Features
description: When the PasteWarden extension steps in and what you can do when it does.
sidebar:
  order: 10
---

## Intercepting clipboard writes

Pages can put content on your clipboard with `navigator.clipboard.writeText`, `document.execCommand('copy')` or the `copy` event. PasteWarden judges it at the moment it is written:

- **Quarantined**: the content is replaced with a harmless notice ("PasteWarden blocked a command this site put on your clipboard"), and the page shows a warning with the source URL, why it was blocked, and an expandable onion view. If you are sure the content is safe, choose "I'm sure it's safe, allow once".
- **Caution**: the content is written as usual, with a warning.
- **Safe**: PasteWarden stays out of the way.

Every frame is checked, including iframes embedded in the page.

## Onion view

Attack commands often hide behind several layers of obfuscation: `^` escapes, backticks, string concatenation, Base64, `-EncodedCommand`… The onion view lists the result of each layer in order; the innermost one is what would actually run. Any secrets inside are masked first.

## Confirming before pasting secrets

When you paste something containing secrets into a page (national ID numbers, card numbers, API keys, private keys, seed phrases…), PasteWarden stops and asks:

| Choice | Key | Result |
|---|---|---|
| Paste masked (default) | Enter | Secrets are replaced with masks like `A1*******9` |
| Paste original | Mouse, or Tab to it and press Space | Pasted unchanged |
| Cancel | Esc | Nothing is pasted |

"Paste original" can't be triggered with Enter on purpose, so hammering Enter never leaks a secret. Password fields are skipped; pasting a password there is the point.

## Pastejacking

When you select and copy text on a page, PasteWarden compares what you selected with what actually reached the clipboard. If they differ and the written content is suspicious, you get a warning.

## Appearance and language

The popup, settings page and in-page warnings follow your system's light/dark mode and language (Traditional Chinese, English). You can switch manually in settings. In-page warnings always follow the operating system, never the page's own colours, so a malicious page can't camouflage them.
