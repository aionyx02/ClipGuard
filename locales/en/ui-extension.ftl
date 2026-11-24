# Browser extension and userscript (apps/extension, apps/userscript). Ids use the `ui-ext-`
# prefix. The content-script strings (notice, toast) are single-line with plain variables.

## Written to the clipboard instead of a blocked command (must stay harmless when pasted)
ui-ext-clipboard-notice = [PasteWarden] Blocked: this website tried to put a command on your clipboard. Never paste commands from a website into the Run dialog, a terminal or PowerShell.

## Non-blocking notice on the page
ui-ext-toast-warn-title = Check before you paste
ui-ext-toast-warn-body = This site put something on your clipboard that looks risky.
ui-ext-toast-pastejack-title = This site changed what you copied
ui-ext-toast-pastejack-body = What is on your clipboard is not what you selected.
ui-ext-toast-dismiss = Dismiss
ui-ext-toast-brand = PasteWarden

## Popup
ui-ext-popup-status-on = Protecting this page
ui-ext-popup-status-off = Protection is off
ui-ext-popup-status-paused = Paused on { $host }
ui-ext-popup-status-unavailable = PasteWarden can't run on this page. Browser pages and extension stores are off-limits to extensions.
ui-ext-popup-page-stats = This page: { $blocked } blocked, { $warned } warnings
ui-ext-popup-engine = Engine: { $backend }
ui-ext-popup-toggle-enabled = Protection
ui-ext-popup-toggle-site = Pause on this site
ui-ext-popup-recent = Recent blocks
ui-ext-popup-recent-empty = Nothing blocked yet.
ui-ext-popup-recent-note = Only the site, time, kind and masked values are kept, never what you copied.
ui-ext-popup-clear = Clear
ui-ext-popup-settings = Settings
ui-ext-kind-command = Command blocked
ui-ext-kind-warning = Warning
ui-ext-kind-pastejack = Pastejacking
ui-ext-kind-secret = Secret paste

## Options page
ui-ext-options-title = PasteWarden settings
ui-ext-options-privacy = Everything runs in your browser. Nothing you copy or paste is sent anywhere.
ui-ext-options-protection = Protection
ui-ext-opt-enabled = Protection on
ui-ext-opt-enabled-desc = Turns every check below on or off.
ui-ext-opt-guard-writes = Block commands websites put on your clipboard
ui-ext-opt-guard-writes-desc = Fake "verify you are human" pages copy a command for you to paste into Run or a terminal. PasteWarden swaps it for a harmless notice.
ui-ext-opt-guard-paste = Confirm before pasting secrets
ui-ext-opt-guard-paste-desc = When you paste an ID number, card number or API key into a page, choose between the masked version and the original. Password fields are never touched.
ui-ext-opt-pastejack = Detect pastejacking
ui-ext-opt-pastejack-desc = Warns when a page changes or adds to the text you copy.
ui-ext-options-strictness = Strictness
ui-ext-opt-block-malicious = Block malicious commands
ui-ext-opt-block-malicious-desc = Off: only warn, and let the command through.
ui-ext-opt-warn-suspicious = Warn about suspicious commands
ui-ext-opt-warn-suspicious-desc = Commands that aren't clearly malicious but deserve a second look.
ui-ext-opt-detect-secrets = Detect secrets and personal data
ui-ext-opt-detect-secrets-desc = ID numbers, card numbers, API keys, private keys, recovery phrases.
ui-ext-opt-detect-hidden = Detect hidden characters
ui-ext-opt-detect-hidden-desc = Zero-width and text-direction characters that hide what text really says.
ui-ext-options-packs = Personal data packs
ui-ext-options-packs-desc = Which countries' ID and phone number formats to look for. Credit cards, IBAN, international phone numbers and API keys are always checked.
ui-ext-opt-packs-auto = Follow my browser languages
ui-ext-pack-universal = Universal
ui-ext-pack-tw = Taiwan
ui-ext-pack-cn = China
ui-ext-pack-jp = Japan
ui-ext-pack-kr = Korea
ui-ext-pack-hk = Hong Kong
ui-ext-pack-sg = Singapore
ui-ext-pack-us = United States
ui-ext-options-appearance = Language and appearance
ui-ext-options-appearance-desc = Warnings shown inside web pages follow your system's light or dark mode, not the page's.
ui-ext-options-allowlist = Allowed sites
ui-ext-options-allowlist-desc = PasteWarden does nothing on these sites, including their subdomains. Use it for internal tools you trust.
ui-ext-allowlist-label = Hostname
ui-ext-allowlist-placeholder = intranet.example.com
ui-ext-allowlist-add = Add
ui-ext-allowlist-remove = Remove { $host }
ui-ext-allowlist-empty = No sites yet.
ui-ext-allowlist-invalid = Enter a hostname such as intranet.example.com.
