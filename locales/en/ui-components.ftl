# Shared React components (packages/ui). Ids use the `ui-comp-` prefix so they never collide
# with the extension / web strings in ui.ftl.

## VerdictCard

ui-comp-action-allow = Safe
ui-comp-action-warn = Caution
ui-comp-action-quarantine = Quarantined
ui-comp-action-allow-desc = Nothing suspicious found.
ui-comp-action-warn-desc = Something here looks off. Double-check before you use it.
ui-comp-action-quarantine-desc = This is very likely an attack. PasteWarden stopped it.
ui-comp-verdict-title = Verdict
ui-comp-level-label = Command verdict
ui-comp-level-none = None
ui-comp-level-suspicious = Suspicious
ui-comp-level-malicious = Malicious
ui-comp-risk-label = Risk score
ui-comp-risk-value = { $score } / 100
ui-comp-reasons-title = Why
ui-comp-reasons-empty = Nothing to explain.
ui-comp-hosts-title = The command connects to
ui-comp-hidden-title = Hidden characters
ui-comp-wallets = Contains { $count } wallet addresses
ui-comp-truncated = The text is too long; only the beginning was analyzed.

## OnionTrace

ui-comp-onion-title = Onion view
ui-comp-onion-subtitle = Peel the obfuscation layer by layer to see what the command really does.
ui-comp-onion-empty = This text is not obfuscated.
ui-comp-onion-layer = Layer { $n }
ui-comp-onion-next = Reveal next layer
ui-comp-onion-all = Reveal all
ui-comp-onion-replay = Replay
ui-comp-onion-progress = { $shown } of { $total } layers revealed
ui-comp-onion-announce = Layer { $n }, { $text }: { $preview }
ui-comp-onion-result = Innermost layer: what actually runs

## SecretList / MaskPreview

ui-comp-secrets-title = Secrets found
ui-comp-secrets-empty = No secrets found.
ui-comp-secrets-note = Only masked values are shown here.
ui-comp-secrets-rule = Rule
ui-comp-mask-title = Mask preview
ui-comp-mask-note = If you paste the masked version, this is all the other side sees.

## Preferences

ui-comp-pref-theme = Appearance
ui-comp-pref-theme-system = System
ui-comp-pref-theme-light = Light
ui-comp-pref-theme-dark = Dark
ui-comp-pref-language = Language
ui-comp-pref-language-system = System
ui-comp-pref-language-zh-TW = 繁體中文
ui-comp-pref-language-en = English
