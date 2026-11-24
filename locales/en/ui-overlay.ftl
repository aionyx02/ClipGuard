# In-page warning layer (packages/overlay). Single-line messages with plain variables only:
# the overlay ships a tiny parser instead of @fluent/bundle to stay under its size budget.

ui-overlay-brand = PasteWarden
ui-overlay-blocked-title = Blocked a command this site put on your clipboard
ui-overlay-blocked-body = This site tried to put a command on your clipboard. That is a common fake-verification trick: it asks you to paste it into the Run dialog or a terminal. Your clipboard now holds a harmless notice instead.
ui-overlay-blocked-source = Source
ui-overlay-allow-once = I'm sure it's safe, allow once
ui-overlay-keep-blocked = Keep blocked
ui-overlay-reasons = Why it was blocked
ui-overlay-layers = Deobfuscation steps ({ $count })
ui-overlay-layer = Layer { $n }
ui-overlay-risk = Risk { $score } / 100
ui-overlay-paste-title = What you're pasting contains secrets
ui-overlay-paste-body = Found { $count } secret(s). Pasting the masked version is recommended.
ui-overlay-paste-masked = Paste masked
ui-overlay-paste-original = Paste original
ui-overlay-paste-cancel = Cancel
ui-overlay-paste-hint = Enter pastes the masked version, Esc cancels
ui-overlay-blocked-hint = Esc keeps it blocked
