# Playground website (apps/web). Ids use the `ui-web-` prefix; must match zh-TW/ui-web.ftl.

ui-web-title = PasteWarden playground: check what you paste
ui-web-skip = Skip to the playground

## Header and navigation
ui-web-tagline = Clipboard guard
ui-web-nav-label = Main
ui-web-nav-playground = Playground
ui-web-nav-privacy = Privacy
ui-web-nav-download = Download
ui-web-nav-docs = Docs
ui-web-nav-github = GitHub
ui-web-prefs-label = Display preferences

## Hero
ui-web-hero-title = Paste anything. See what it really does.
ui-web-hero-lead = PasteWarden catches fake “verify you are human” commands, hidden characters and swapped wallet addresses on the way in, and stops IDs, API keys and seed phrases on the way out. Try the same engine right here.
ui-web-privacy-badge = Runs entirely in your browser. Nothing is uploaded.

## Playground
ui-web-playground-title = Playground
ui-web-input-label = Text to check
ui-web-input-placeholder = Paste a command, a message, a seed phrase…
ui-web-input-hint = Checked as you type. The text stays in this tab: it is not saved, sent, or put in the URL.
ui-web-clear = Clear
ui-web-chars = { $count ->
    [one] { $count } character
   *[other] { $count } characters
}
ui-web-elapsed = checked in { $ms } ms
ui-web-examples-title = Try an example
ui-web-examples-note = Every example is fake and harmless: commands only open the calculator or point at example.invalid, and the numbers, key and phrases are generated on this page.
ui-web-example-clickfix = Fake CAPTCHA (ClickFix)
ui-web-example-obfuscated = Obfuscated command
ui-web-example-pii = Personal data
ui-web-example-apikey = API key
ui-web-example-seed-valid = Seed phrase
ui-web-example-seed-invalid = Seed phrase, bad checksum
ui-web-example-clean = Ordinary text
ui-web-example-clickfix-note = A fake “I am not a robot” page asks you to press Win+R and paste this. It downloads a script and runs it.
ui-web-example-obfuscated-note = The same attack wrapped in four layers: ^ escapes, a Base64 -EncodedCommand, string concatenation and a string run as code. Watch the onion view peel them.
ui-web-example-pii-note = A Taiwan ID with a computed check digit, a mobile number and a card number that passes the Luhn check. All made up.
ui-web-example-apikey-note = A GitHub-style token generated from a fixed seed. It has never existed anywhere else.
ui-web-example-seed-valid-note = Twelve BIP-39 words whose checksum is correct, so they could be a real wallet's recovery phrase. This one is derived from a public label: never send funds to it.
ui-web-example-seed-invalid-note = The same words with a different last word. The checksum no longer matches, so it is just a list of English words and PasteWarden stays quiet.
ui-web-example-clean-note = Normal text should pass without any fuss.

## Results
ui-web-results-title = Result
ui-web-loading = Loading the detection engine…
ui-web-engine-error = The detection engine could not be loaded in this browser. Try reloading the page or using a current browser.
ui-web-empty-title = Nothing to check yet
ui-web-empty-body = Paste some text above or pick an example. The verdict, the reasons and the onion view appear here.
ui-web-copy-masked = Copy masked text
ui-web-copied = Masked text copied.
ui-web-copy-failed = Could not copy. Select the text in the preview and copy it yourself.

## Privacy
ui-web-privacy-title = Privacy you can check
ui-web-privacy-lead = A tool that reads your clipboard has to earn trust. This page is built so you do not have to take our word for it.
ui-web-privacy-local-title = Runs on your device
ui-web-privacy-local-body = The detection engine is compiled to WebAssembly and runs in this tab. Analysis works with the network unplugged.
ui-web-privacy-none-title = Nothing leaves the page
ui-web-privacy-none-body = No analytics, no cookies, no fonts or scripts from other sites. The page's security policy only allows requests to its own address, and it makes none after loading.
ui-web-privacy-open-title = Open source
ui-web-privacy-open-body = The engine, the rules and this page are MIT-licensed on GitHub. Open your browser's developer tools, go to the Network tab, and watch it stay empty while you type.

## Download
ui-web-download-title = Get PasteWarden
ui-web-download-lead = The browser extension guards your clipboard on every site. Builds are published on GitHub Releases; the install guides walk you through each step.
ui-web-dl-chrome = Chrome and Edge
ui-web-dl-chrome-desc = Extension (Manifest V3). Blocks malicious commands the moment a page writes them to your clipboard.
ui-web-dl-firefox = Firefox
ui-web-dl-firefox-desc = The same extension for Firefox.
ui-web-dl-userscript = Userscript
ui-web-dl-userscript-desc = For Tampermonkey or Violentmonkey, when you cannot install extensions.
ui-web-dl-desktop = Desktop app
ui-web-dl-desktop-desc = Windows, macOS and Linux: guards the system clipboard everywhere, not only in the browser.
ui-web-dl-guide = Install guide
ui-web-dl-soon = Coming soon
ui-web-dl-releases = All releases on GitHub

## Footer
ui-web-footer-license = MIT License
ui-web-footer-engine = Engine { $version } · { $backend }
ui-web-backend-wasm = WebAssembly
ui-web-backend-wasm2js = JavaScript fallback
ui-web-external = (opens GitHub)
