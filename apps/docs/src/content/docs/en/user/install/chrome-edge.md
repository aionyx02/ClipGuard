---
title: Chrome / Edge
description: Load the PasteWarden extension in Chrome or Edge (unpacked).
sidebar:
  order: 1
---

PasteWarden is not listed in the Chrome Web Store. You download it from GitHub Releases and load it yourself, so every version can be matched to its source code and build log.

:::caution[In development]
The extension is being built in Phase 3. Until the first release, the Releases page may not have the file yet.
:::

## Steps

1. Download the latest `paste-warden-chrome.zip` from [GitHub Releases](https://github.com/aionyx02/paste-warden/releases).
2. **Extract** the zip into a folder you will keep, for example `Documents/PasteWarden`. The browser keeps loading the extension from that folder.
3. Go to `chrome://extensions` (Edge: `edge://extensions`).
4. Turn on **Developer mode** (top right; bottom left in Edge).
5. Click **Load unpacked** and pick the extracted folder, the one that contains `manifest.json`.
6. PasteWarden now appears in the list. Pin it to the toolbar from the puzzle-piece menu.

## Updating

Download the new zip, extract it over the same folder, then press the reload button on PasteWarden's card on the extensions page.

## FAQ

**Chrome keeps asking me to disable developer-mode extensions.** Chrome shows this for every extension you load yourself. Choose "Keep".

**Which permissions does it need?** See the [privacy promise](../../privacy/#extension-permissions).
