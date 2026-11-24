---
title: Userscript
description: Install the PasteWarden userscript with Violentmonkey or Tampermonkey.
sidebar:
  order: 3
---

If you'd rather not install the extension, or your browser can't run it (iOS Safari with the Userscripts app, for example), use the userscript. It does what the extension does inside web pages: intercepts clipboard writes, confirms before pasting secrets, and detects pastejacking.

## Steps

1. Install a userscript manager. [Violentmonkey](https://violentmonkey.github.io/) (open source) is recommended; Tampermonkey also works.
2. Open `paste-warden.user.js` from [GitHub Releases](https://github.com/aionyx02/paste-warden/releases).
3. The manager shows an install page. Check the source and click **Install**.

The manager then checks GitHub Releases for updates via `@updateURL`.

## Extra step in Chrome / Edge

Under Manifest V3, Chrome and Edge don't let extensions run userscripts by default. If the manager says scripts are not running, open the manager's **Details** on the extensions page and turn on **Allow user scripts** (older versions need Developer mode instead).

## Differences from the extension

- Settings live in the manager (`GM_setValue`) and don't sync with the extension.
- On sites with a very strict Content Security Policy the userscript falls back to a slower JavaScript build of the engine. Verdicts are identical.
- Don't enable both at once, or every event is checked twice.
