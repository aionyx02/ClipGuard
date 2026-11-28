---
title: Desktop (Phase 4)
description: Installing the Windows, macOS and Linux desktop app (in development).
sidebar:
  order: 4
---

The desktop app arrives in Phase 4 and protects places outside the browser: it clears suspicious commands from the clipboard and warns again when you open the Run dialog or a terminal. Either the extension or the desktop app works fully on its own; with both installed they talk to each other.

For what the desktop app can and can't protect, see [What is protected, and platform limits](../../limits/).

Install steps will appear here after release. One rule up front:

:::danger[Never paste a terminal command to install anything]
On macOS, the first time you open an app that Apple hasn't notarized yet, use the graphical route: **System Settings → Privacy & Security**, find the blocked app near the bottom, and click **Open Anyway**.

**PasteWarden's install instructions will never ask you to paste a command into a terminal.** "Paste this command to install or verify" is exactly how ClickFix attacks work. Be suspicious of any instructions like that, whoever they claim to come from.
:::
