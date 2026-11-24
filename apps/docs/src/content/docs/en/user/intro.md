---
title: What is PasteWarden?
description: The two directions PasteWarden guards, and how it complements antivirus software.
sidebar:
  order: 1
---

PasteWarden treats the clipboard as a trust boundary and guards both directions:

**What comes in**

- **ClickFix / FileFix**: a fake "I'm not a robot" page tells you to press Win+R (or open a terminal, or File Explorer's address bar) and paste a command it quietly put on your clipboard.
- **Pastejacking**: you select and copy harmless-looking text, and the page swaps the clipboard for something else.
- **Hidden characters**: zero-width characters, BiDi controls and homoglyphs make what you see differ from what you paste.
- **Wallet address swaps**: clipboard malware replaces the crypto address you copied with the attacker's.

**What goes out**

- Personal data (national ID numbers, phone numbers, card numbers…), API keys, private keys, seed phrases, and secrets you registered yourself, pasted into a web page or chat by mistake.

## How it works

The detection engine is written in Rust and compiled to WebAssembly that runs inside your browser. It peels obfuscation layer by layer (up to 5 layers) and returns one of three verdicts defined in the public [detection spec](../../dev/generated/detection-rules/):

| Verdict | Meaning | What the extension does |
|---|---|---|
| Safe | Nothing suspicious | Stays out of the way |
| Caution | Something looks off | Lets it through with a warning |
| Quarantined | Very likely an attack | Replaces the clipboard with a harmless notice and explains why |

## What it is not

PasteWarden is not antivirus: it doesn't scan files or watch program behaviour. It covers one step, moving an attacker's text into a place that runs it, and works alongside your antivirus.
