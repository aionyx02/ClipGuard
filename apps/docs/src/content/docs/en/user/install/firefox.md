---
title: Firefox
description: Install PasteWarden in Firefox (xpi).
sidebar:
  order: 2
---

The Firefox build is published as an `.xpi` file on [GitHub Releases](https://github.com/aionyx02/paste-warden/releases).

:::caution[Before signing]
Mozilla signing (AMO unlisted) arrives in Phase 6. Until then the xpi is **unsigned**, and release Firefox can only load it temporarily: it is removed when the browser restarts.
:::

## Signed builds (from Phase 6)

1. Open the Releases page in Firefox and click `paste-warden-firefox.xpi`.
2. Firefox asks whether to install it. Click **Add**.
3. Pin PasteWarden from the extensions menu in the toolbar.

## Unsigned test builds

1. Download `paste-warden-firefox.xpi`.
2. Go to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on…** and pick the xpi.

Temporary add-ons disappear when Firefox restarts. Firefox Developer Edition and Nightly can install unsigned builds permanently after setting `xpinstall.signatures.required` to `false` in `about:config`; release Firefox ignores that setting.

## Permissions

Firefox may list "Access your data for all websites" as an optional permission. PasteWarden needs it to intercept clipboard writes, so turn it on in the add-on's Permissions tab. The [privacy promise](../../privacy/#extension-permissions) explains why.
