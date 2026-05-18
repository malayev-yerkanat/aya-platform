# AYA Collection Modal Reload Bug Report

Date: 2026-05-18

## Live Verification

Live URL tested:

```text
https://aya-platform-ruddy.vercel.app/
```

## Reproduction

The bug reproduces on the deployed Vercel site.

Steps observed:

1. Open `https://aya-platform-ruddy.vercel.app/`.
2. Wait for the platform to finish loading.
3. The collection creation modal appears automatically.
4. Refresh the page.
5. The modal appears automatically again.

## Modal That Appears

The modal is the **“Новая коллекция” / New collection** modal, not the regular “save to collection” picker.

Visible overlay element:

```text
#create-coll-overlay
```

Other collection overlays at the same time:

```text
#coll-picker-overlay: hidden
#coll-detail-overlay: hidden
```

## Console

Chrome MCP reported no console warnings or errors during the live-page checks.

## URL State

No query string or hash appears to be involved:

```text
search: ""
hash: ""
```

## Storage Observations

Chrome MCP did not expose readable `localStorage` / `sessionStorage` from the evaluated page context in this run. The observed modal behavior does not appear to require a query/hash trigger.

The live DOM inspection showed the problematic overlay itself is present and visible on load.

## DOM Observation

For `#create-coll-overlay`, the live page reports:

```text
inline style: display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1300;align-items:center;justify-content:center
computed display: block
```

This means the element is visually active on load even though its inline style intends to hide it.

## Current Hypothesis Before Code Fix

The issue is most likely caused by fragile modal hiding logic around `#create-coll-overlay` rather than a user-triggered click path.

The safest fix is to add an explicit startup modal reset for AYA overlays and make the create-collection overlay hidden with `display: none !important` at startup/close, while preserving normal `openCreateCollection()` behavior.

## Fix Status

Fixed locally in `aya-platform.html`.

## Code Cause Found

The create-collection modal depended on fragile inline display switching:

```js
document.getElementById('create-coll-overlay').style.display = 'flex';
document.getElementById('create-coll-overlay').style.display = 'none';
```

The deployed DOM showed that this was not strong enough to guarantee a hidden startup state for `#create-coll-overlay`.

## Fix Applied

Added a single controlled helper:

```js
function setCreateCollectionModalOpen(isOpen) {
  const overlay = document.getElementById('create-coll-overlay');
  if (!overlay) return;
  overlay.style.setProperty('display', isOpen ? 'flex' : 'none', 'important');
  overlay.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
}
```

Added startup reset:

```js
function resetCreateCollectionModalOnStartup() {
  _fromPicker = false;
  _collPublicNew = false;
  setCreateCollectionModalOpen(false);
}
```

Called the reset at the beginning of `restoreSession()`.

Updated `openCreateCollection()`, `closeCreateCollection()`, and `submitCreateCollection()` to use the helper.

Updated the static HTML for `#create-coll-overlay`:

```html
aria-hidden="true"
style="display:none!important;..."
```

## Local Verification After Fix

Tested locally at:

```text
http://localhost:3000/aya-platform.html
```

Results:

- Initial load: `#create-coll-overlay` computed display is `none`.
- Reload: `#create-coll-overlay` computed display remains `none`.
- `aria-hidden` remains `true` while closed.
- Other collection overlays remain hidden:
  - `#coll-picker-overlay`
  - `#coll-detail-overlay`
- Generic modal remains hidden:
  - `#modal-overlay`
- Console warnings/errors after local check: none.

## Deployment Note

The live Vercel site will continue showing the bug until the updated `aya-platform.html` is deployed.
