# Brand assets

- `logo.svg` — the official Malanta wordmark (160×30 SVG), the plugin's
  marketplace icon (referenced by `.cursor-plugin/plugin.json`'s `icon`
  field). Source of truth: the Malanta website
  (`https://malanta.ai`). Verified script-free (no `<script>`/`onload`/
  `foreignObject`) before committing.

Owned by Malantai Ltd. Use of the mark is subject to Malanta's trademark
policy; this repository bundles it solely to identify the plugin's
publisher on the Cursor Marketplace.

If Cursor requires a square raster icon instead of an SVG wordmark, the
256×256 PNG favicon from the same site can be used — swap the file here and
update the `icon` path in `.cursor-plugin/plugin.json`.
