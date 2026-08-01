# Brand assets

- `logo.png` — the official Malanta mark (256×256 PNG), referenced by
  `.cursor-plugin/plugin.json`'s `logo` field and shown as the plugin's tile
  in the Cursor Marketplace and the Customize panel. Square and opaque, so it
  renders on both light and dark themes.
- `logo.svg` — the official Malanta wordmark (160×30 SVG), for documentation
  headers. Not used as the plugin logo: its 5:1 aspect ratio letterboxes in a
  square tile, and its fills are solid black, which disappears against
  Cursor's dark theme. Cursor fetches the logo as an image URL, so no CSS can
  recolor it.

Both are sourced from the Malanta website (`https://malanta.ai`). The SVG was
verified script-free (no `<script>`/`onload`/`foreignObject`) before
committing.

Cursor resolves a relative `logo` path to a `raw.githubusercontent.com` URL
built from the repository and commit SHA — it never reads the file from the
installed plugin directory. A plugin loaded from `~/.cursor/plugins/local`
therefore shows a generic placeholder rather than this logo, which is
expected and not a manifest error.

Owned by Malantai Ltd. Use of the mark is subject to Malanta's trademark
policy; this repository bundles it solely to identify the plugin's publisher
on the Cursor Marketplace.
