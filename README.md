# bt-clean-panel

## Current Release

`v20261025-panel-loader` fixes a JavaScript syntax error in the shared panel
PHP-version helper that prevented panel dependencies from loading correctly.
The release updates the helper and the plugin-frame cache version only; it
preserves the existing Nginx and WAF protections.

Use the release assets together, including `SHA256SUMS`. The archive filename
remains `bt-clean-20260617.tar.gz` for compatibility with the installer.

```sh
curl -fL https://github.com/maomao5813646-ux/bt-clean-panel/releases/latest/download/install.sh -o install.sh
sudo env BT_CLEAN_BASE_URL=https://github.com/maomao5813646-ux/bt-clean-panel/releases/latest/download bash install.sh
```

These commands perform an installation; they are not an in-place repair command
for an existing production server. Back up existing installations first.

See `maintenance/PANEL_LOADER.md` for the patch scope and verification commands.
