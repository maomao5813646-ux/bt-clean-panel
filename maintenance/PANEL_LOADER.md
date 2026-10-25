# Panel Plugin Loader Repair

The preceding release contained `for(var r=[c],e=0;if(o&&...)` in
`BTPanel/static/js/utils.min.js`. An `if` statement cannot appear in the loop's
condition. The browser rejected the entire shared script with
`Unexpected token 'if'`, affecting panel/plugin dependencies.

The repair moves metadata collection before a valid loop and changes the
shared-script query version in `templates/default/software.html`. It does not
change firewall rules, SSH authentication, Go applications, Nginx configuration,
or WAF blocking rules. Existing browsers should hard-refresh the panel.

## Build And Verify

The builder checks the preceding release's fixed SHA256 before modifying it.
It preserves every other tar/zip entry's contents and retains zip metadata.
Use a new output directory; never overwrite the old release archive.

```sh
python3 maintenance/rebuild_panel_loader_release.py /path/to/old/bt-clean-20260617.tar.gz /path/to/new-release
python3 maintenance/test_panel_loader.py /path/to/old/bt-clean-20260617.tar.gz /path/to/new-release/bt-clean-20260617.tar.gz
python3 maintenance/test_panel_loader_browser.py /path/to/new-release/bt-clean-20260617.tar.gz
```

Tests require Node.js; the browser smoke test additionally requires Python
Playwright and Chromium (Microsoft Edge on Windows). The browser test uses
the release's actual static assets and an isolated mocked plugin-status API.
It does not log in to a server or modify production settings.

The source snapshot under `panel/BTPanel/` must match the archive entries.
Retain previous release assets for rollback. Do not upload server credentials,
incident logs, or quarantined executables with a release.
