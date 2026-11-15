# Disable bundled website statistics

New installs explicitly opt out of `site_total` before starting the panel.
The packaged SiteTotalService install, upgrade and start entry points return
without running or downloading the optional daemon. The installation hook
also stops/disables/masks any existing service and adds a systemd condition
guard. It does not change SSH credentials, firewall rules or application code.

The maintenance helper backs up the previous module, affected configuration,
service file and statistics directory under `/root/bt-disable-site-total-*`.
Only the site_total socket access-log directives are removed; ordinary logs
are retained. Nginx is tested before and after edits, and only smoothly
reloaded when needed. Configuration edits are restored on validation failure.
The daemon directory is moved to the backup and replaced by a stop marker.
Statistics history is retained in the backup, but website statistics stop
updating. Do not restore the daemon merely to clear an old service error.

Existing installations can run the verified helper as root:

```sh
python3 /www/server/panel/script/bt_disable_site_total.py
```

The package build verifies that all unrelated archive files are unchanged.
Unit tests cover blocked entry points, idempotence and access-log preservation.
Replacing this distribution with an upstream panel or manually removing the
policy can undo the opt-out; this is not a guarantee against arbitrary root
changes or a compromised host.
