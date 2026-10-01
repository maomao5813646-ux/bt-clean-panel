# Nginx stability repair (2026-10-01)

The CPU guard used to rewrite Nginx configuration on every `--light` cron run.
An unmarked `proxy_cache_key` could coexist with a newly inserted cache block,
causing duplicate directives. A failed configuration test does not itself prove
what stopped a running Nginx master.

This patch makes periodic runs validation-only, serializes maintenance with
`flock`, preserves unmarked site directives, and only inserts the managed cache
block when no `proxy_cache` or `proxy_cache_*` directive exists in the file.
Explicit full maintenance still performs its existing migrations and protection
updates. It is not a read-only operation and should not be used as a health check.

## Files

- `patch_nginx_stability.py`: idempotent, fail-closed patcher for known guard layouts.
- `test_stability.py`: repeated patch, standalone key, cache-off, custom cache,
  and new-cache fixtures. It executes only the extracted Python migration in a
  temporary directory, never the full shell script.
- `rebuild_stability_release.py`: verifies the input archive checksum and replaces
  only `script/bt_cpu_guard.sh` inside `panel6_clean.zip`; other entries are preserved.
- `../panel/script/bt_cpu_guard.sh`: exact guard shipped in the repaired release.
- `bt-nginx-availability-*`: optional recovery check and systemd units. These are
  not automatically enabled by the release installer. The check leaves running
  Nginx alone; only an absent master with valid configuration may be started.

## Verify

```sh
python3 maintenance/test_stability.py panel/script/bt_cpu_guard.sh
bash -n panel/script/bt_cpu_guard.sh
```

Back up the installed guard before replacing it. Validate with the actual BaoTa
binary and explicit prefix/config. Do not restart Go or use `systemctl nginx`.
No reload is needed when only changing the maintenance script.

For the optional recovery check, install the executable under `/usr/local/sbin/`
and the units under `/etc/systemd/system/`, validate the script, then enable the
timer. Stop `bt-nginx-availability.timer` before deliberately stopping Nginx for
maintenance. Invalid configuration is logged and never started automatically.

## Rollback

Restore the backed-up guard, not an old entire vhost directory. Disable the
availability timer before removing its units. The previous GitHub release is
retained; the new release is not an in-place replacement of its assets.
