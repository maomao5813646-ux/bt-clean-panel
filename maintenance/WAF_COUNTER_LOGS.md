# WAF counters and log rotation

All ten WAF shared-dictionary increments now use a numeric-result wrapper.
If incrementing fails, use the existing numeric count, or zero when no usable
count exists. This prevents nil comparisons from aborting requests. It does
not solve shared-memory exhaustion itself: affected counters may undercount
while memory is unavailable. Independent WAF rules remain enabled.

Nginx access/error logs are checked every ten minutes via the existing
logrotate timer. The 200 MB maxsize is a rotation trigger, not a hard size cap.
Archives use second-resolution names and fast compression. Rotation renames
the file and asks Nginx to reopen logs, avoiding copytruncate's copy cost and
write-loss window. Retention is bounded by 168 archives and maxage 7 days;
high-volume sites may retain less than seven days. Existing archives using
older names are preserved and may need separate retention management.

The release builder preserves all prior whitelist and no-site_total fixes,
verifies the exact changed archive entries, and emits Lua syntax/behavior
fixtures and shell syntax fixtures for validation. A complete fresh-server
installation is not exercised by these tests.
