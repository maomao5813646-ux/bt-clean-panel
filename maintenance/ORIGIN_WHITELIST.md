# Origin Access Whitelist

The local WAF home screen now manages a source-address whitelist for TCP
ports 80 and 443. IPv4, IPv6 and CIDR entries are accepted, one per line.
Removing an entry and saving revokes its managed firewall exceptions.

This is an origin-firewall exception, not a WAF inspection bypass. It does
not change SSH, panel, Go ports, destination-IP exceptions or other rules.
Only rules tagged `bt-clean-origin-whitelist` belong to this feature.
Existing conflicting rules are rejected rather than taken over.

UFW must already be active. Writes are serialized with a file lock, both
UFW rule files are backed up under `panel/data/origin-whitelist-*`, and
failed updates restore those files and reload UFW. No Nginx or Go restart
is required. Broad all-address `/0` entries and malformed input are rejected.
Do not edit firewall rules concurrently from another tool during a save.

An empty whitelist does not mean the origin is fully locked down: existing
destination-IP exceptions, public application ports and other manually
managed rules remain in effect.

Validation:

```text
python maintenance/test_origin_whitelist.py
```

The release builder changes only `install/local_waf.sh` in the preceding
verified package, preserves all other packaged files and publishes a checksum.
Existing installations are not automatically upgraded by publishing a release.
