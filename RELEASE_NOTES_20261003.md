# Nginx recovery lifecycle correction

Fix an error in the optional Nginx recovery mechanism introduced on October 1:
the oneshot service's default control-group cleanup could terminate the Nginx
master it had just started. Set `KillMode=process` for this short-lived check and
close the two maintenance lock descriptors before launching detached Nginx.

The existing periodic CPU guard fix remains unchanged. The installer archive is
byte-identical to the October 1 stability release: optional recovery units are
not installed by that archive. Corrected recovery files are available separately
and in this release's Git source. Existing servers with the optional mechanism
need their service and check updated; merely installing the panel is not enough.

Before updating, back up both files and stop the timer (not Nginx). Validate the
shell script, install both files, run `systemctl daemon-reload`, and resume the
timer. Validate configuration with the BaoTa binary before recovering an absent
Nginx. Check that the master survives service completion and later timer cycles.
Never test recovery by stopping a healthy production Nginx unnecessarily.

The original cause of the first Nginx exit is not established by these recovery
logs. This fix addresses the confirmed repeated recovery/termination failure.
