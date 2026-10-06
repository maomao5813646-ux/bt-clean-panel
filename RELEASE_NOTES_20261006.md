# WAF CPU growth fix

The local WAF appended identical Lua native-module search paths on every request.
Long-lived workers could accumulate extremely large search paths and saturate CPU.
Make initialization idempotent while preserving all request filtering logic.

The panel installer archive now contains the corrected `install/local_waf.sh`.
Every other payload is unchanged from the October 3 recovery release. Existing
installations require the same change in both their live WAF and installer copy;
validate Lua and Nginx configuration, then gracefully reload Nginx. Do not run the
entire installer or restart Go merely to apply this narrow fix.

Regression test: `luajit maintenance/test_waf_cpath.lua panel/install/local_waf.sh`
executes only initialization 100,000 times and asserts a constant module path.
Previous recovery lifecycle fixes and security checks remain intact.
