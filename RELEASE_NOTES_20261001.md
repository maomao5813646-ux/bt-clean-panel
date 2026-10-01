# Nginx maintenance stability

- Make `bt_cpu_guard.sh --light` validation-only: no site rewrites, rollback,
  service restart, or reload during periodic checks.
- Serialize guard maintenance with a dedicated lock.
- Avoid duplicate `proxy_cache_key` insertion when any existing cache directive
  is present; preserve unmarked site-specific directives.
- Preserve all other release files and existing protection logic.
- Include source, surgical patcher, regression tests, and optional availability
  checker in the Git repository. Recovery units are not auto-installed by this
  release.

Validated shell syntax and a production validation-only invocation. Regression
fixtures cover repeated execution, existing cache keys, disabled cache, custom
cache, and initial cache creation. The full installer was not run against
production. Existing sites and Go processes were not restarted for this repair.

The archive retains its legacy filename for bootstrap compatibility. Use the
SHA256SUMS distributed with this release. The previous release remains available
for rollback. No claim is made that all possible causes of downtime are removed.
