"""Surgical, idempotent patch for existing BaoTa CPU guard versions."""
import argparse
from pathlib import Path

MARKER = '# BT-CLEAN-READONLY-PERIODIC-V1'
ENTRY = '\nquarantine_usbnotify_persistence\nquarantine_known_mobile_redirect_backdoor\npurge_known_darkjump_artifacts\n'
PERIODIC = r'''
# BT-CLEAN-READONLY-PERIODIC-V1
# Scheduled checks must not rewrite site configuration or restart services.
exec 8>/run/lock/bt-cpu-guard-maintenance.lock
flock -n 8 || exit 0
if [ "$MODE" = "--light" ]; then
    check_nginx=/www/server/nginx/sbin/nginx.real_btclean
    [ -x "$check_nginx" ] || check_nginx=/www/server/nginx/sbin/nginx
    if "$check_nginx" -p /www/server/nginx/ -c /www/server/nginx/conf/nginx.conf -t; then
        exit 0
    fi
    logger -t bt-cpu-guard 'Nginx validation failed; running workers and site files left unchanged'
    exit 1
fi
'''


def patch(source):
    source = source.replace('\r\n', '\n')
    if MARKER in source:
        return source
    if source.count(ENTRY) != 1:
        raise ValueError('Unknown guard entry point; no changes made')
    cache_write = "            text = text.replace('proxy_pass http://bt_clean_kuaipai_backend;', 'proxy_pass http://bt_clean_kuaipai_backend;' + cache, 1)"
    lines = source.splitlines()
    found = 0
    for i, line in enumerate(lines):
        if line == cache_write:
            if (not lines[i - 1].startswith("        if root.name == 'rewrite'")
                    and not (lines[i - 1] == '        if is_public_rewrite:'
                             and lines[i - 2] == "        is_public_rewrite = root.name == 'rewrite' and not has_unmanaged_cache")):
                raise ValueError('Unknown cache insertion; no changes made')
            lines[i - 1] = r"        if root.name == 'rewrite' and not re.search(r'^\s*proxy_cache(?:_[a-z_]+)?\s+', text, flags=re.M):"
            found += 1
    if found != 1:
        raise ValueError('Expected one managed cache insertion')
    source = '\n'.join(lines) + '\n'
    # Do not delete unmarked user directives between proxy_pass and a header.
    start = source.find("        if root.name == 'rewrite':\n            text = re.sub(")
    if start != -1:
        end = source.find('\n        lines = text.splitlines(keepends=True)', start)
        if end == -1 or 'X-Kuaipai-Proxy-Token' not in source[start:end]:
            raise ValueError('Unknown legacy migration; no changes made')
        comment = source.rfind('        # Releases before 2026-08-30', 0, start)
        if comment != -1 and source[comment:start].count('\n') <= 4:
            start = comment
        source = source[:start] + '        # Preserve unmarked site directives during upgrades.\n' + source[end:]
    return source.replace(ENTRY, '\n' + PERIODIC + ENTRY)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    original = args.path.read_text(encoding='utf-8')
    candidate = patch(original)
    if candidate != original:
        backup = args.path.with_name(args.path.name + '.before-stability-20261001')
        if not backup.exists():
            backup.write_bytes(args.path.read_bytes())
        args.path.write_text(candidate, encoding='utf-8', newline='\n')
    print('Patched: ' + str(args.path))
