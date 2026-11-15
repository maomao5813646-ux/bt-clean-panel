#!/usr/bin/env python3
"""Remove the optional statistics daemon without restarting websites."""
import ast
import datetime
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


def patch_module(text):
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SiteTotalService')
    methods = {n.name: n for n in service.body if isinstance(n, ast.FunctionDef)}
    for name in ('install', 'upgrade', 'start'):
        assert name in methods, 'Unexpected statistics module layout'
    for name in sorted(('install', 'upgrade', 'start'), key=lambda n: methods[n].body[0].lineno, reverse=True):
        index = methods[name].body[0].lineno - 1
        if 'bt-clean: site_total disabled' in lines[index]:
            continue
        value = '""' if name == 'upgrade' else 'False'
        lines.insert(index, '        return ' + value + '  # bt-clean: site_total disabled\n')
    result = ''.join(lines)
    compile(result, 'free_site_total.py', 'exec')
    return result


def clean_config(text):
    # Only the statistics socket logger is removed; ordinary access logs remain.
    return ''.join(line for line in text.splitlines(keepends=True) if not re.fullmatch(
        r'\s*access_log\s+syslog:server=unix:/tmp/site_total\.sock[^;]*;\s*', line))


def run(args, check=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=40)
    if check and p.returncode:
        raise RuntimeError(' '.join(args) + ': ' + p.stdout[-1200:])
    return p


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    panel = Path('/www/server/panel')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = Path('/root/bt-disable-site-total-' + stamp)
    backup.mkdir(mode=0o700)
    changed = []

    def save(path):
        dest = backup / str(path).lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        changed.append((path, dest))

    module = panel / 'mod/base/free_site_total/__init__.py'
    edits = []
    if module.exists():
        original = module.read_text()
        replacement = patch_module(original)
        if replacement != original:
            edits.append((module, replacement))
    for root in (panel / 'vhost/nginx', Path('/www/server/nginx/conf')):
        if not root.exists():
            continue
        for path in root.rglob('*.conf'):
            if path.is_symlink() or any('backup' in part.lower() or part.lower().startswith('bak') for part in path.relative_to(root).parts):
                continue
            original = path.read_text(errors='surrogateescape')
            replacement = clean_config(original)
            if replacement != original:
                edits.append((path, replacement))
    binary = Path('/www/server/nginx/sbin/nginx.real_btclean')
    if not binary.exists():
        binary = Path('/www/server/nginx/sbin/nginx')
    nginx = [str(binary), '-p', '/www/server/nginx/', '-c', '/www/server/nginx/conf/nginx.conf']
    masters = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.joinpath('cmdline').read_bytes().startswith(b'nginx: master process'):
                masters.append(proc.name)
        except OSError:
            pass
    if binary.exists():
        run(nginx + ['-t'])
    try:
        for path, text in edits:
            save(path)
            path.write_text(text, errors='surrogateescape')
        if binary.exists():
            run(nginx + ['-t'])
            if masters and any(p.suffix == '.conf' for p, _ in edits):
                run(nginx + ['-s', 'reload'])
    except Exception:
        for path, dest in reversed(changed):
            shutil.copy2(dest, path)
        if masters:
            run(nginx + ['-t'])
            run(nginx + ['-s', 'reload'])
        raise
    unit = Path('/etc/systemd/system/site_total.service')
    if unit.exists() and not unit.is_symlink():
        save(unit)
    run(['systemctl', 'stop', 'site_total.service'], check=False)
    run(['systemctl', 'disable', 'site_total.service'], check=False)
    if run(['systemctl', 'is-active', 'site_total.service'], check=False).stdout.strip() == 'active':
        raise RuntimeError('Statistics service did not stop')
    if unit.exists() or unit.is_symlink():
        unit.unlink()
    unit.symlink_to('/dev/null')
    policy = panel / 'data/site_total.disabled'
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text('Disabled by bt-clean policy\n')
    dropin = Path('/etc/systemd/system/site_total.service.d')
    dropin.mkdir(exist_ok=True)
    (dropin / 'bt-clean-disabled.conf').write_text('[Unit]\nConditionPathExists=!/www/server/panel/data/site_total.disabled\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'reset-failed', 'site_total.service'], check=False)
    folder = Path('/www/server/site_total')
    # Match the executable path rather than killing similarly named processes.
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.readlink(proc / 'exe').split(' (deleted)')[0] == str(folder / 'site_total'):
                os.kill(int(proc.name), 15)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    time.sleep(2)
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.readlink(proc / 'exe').split(' (deleted)')[0] == str(folder / 'site_total'):
                raise RuntimeError('Statistics process still running; files retained')
        except (FileNotFoundError, PermissionError):
            pass
    if folder.exists():
        assert not folder.is_symlink()
        shutil.move(str(folder), str(backup / 'site_total-files'))
    folder.mkdir(exist_ok=True)
    (folder / 'stop_always.txt').write_text('1\n')
    print('BACKUP=' + str(backup))
    print('SERVICE=' + run(['systemctl', 'is-enabled', 'site_total.service'], check=False).stdout.strip())
    print('NGINX_MASTER_PIDS=' + ','.join(masters))
    print('PASS: statistics payload removed from live path; service masked; panel start/install/upgrade blocked')


if __name__ == '__main__':
    main()
