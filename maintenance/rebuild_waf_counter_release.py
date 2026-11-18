"""Preserve the prior release while patching WAF counters and log rotation."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile

base, output = map(Path, sys.argv[1:])
expected = 'd77da30ac7105c88278c60eb6f307d10f63327e482ffce7492deed98ada91bdc'
assert hashlib.sha256(base.read_bytes()).hexdigest() == expected
repo = Path(__file__).parents[1]
local_waf = (repo / 'panel/install/local_waf.sh').read_text(encoding='utf-8')
guard = (repo / 'panel/script/bt_cpu_guard.sh').read_text(encoding='utf-8')
helper = local_waf.split("<<'EOF'\n-- A failed shared-memory", 1)[1].split('end\n\n', 1)[0]
helper = '-- A failed shared-memory' + helper + 'end\n\n'
rotation = guard[guard.index('setup_logrotate() {'):guard.index('setup_search_spider_ip_verification() {')]
output.mkdir(exist_ok=False)
result = io.BytesIO()
names = {'install/local_waf.sh', 'script/bt_cpu_guard.sh'}
with tarfile.open(base) as src, tarfile.open(fileobj=result, mode='w:gz') as dst:
    for member in src.getmembers():
        data = src.extractfile(member).read() if member.isfile() else None
        if member.name == 'panel6_clean.zip':
            packed = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(packed, 'w') as zout:
                for info in zin.infolist():
                    content = zin.read(info)
                    if info.filename == 'install/local_waf.sh':
                        text = content.decode()
                        anchor = '  cat > "$WAF_DIR/waf.lua" <<\'EOF\'\n'
                        assert text.count(anchor) == 1 and text.count('dict:incr(') == 10
                        text = text.replace('dict:incr(', 'safe_counter_incr(dict, ')
                        content = text.replace(anchor, anchor + helper).encode()
                        lua = content.decode().split(anchor)[1].split('\nEOF')[0]
                        (output / 'waf-test.lua').write_text(lua, encoding='utf-8', newline='\n')
                        (output / 'local-waf-syntax.sh').write_bytes(content)
                    elif info.filename == 'script/bt_cpu_guard.sh':
                        text = content.decode()
                        start, end = text.index('setup_logrotate() {'), text.index('setup_search_spider_ip_verification() {')
                        content = (text[:start] + rotation + text[end:]).encode()
                        (output / 'guard-syntax.sh').write_bytes(content)
                    zout.writestr(info, content)
            data = packed.getvalue()
        entry = copy.copy(member)
        if data is not None:
            entry.size = len(data)
        dst.addfile(entry, io.BytesIO(data) if data is not None else None)
archive = output / base.name
archive.write_bytes(result.getvalue())
with tarfile.open(base) as a, tarfile.open(archive) as b:
    assert a.getnames() == b.getnames()
    for member in a.getmembers():
        if not member.isfile():
            continue
        old, new = a.extractfile(member).read(), b.extractfile(member.name).read()
        if member.name != 'panel6_clean.zip':
            assert old == new
        else:
            with zipfile.ZipFile(io.BytesIO(old)) as za, zipfile.ZipFile(io.BytesIO(new)) as zb:
                assert za.namelist() == zb.namelist()
                assert {n for n in za.namelist() if za.read(n) != zb.read(n)} == names
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
(output / 'build-manifest.json').write_text(json.dumps({'base_sha256': expected, 'sha256': digest, 'changed_zip_entries': sorted(names)}, indent=2))
for name in ['install.sh', 'bt-nginx-availability-check', 'bt-nginx-availability.service', 'bt-nginx-availability.timer']:
    shutil.copy2(base.parent / name, output / name)
assert b'\r' not in (output / 'install.sh').read_bytes()
(output / 'counter-test.lua').write_text(helper + '''
local d = {incr=function() return 61 end, get=function() return nil end}
assert(safe_counter_incr(d, 'k', 1, 0, 10) == 61)
d.incr=function() return nil, 'no memory' end
assert(safe_counter_incr(d, 'k', 1, 0, 10) == 0)
d.get=function() return 75 end
assert(safe_counter_incr(d, 'k', 1, 0, 10) == 75)
d.get=function() return 'invalid' end
assert(safe_counter_incr(d, 'k', 1, 0, 10) == 0)
print('PASS: numeric, failed allocation, prior count and invalid value')
''', encoding='utf-8', newline='\n')
print('PASS: only two intended archive files changed; SHA256=' + digest)
