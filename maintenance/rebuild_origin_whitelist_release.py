"""Patch only the WAF installer inside the verified preceding release."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import zipfile

EXPECTED = '4ee96d6cbc408a2b3d5fa248fe38557a59386896afd9f6bf00a125df374026cc'


def patch_installer(original, updated):
    text = original.decode('utf-8')
    assert 'def _origin_rules(' not in text
    sections = [
        ('    def _origin_rules(', '    def set_enable('),
        ('      <div class="waf-form-row" style="margin:16px 0">', '      <div class="waf-grid">'),
        ('  function originWhitelistRequest(', '  function setChecks('),
    ]
    for start, anchor in sections:
        addition = updated[updated.index(start):updated.index(anchor, updated.index(start))]
        assert text.count(anchor) == 1
        text = text.replace(anchor, addition + anchor, 1)
    return text.encode('utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raw = args.base.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    updated = (Path(__file__).parents[1] / 'panel/install/local_waf.sh').read_text(encoding='utf-8')
    args.output.mkdir(exist_ok=False)
    result = io.BytesIO()
    changed = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as src, tarfile.open(fileobj=result, mode='w:gz') as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else None
            if member.name == 'panel6_clean.zip':
                packed = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(packed, 'w') as zout:
                    for info in zin.infolist():
                        content = zin.read(info)
                        if info.filename == 'install/local_waf.sh':
                            content = patch_installer(content, updated)
                            changed.append(info.filename)
                        zout.writestr(info, content)
                data = packed.getvalue()
            entry = copy.copy(member)
            if data is not None:
                entry.size = len(data)
            dst.addfile(entry, io.BytesIO(data) if data is not None else None)
    assert changed == ['install/local_waf.sh']
    archive = args.output / args.base.name
    archive.write_bytes(result.getvalue())
    # Verify every packaged file, not just the resulting archive checksum.
    with tarfile.open(args.base) as old, tarfile.open(archive) as new:
        assert old.getnames() == new.getnames()
        for member in old.getmembers():
            if not member.isfile():
                continue
            a, b = old.extractfile(member).read(), new.extractfile(member.name).read()
            if member.name != 'panel6_clean.zip':
                assert a == b
                continue
            with zipfile.ZipFile(io.BytesIO(a)) as za, zipfile.ZipFile(io.BytesIO(b)) as zb:
                assert za.namelist() == zb.namelist()
                assert [n for n in za.namelist() if za.read(n) != zb.read(n)] == changed
                backend = zb.read(changed[0]).decode().split('cat > "$PLUGIN_DIR/local_waf_main.py" <<\'EOF\'\n')[1].split('\nEOF')[0]
                compile(backend, 'packaged_backend.py', 'exec')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
    (args.output / 'build-manifest.json').write_text(json.dumps({'base_sha256': EXPECTED, 'sha256': digest, 'changed_zip_entries': changed}, indent=2))
    for name in ['install.sh', 'bt-nginx-availability-check', 'bt-nginx-availability.service', 'bt-nginx-availability.timer']:
        shutil.copy2(args.base.parent / name, args.output / name)
    assert b'\r' not in (args.output / 'install.sh').read_bytes()
    print(json.dumps({'sha256': digest, 'changed': changed, 'unchanged_files_verified': True}))


if __name__ == '__main__':
    main()
