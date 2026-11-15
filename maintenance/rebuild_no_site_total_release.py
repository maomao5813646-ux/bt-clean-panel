"""Build a narrowly scoped no-statistics release from a verified archive."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile

repo = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('disable', repo / 'panel/script/bt_disable_site_total.py')
disable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(disable)
base, output = map(Path, sys.argv[1:])
expected = 'f7d2e15b5dd10b5e105a73bf0943374f350a292dfa0b46a7c2face735bc7a0eb'
assert hashlib.sha256(base.read_bytes()).hexdigest() == expected
output.mkdir(exist_ok=False)
helper_name = 'script/bt_disable_site_total.py'
module_name = 'mod/base/free_site_total/__init__.py'
helper = (repo / 'panel' / helper_name).read_bytes().replace(b'\r\n', b'\n')
result = io.BytesIO()
with tarfile.open(base) as src, tarfile.open(fileobj=result, mode='w:gz') as dst:
    for member in src.getmembers():
        data = src.extractfile(member).read() if member.isfile() else None
        if member.name == 'panel6_clean.zip':
            packed = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(packed, 'w') as zout:
                assert helper_name not in zin.namelist()
                assert module_name in zin.namelist()
                for info in zin.infolist():
                    content = zin.read(info)
                    if info.filename == module_name:
                        content = disable.patch_module(content.decode()).encode()
                    zout.writestr(info, content)
                entry = zipfile.ZipInfo(helper_name)
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(entry, helper)
            data = packed.getvalue()
        elif member.name == 'install-ubuntu_6.0_clean.sh':
            text = data.decode()
            anchor = '\tunzip -o panel.zip -d ${setup_path}/server/panel/ > /dev/null 2>&1\n'
            assert text.count(anchor) == 1
            hook = '''	# Apply the statistics opt-out before starting the panel.
	if ! python3 "${setup_path}/server/panel/script/bt_disable_site_total.py"; then
		echo "ERROR: site_total disable policy failed; panel startup aborted"
		exit 1
	fi
'''
            data = text.replace(anchor, anchor + hook).encode()
        entry = copy.copy(member)
        if data is not None:
            entry.size = len(data)
        dst.addfile(entry, io.BytesIO(data) if data is not None else None)
archive = output / base.name
archive.write_bytes(result.getvalue())
with tarfile.open(base) as old, tarfile.open(archive) as new:
    assert old.getnames() == new.getnames()
    changes = [m.name for m in old.getmembers() if m.isfile() and old.extractfile(m).read() != new.extractfile(m.name).read()]
    assert set(changes) == {'panel6_clean.zip', 'install-ubuntu_6.0_clean.sh'}
    with zipfile.ZipFile(io.BytesIO(old.extractfile('panel6_clean.zip').read())) as a, zipfile.ZipFile(io.BytesIO(new.extractfile('panel6_clean.zip').read())) as b:
        assert set(b.namelist()) - set(a.namelist()) == {helper_name}
        assert [n for n in a.namelist() if a.read(n) != b.read(n)] == [module_name]
        code = b.read(module_name).decode()
        assert disable.patch_module(code) == code
        compile(code, module_name, 'exec')
        compile(b.read(helper_name), helper_name, 'exec')
    (output / 'installer-syntax-check.sh').write_bytes(new.extractfile('install-ubuntu_6.0_clean.sh').read())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
(output / 'build-manifest.json').write_text(json.dumps({'base_sha256': expected, 'sha256': digest, 'changed_tar_entries': changes, 'changed_zip_entries': [module_name], 'added_zip_entries': [helper_name]}, indent=2))
for name in ['install.sh', 'bt-nginx-availability-check', 'bt-nginx-availability.service', 'bt-nginx-availability.timer']:
    shutil.copy2(base.parent / name, output / name)
assert b'\r' not in (output / 'install.sh').read_bytes()
print('PASS: archive built; only opt-out module, helper and installer hook changed; sha256=' + digest)
