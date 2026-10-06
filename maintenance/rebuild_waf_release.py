"""Surgically update the WAF installer in a verified release archive."""
import copy
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import zipfile
from patch_waf_cpath import patch

d = Path(sys.argv[1])
p = d / 'bt-clean-20260617.tar.gz'
original = p.read_bytes()
assert hashlib.sha256(original).hexdigest() == (d / 'SHA256SUMS').read_text().split()[0]
out = io.BytesIO()
changed = []
with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as src, tarfile.open(fileobj=out, mode='w:gz') as dst:
    for member in src.getmembers():
        data = src.extractfile(member).read() if member.isfile() else None
        if member.name == 'panel6_clean.zip':
            packed = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(packed, 'w') as zout:
                for info in zin.infolist():
                    content = zin.read(info)
                    if info.filename == 'install/local_waf.sh':
                        content = patch(content)
                        assert patch(content) == content
                        (d / 'local_waf.sh').write_bytes(content)
                        changed.append(info.filename)
                    zout.writestr(info, content)
            data = packed.getvalue()
        info = copy.copy(member)
        if data is not None:
            info.size = len(data)
        dst.addfile(info, io.BytesIO(data) if data is not None else None)
assert changed == ['install/local_waf.sh']
backup = p.with_name(p.name + '.before-cpath')
assert not backup.exists(), 'Do not overwrite rollback archive'
backup.write_bytes(original)
p.write_bytes(out.getvalue())
digest = hashlib.sha256(out.getvalue()).hexdigest()
(d / 'SHA256SUMS').write_text(f'{digest}  {p.name}\n', encoding='ascii')
print(digest)
