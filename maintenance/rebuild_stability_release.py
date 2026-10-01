"""Patch only the CPU guard inside an existing, checksum-verified release."""
import argparse
import copy
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from patch_nginx_stability import patch


def rebuild(directory):
    archive = directory / 'bt-clean-20260617.tar.gz'
    original = archive.read_bytes()
    checksum = (directory / 'SHA256SUMS').read_text().split()[0]
    assert hashlib.sha256(original).hexdigest() == checksum, 'Input checksum mismatch'
    output = io.BytesIO()
    changes = 0
    with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as src, tarfile.open(fileobj=output, mode='w:gz') as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else None
            if member.name == 'panel6_clean.zip':
                packed = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(data)) as panel, zipfile.ZipFile(packed, 'w') as target:
                    for entry in panel.infolist():
                        content = panel.read(entry)
                        if entry.filename == 'script/bt_cpu_guard.sh':
                            content = patch(content.decode('utf-8')).encode('utf-8')
                            assert patch(content.decode()) == content.decode(), 'Not idempotent'
                            (directory / 'bt_cpu_guard.sh').write_bytes(content)
                            changes += 1
                        target.writestr(entry, content)
                data = packed.getvalue()
            info = copy.copy(member)
            if data is not None:
                info.size = len(data)
            dst.addfile(info, io.BytesIO(data) if data is not None else None)
    assert changes == 1
    backup = archive.with_suffix(archive.suffix + '.before-stability')
    if not backup.exists():
        backup.write_bytes(original)
        (directory / 'SHA256SUMS.before-stability').write_text((directory / 'SHA256SUMS').read_text())
    archive.write_bytes(output.getvalue())
    digest = hashlib.sha256(output.getvalue()).hexdigest()
    (directory / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    rebuild(parser.parse_args().directory)
