"""Build a narrowly patched archive from the verified preceding release."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile
from patch_panel_loader import patch_utils, patch_template

EXPECTED = 'fab6e1aff9ee587e6c9d406afaa9a4c071312b43b73ed9d1bb41a8e0f82f0011'
PATCHES = {
    'BTPanel/static/js/utils.min.js': patch_utils,
    'BTPanel/templates/default/software.html': patch_template,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    original = args.input.read_bytes()
    if hashlib.sha256(original).hexdigest() != EXPECTED:
        raise ValueError('Input is not the verified v20261006-waf-cpath archive')
    args.output.mkdir(exist_ok=False)
    changed = []
    result = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as source, tarfile.open(fileobj=result, mode='w:gz') as target:
        for member in source.getmembers():
            data = source.extractfile(member).read() if member.isfile() else None
            if member.name == 'panel6_clean.zip':
                packed = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(packed, 'w') as zout:
                    for info in zin.infolist():
                        content = zin.read(info)
                        if info.filename in PATCHES:
                            patch = PATCHES[info.filename]
                            content = patch(content)
                            assert patch(content) == content
                            dest = Path(__file__).resolve().parents[1] / 'panel' / info.filename
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            dest.write_bytes(content)
                            changed.append(info.filename)
                        zout.writestr(info, content)
                data = packed.getvalue()
            info = copy.copy(member)
            if data is not None:
                info.size = len(data)
            target.addfile(info, io.BytesIO(data) if data is not None else None)
    assert set(changed) == set(PATCHES)
    archive = args.output / args.input.name
    archive.write_bytes(result.getvalue())
    digest = hashlib.sha256(result.getvalue()).hexdigest()
    (args.output / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    (args.output / 'build-manifest.json').write_text(json.dumps({'base_sha256': EXPECTED, 'sha256': digest, 'changed_zip_entries': changed}, indent=2))
    print(json.dumps({'sha256': digest, 'changed': changed}))


if __name__ == '__main__':
    main()
