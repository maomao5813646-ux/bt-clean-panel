"""Check patch idempotence, JS syntax, behavior and archive change boundaries."""
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from patch_panel_loader import START, END, FIXED, patch_utils, patch_template


def unpack(path):
    with tarfile.open(path, 'r:gz') as archive:
        return {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}


def main():
    before, after = (unpack(p) for p in sys.argv[1:3])
    assert before.keys() == after.keys()
    assert [n for n in before if before[n] != after[n]] == ['panel6_clean.zip']
    with zipfile.ZipFile(io.BytesIO(before['panel6_clean.zip'])) as old, zipfile.ZipFile(io.BytesIO(after['panel6_clean.zip'])) as new:
        assert old.namelist() == new.namelist()
        changed = [n for n in old.namelist() if old.read(n) != new.read(n)]
        assert set(changed) == {'BTPanel/static/js/utils.min.js', 'BTPanel/templates/default/software.html'}
        raw = old.read('BTPanel/static/js/utils.min.js')
        fixed = new.read('BTPanel/static/js/utils.min.js')
        assert patch_utils(raw) == fixed and patch_utils(fixed) == fixed
        template = new.read('BTPanel/templates/default/software.html')
        assert patch_template(template) == template
        for invalid in [b'', fixed.replace(START.encode(), b'changed:function(c,o){')]:
            try:
                patch_utils(invalid)
            except ValueError:
                pass
            else:
                raise AssertionError('Unknown input accepted')
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'utils.js'
            p.write_bytes(fixed)
            subprocess.run(['node', '--check', str(p)], check=True)
            for name in ['BTPanel/static/js/software.js', 'BTPanel/static/js/software-legacy.js']:
                p = Path(directory) / ('loader.mjs' if name.endswith('/software.js') else 'legacy.js')
                p.write_bytes(new.read(name))
                subprocess.run(['node', '--check', str(p)], check=True)
            p = Path(directory) / 'behavior.js'
            p.write_text('const f=({' + FIXED + '}).get_php_version_token;\n' + '''
const tests=[['php-83',{},'83'],['PHP 8.1',{},'81'],['php',{versions:[{m_version:'8',version:'2'}]},'82'],['php',{version:'7.4'},'74'],['php',{version:'74'},'74'],['local_waf',{},''],['nginx',null,'']];
for(const [name,info,want] of tests){if(f(name,info)!==want)throw Error('Mismatch: '+name);}
console.log('7 PHP-token cases passed');
''', encoding='utf-8')
            subprocess.run(['node', str(p)], check=True)
    print('PASS: idempotence, unknown-layout rejection, JS syntax, behavior, exact archive scope')


if __name__ == '__main__':
    main()
