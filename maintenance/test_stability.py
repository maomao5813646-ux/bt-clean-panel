import contextlib
import io
from pathlib import Path
import re
import sys
import tempfile
from patch_nginx_stability import patch


def test_guard(path):
    source = path.read_text(encoding='utf-8')
    fixed = patch(source)
    assert patch(fixed) == fixed
    assert fixed.index('if [ "$MODE" = "--light" ]; then', fixed.index('# BT-CLEAN-READONLY')) < fixed.index('\nquarantine_usbnotify_persistence\n')
    func = fixed.split('patch_kuaipai_go_proxies() {', 1)[1]
    code = func.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    fixtures = {
        'standalone-key': 'proxy_cache_key "$scheme$host$request_uri";\n',
        'cache-off': 'proxy_cache off;\n',
        'custom-cache': 'proxy_cache my_cache;\nproxy_cache_key "$host$request_uri";\n',
        'new': '',
    }
    for name, directives in fixtures.items():
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rewrite = root / 'rewrite'
            rewrite.mkdir()
            conf = rewrite / 'fixture.conf'
            original = 'proxy_pass http://127.0.0.1:8090;\n' + directives + 'add_header X-Custom preserved;\nproxy_set_header X-Kuaipai-Proxy-Token token;\n'
            conf.write_text(original, encoding='utf-8')
            local_code = code.replace('/www/server/panel/vhost', root.as_posix())
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(local_code, '<cache-patcher>', 'exec'), {})
                first = conf.read_text()
                exec(compile(local_code, '<cache-patcher>', 'exec'), {})
            result = conf.read_text()
            assert first == result, name + ': repeated patch changed output'
            assert 'add_header X-Custom preserved;' in result
            for line in directives.splitlines():
                assert line in result
            assert len(re.findall(r'^\s*proxy_cache_key\s+', result, re.M)) <= 1, name
            assert result.count('CODEX-PUBLIC-GO-FLOOD-GUARD-START') == 1
            if name == 'new':
                assert result.count('CODEX-PUBLIC-MICROCACHE-START') == 1
            else:
                assert 'CODEX-PUBLIC-MICROCACHE-START' not in result
    print(str(path) + ': idempotency, custom directives, cache key/off/new fixtures PASS')


if __name__ == '__main__':
    for argument in sys.argv[1:]:
        test_guard(Path(argument))
