"""Validate firewall whitelist without changing the host firewall."""
import io
import re
import sys
import types
from pathlib import Path
from unittest.mock import patch

source = (Path(__file__).parents[1] / 'panel/install/local_waf.sh').read_text(encoding='utf-8')
backend = source.split('cat > "$PLUGIN_DIR/local_waf_main.py" <<\'EOF\'\n')[1].split('\nEOF')[0]
compile(backend, 'local_waf_main.py', 'exec')
sys.modules['public'] = types.SimpleNamespace(returnMsg=lambda ok, msg: {'status': ok, 'msg': msg})
sys.modules.setdefault('fcntl', types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=2, LOCK_NB=4))
namespace = {}
exec(backend, namespace)
plugin = namespace['local_waf_main']()
rules = []
calls = []
failure = [False]


def run(args, **kwargs):
    calls.append(args)
    command = args[1:]
    output = ''
    if command == ['show', 'added']:
        output = '\n'.join('ufw ' + ' '.join(r) for r in rules)
    elif command == ['status']:
        output = 'Status: active\n'
    elif command[:2] == ['--force', 'delete']:
        rules.remove(command[2:])
    elif command[0] == 'allow':
        if failure[0]:
            return types.SimpleNamespace(returncode=1, stdout='', stderr='injected failure')
        rules.append(command)
    return types.SimpleNamespace(returncode=0, stdout=output, stderr='')


class Lock(io.StringIO):
    def fileno(self):
        return 0


with patch('subprocess.run', run), patch('builtins.open', lambda *a, **k: Lock()), patch('tempfile.mkdtemp', return_value='/backup/test'), patch('shutil.copy2') as copy:
    for bad in ['0.0.0.0/0', '::/0', '1.2.3.4; reboot', 'bad-ip', '224.0.0.1']:
        assert plugin.save_origin_whitelist({'entries': bad})['status'] is False
    assert not calls, 'Invalid input must not run firewall commands'
    result = plugin.save_origin_whitelist({'entries': '192.0.2.7\n2001:db8::/64\n192.0.2.7'})
    assert result['status'] and len(rules) == 4, result
    assert plugin.get_origin_whitelist()['entries'] == ['192.0.2.7', '2001:db8::/64']
    assert all(r[r.index('port') + 1] in ('80', '443') for r in rules)
    count = len(calls)
    assert plugin.save_origin_whitelist({'entries': '192.0.2.7\n2001:db8::/64'})['status']
    assert not any('allow' in c for c in calls[count:])
    assert plugin.save_origin_whitelist({'entries': ''})['status'] and not rules
    failure[0] = True
    assert not plugin.save_origin_whitelist({'entries': '192.0.2.8'})['status']
    assert calls[-1] == ['/usr/sbin/ufw', 'reload']
    assert copy.call_count >= 6
print('PASS: syntax, invalid input, IPv4/IPv6, deduplication, ports, readback, idempotence, removal, rollback')
