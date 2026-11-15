import importlib.util
from pathlib import Path

path = Path(__file__).parents[1] / 'panel/script/bt_disable_site_total.py'
spec = importlib.util.spec_from_file_location('disable', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source = '''class SiteTotalService:
    @classmethod
    def install(cls):
        raise RuntimeError('must not install')
    @classmethod
    def upgrade(cls):
        raise RuntimeError('must not upgrade')
    def start(self):
        raise RuntimeError('must not start')
    def unrelated(self):
        return 42
'''
patched = module.patch_module(source)
assert module.patch_module(patched) == patched
namespace = {}
exec(patched, namespace)
service = namespace['SiteTotalService']()
assert service.start() is False
assert service.install() is False
assert service.upgrade() == ''
assert service.unrelated() == 42
config = 'access_log /www/wwwlogs/site.log;\naccess_log syslog:server=unix:/tmp/site_total.sock,nohostname,tag=1__access site_total;\nerror_log /www/wwwlogs/error.log;\n'
clean = module.clean_config(config)
assert clean == 'access_log /www/wwwlogs/site.log;\nerror_log /www/wwwlogs/error.log;\n'
assert module.clean_config(clean) == clean
print('PASS: install/upgrade/start blocked; idempotence; ordinary logs preserved')
