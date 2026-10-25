"""Exercise shipped plugin assets in an isolated browser with a mocked status API."""
import io
import json
import sys
import tarfile
from urllib.parse import urlparse
import zipfile
from playwright.sync_api import sync_playwright

with tarfile.open(sys.argv[1], 'r:gz') as archive:
    packed = archive.extractfile('panel6_clean.zip').read()
with zipfile.ZipFile(io.BytesIO(packed)) as archive:
    files = {n: archive.read(n) for n in archive.namelist() if n.startswith('BTPanel/static/') or n == 'BTPanel/templates/default/software.html'}
    installer = archive.read('install/local_waf.sh').decode('utf-8')
    plugin = installer.split('cat > "$PLUGIN_DIR/index.html" <<\'EOF\'\n', 1)[1].split('\nEOF', 1)[0]

errors = []
with sync_playwright() as engine:
    browser = engine.chromium.launch(headless=True, **({'channel': 'msedge'} if sys.platform == 'win32' else {}))
    try:
        page = browser.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))

        def route(request):
            url = urlparse(request.request.url)
            if url.path == '/':
                request.fulfill(content_type='text/html', body='''<iframe src="/software"></iframe><script>
window.events=[];window.addEventListener('message',e=>events.push(e.data));
document.querySelector('iframe').onload=()=>document.querySelector('iframe').contentWindow.postMessage(JSON.stringify({pluginName:'local_waf',pluginTitle:'Local WAF',pluginBuilt:false}),'*');
</script>''')
            elif url.path == '/software':
                request.fulfill(content_type='text/html', body=files['BTPanel/templates/default/software.html'])
            elif url.path == '/plugin':
                if 'getConfigHtml' in url.query:
                    request.fulfill(content_type='text/html', body=plugin)
                else:
                    request.fulfill(content_type='application/json', body=json.dumps({'status': True, 'enabled': True, 'config': {}, 'sites': [], 'stats': {}}))
            elif 'BTPanel' + url.path in files:
                mime = 'application/javascript' if url.path.endswith('.js') else 'text/css' if url.path.endswith('.css') else 'application/octet-stream'
                request.fulfill(content_type=mime, body=files['BTPanel' + url.path])
            else:
                request.fulfill(status=404, body='Not found')

        page.route('**/*', route)
        page.goto('http://panel-test.local/')
        frame = page.frames[1]
        frame.locator('.local-waf-app').wait_for(state='visible', timeout=15000)
        frame.locator('#waf-enabled:checked').wait_for(state='attached', timeout=10000)
        assert not errors, errors
        assert 'pluginLoad' in page.evaluate('events')
        print('PASS: release WAF opens, ready message sent, mocked status renders, no page errors')
    finally:
        browser.close()
